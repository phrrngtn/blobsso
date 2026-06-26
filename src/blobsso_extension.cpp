#define DUCKDB_EXTENSION_MAIN

#include "blobsso_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/secret/secret.hpp"

#include "negotiate_auth.hpp" // vendored from blobhttp: SPNEGO token via dlopen'd GSS-API

#include <cctype>

namespace duckdb {

//===--------------------------------------------------------------------===//
// Small helpers (dependency-free: no XML/JSON/HTTP library linked; the only
// runtime dependency is GSS-API, dlopen'd by the vendored negotiate code, and
// only on the SPNEGO path).
//===--------------------------------------------------------------------===//

static string UrlEncode(const string &value) {
	static const char *hex = "0123456789ABCDEF";
	string out;
	out.reserve(value.size() * 3);
	for (unsigned char c : value) {
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			out.push_back(static_cast<char>(c));
		} else {
			out.push_back('%');
			out.push_back(hex[c >> 4]);
			out.push_back(hex[c & 0xF]);
		}
	}
	return out;
}

// Inner text of the first <tag>...</tag> (namespace-agnostic). For STS XML.
static string ExtractXmlTag(const string &xml, const string &tag) {
	const string open = "<" + tag + ">";
	auto start = xml.find(open);
	if (start == string::npos) {
		return "";
	}
	start += open.size();
	auto end = xml.find("</" + tag + ">", start);
	return end == string::npos ? "" : xml.substr(start, end - start);
}

// Value of a JSON string field: "key" : "value". Sufficient for OIDC discovery
// and token responses (well-formed, no escaped quotes in the fields we read).
static string ExtractJsonString(const string &json, const string &key) {
	auto k = json.find("\"" + key + "\"");
	if (k == string::npos) {
		return "";
	}
	auto colon = json.find(':', k + key.size() + 2);
	if (colon == string::npos) {
		return "";
	}
	auto q1 = json.find('"', colon);
	if (q1 == string::npos) {
		return "";
	}
	auto q2 = json.find('"', q1 + 1);
	return q2 == string::npos ? "" : json.substr(q1 + 1, q2 - q1 - 1);
}

static string ReadFileToString(ClientContext &context, const string &path) {
	auto &fs = FileSystem::GetFileSystem(context);
	auto handle = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ);
	auto size = fs.GetFileSize(*handle);
	string buffer(static_cast<size_t>(size), '\0');
	fs.Read(*handle, const_cast<char *>(buffer.data()), static_cast<int64_t>(size));
	while (!buffer.empty() && (buffer.back() == '\n' || buffer.back() == '\r' || buffer.back() == ' ')) {
		buffer.pop_back();
	}
	return buffer;
}

static string GetOption(const CreateSecretInput &input, const string &key, const string &fallback = "") {
	auto it = input.options.find(key);
	if (it != input.options.end() && !it->second.IsNull()) {
		return it->second.ToString();
	}
	return fallback;
}

//===--------------------------------------------------------------------===//
// HTTP via httpfs's core HTTPUtil (no HTTP library linked here)
//===--------------------------------------------------------------------===//

static unique_ptr<HTTPResponse> HttpGet(HTTPUtil &http_util, HTTPParams &params, const string &url,
                                        const HTTPHeaders &headers, string &body_out) {
	GetRequestInfo req(
	    url, headers, params, [](const HTTPResponse &) { return true; },
	    [&body_out](const_data_ptr_t data, idx_t len) {
		    body_out.append(reinterpret_cast<const char *>(data), len);
		    return true;
	    });
	return http_util.Request(req);
}

static string HttpPostForm(HTTPUtil &http_util, HTTPParams &params, const string &url, const string &body) {
	HTTPHeaders headers;
	headers.Insert("Content-Type", "application/x-www-form-urlencoded");
	PostRequestInfo post(url, headers, params, reinterpret_cast<const_data_ptr_t>(body.data()), body.size());
	http_util.Request(post);
	return post.buffer_out;
}

//===--------------------------------------------------------------------===//
// Stage 2: acquire the JWT via Kerberos/SPNEGO against an OIDC provider.
//
//   kinit ticket -> Authorization: Negotiate -> OIDC auth-code -> JWT.
// The SPNEGO token is generated from the OS Kerberos credential (GSS-API);
// the host's krb5.conf should set `dns_canonicalize_hostname = false` so the
// SPN matches the issuer's hostname (HTTP/<issuer-host>) rather than a CNAME.
//===--------------------------------------------------------------------===//
static string AcquireTokenViaSpnego(ClientContext &context, HTTPUtil &http_util, const CreateSecretInput &input) {
	const string issuer = GetOption(input, "oidc_issuer");
	const string client_id = GetOption(input, "client_id");
	const string client_secret = GetOption(input, "client_secret");
	const string redirect_uri = GetOption(input, "redirect_uri", "http://localhost/cb");
	if (client_id.empty()) {
		throw InvalidInputException("blobsso 'sso' provider: 'client_id' is required with 'oidc_issuer'.");
	}

	auto params = http_util.InitializeParameters(context, issuer);

	// 1. OIDC discovery -> authorization_endpoint, token_endpoint
	params->follow_location = true;
	string disc_body;
	HTTPHeaders no_headers;
	HttpGet(http_util, *params, issuer + "/.well-known/openid-configuration", no_headers, disc_body);
	const string auth_endpoint = ExtractJsonString(disc_body, "authorization_endpoint");
	const string token_endpoint = ExtractJsonString(disc_body, "token_endpoint");
	if (auth_endpoint.empty() || token_endpoint.empty()) {
		throw InvalidInputException("blobsso 'sso' provider: OIDC discovery failed at %s/.well-known/"
		                            "openid-configuration",
		                            issuer);
	}

	// 2. SPNEGO token for HTTP/<auth-host> from the OS Kerberos credential.
	// By default Negotiate requires HTTPS (replay protection); allow_http_negotiate
	// opts into plain HTTP when the transport is already encrypted (e.g. Tailscale).
	const bool allow_http = GetOption(input, "allow_http_negotiate") == "true";
	string negotiate;
	try {
		negotiate = blobhttp::GenerateNegotiateToken(auth_endpoint, allow_http).token;
	} catch (const std::exception &e) {
		throw InvalidInputException("blobsso 'sso' provider: SPNEGO/Kerberos token generation failed (%s). "
		                            "Do you have a ticket (kinit)?",
		                            e.what());
	}

	// 3. Proactive Negotiate GET on the auth endpoint -> 302 with ?code=
	const string auth_url = auth_endpoint + "?client_id=" + UrlEncode(client_id) +
	                        "&response_type=code&scope=openid&redirect_uri=" + UrlEncode(redirect_uri) +
	                        "&state=blobsso";
	HTTPHeaders auth_headers;
	auth_headers.Insert("Authorization", "Negotiate " + negotiate);
	params->follow_location = false;
	string ignore;
	auto resp = HttpGet(http_util, *params, auth_url, auth_headers, ignore);
	string location = (resp && resp->HasHeader("Location")) ? resp->GetHeaderValue("Location") : "";
	auto cpos = location.find("code=");
	if (cpos == string::npos) {
		throw InvalidInputException("blobsso 'sso' provider: SPNEGO auth did not yield an authorization code "
		                            "(status %d). Check the SPN/keytab and client_id.",
		                            resp ? static_cast<int>(resp->status) : 0);
	}
	cpos += 5;
	auto cend = location.find('&', cpos);
	const string code = location.substr(cpos, cend == string::npos ? string::npos : cend - cpos);

	// 4. Exchange the code for the JWT
	string token_body = "grant_type=authorization_code&code=" + UrlEncode(code) +
	                    "&client_id=" + UrlEncode(client_id) + "&redirect_uri=" + UrlEncode(redirect_uri);
	if (!client_secret.empty()) {
		token_body += "&client_secret=" + UrlEncode(client_secret);
	}
	params->follow_location = true;
	const string token_resp = HttpPostForm(http_util, *params, token_endpoint, token_body);
	const string jwt = ExtractJsonString(token_resp, "access_token");
	if (jwt.empty()) {
		throw InvalidInputException("blobsso 'sso' provider: code exchange returned no access_token. Body: %s",
		                            token_resp);
	}
	return jwt;
}

// Resolve the web-identity JWT: inline token, token file, env var, or — when an
// `oidc_issuer` is given — Kerberos/SPNEGO against that OIDC provider (Stage 2).
static string AcquireWebIdentityToken(ClientContext &context, HTTPUtil &http_util, const CreateSecretInput &input) {
	auto it = input.options.find("token");
	if (it != input.options.end() && !it->second.IsNull()) {
		return it->second.ToString();
	}
	it = input.options.find("web_identity_token_file");
	if (it != input.options.end() && !it->second.IsNull()) {
		return ReadFileToString(context, it->second.ToString());
	}
	if (!GetOption(input, "oidc_issuer").empty()) {
		return AcquireTokenViaSpnego(context, http_util, input);
	}
	const char *env_file = std::getenv("AWS_WEB_IDENTITY_TOKEN_FILE");
	if (env_file) {
		return ReadFileToString(context, env_file);
	}
	throw InvalidInputException("blobsso 'sso' provider: no web-identity token. Supply 'token', "
	                            "'web_identity_token_file', 'oidc_issuer' (Kerberos/SPNEGO), or set "
	                            "AWS_WEB_IDENTITY_TOKEN_FILE.");
}

//===--------------------------------------------------------------------===//
// 'sso' provider for the s3 secret type — JWT -> STS -> temporary creds.
//===--------------------------------------------------------------------===//
static unique_ptr<BaseSecret> CreateS3SecretFromSSO(ClientContext &context, CreateSecretInput &input) {
	const string sts_endpoint = GetOption(input, "sts_endpoint");
	if (sts_endpoint.empty()) {
		throw InvalidInputException("blobsso 'sso' provider: 'sts_endpoint' is required (e.g. the MinIO/STS URL).");
	}

	auto &db = DatabaseInstance::GetDatabase(context);
	auto &http_util = HTTPUtil::Get(db);

	const string token = AcquireWebIdentityToken(context, http_util, input);
	const string role_arn = GetOption(input, "role_arn");
	const string duration = GetOption(input, "duration_seconds");
	const string session_name = GetOption(input, "role_session_name", "blobsso");

	string body = "Action=AssumeRoleWithWebIdentity&Version=2011-06-15";
	body += "&WebIdentityToken=" + UrlEncode(token);
	body += "&RoleSessionName=" + UrlEncode(session_name);
	if (!role_arn.empty()) {
		body += "&RoleArn=" + UrlEncode(role_arn);
	}
	if (!duration.empty()) {
		body += "&DurationSeconds=" + UrlEncode(duration);
	}

	auto params = http_util.InitializeParameters(context, sts_endpoint);
	const string xml = HttpPostForm(http_util, *params, sts_endpoint, body);

	if (xml.find("<ErrorResponse") != string::npos || xml.find("<Error>") != string::npos) {
		string code = ExtractXmlTag(xml, "Code");
		string message = ExtractXmlTag(xml, "Message");
		throw InvalidInputException("blobsso 'sso' provider: STS AssumeRoleWithWebIdentity failed (%s) at %s",
		                            code + ": " + message, sts_endpoint);
	}

	const string key_id = ExtractXmlTag(xml, "AccessKeyId");
	const string secret = ExtractXmlTag(xml, "SecretAccessKey");
	const string session_token = ExtractXmlTag(xml, "SessionToken");
	const string expiration = ExtractXmlTag(xml, "Expiration");
	if (key_id.empty() || secret.empty()) {
		throw InvalidInputException("blobsso 'sso' provider: STS response missing credentials. Body: %s", xml);
	}

	auto scope = input.scope;
	if (scope.empty()) {
		scope = {"s3://", "s3n://", "s3a://"};
	}
	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);
	result->redact_keys = {"secret", "session_token"};
	result->secret_map["key_id"] = Value(key_id);
	result->secret_map["secret"] = Value(secret);
	if (!session_token.empty()) {
		result->secret_map["session_token"] = Value(session_token);
	}
	if (!expiration.empty()) {
		result->secret_map["expiration"] = Value(expiration);
	}
	for (const auto *key : {"region", "endpoint", "url_style", "use_ssl"}) {
		result->TrySetValue(key, input);
	}

	// Auto-rotation: store the creation options as `refresh_info` so httpfs, on an
	// expired-credential failure, re-invokes this provider (re-running SPNEGO/STS
	// for fresh temporary credentials) via CreateS3SecretFunctions::TryRefreshS3Secret.
	child_list_t<Value> refresh_children;
	for (const auto &opt : input.options) {
		refresh_children.emplace_back(opt.first, opt.second);
	}
	if (!refresh_children.empty()) {
		result->secret_map["refresh_info"] = Value::STRUCT(std::move(refresh_children));
	}
	return std::move(result);
}

static void RegisterSSOSecretProvider(ExtensionLoader &loader) {
	CreateSecretFunction sso = {"s3", "sso", CreateS3SecretFromSSO};

	// Token acquisition: pre-fetched, file/env, or Kerberos/SPNEGO via OIDC
	sso.named_parameters["token"] = LogicalType::VARCHAR;
	sso.named_parameters["web_identity_token_file"] = LogicalType::VARCHAR;
	sso.named_parameters["oidc_issuer"] = LogicalType::VARCHAR; // SPNEGO: OIDC issuer URL
	sso.named_parameters["client_id"] = LogicalType::VARCHAR;
	sso.named_parameters["client_secret"] = LogicalType::VARCHAR;
	sso.named_parameters["redirect_uri"] = LogicalType::VARCHAR;
	sso.named_parameters["allow_http_negotiate"] = LogicalType::BOOLEAN; // opt-in: SPNEGO over plain HTTP
	// STS target
	sso.named_parameters["sts_endpoint"] = LogicalType::VARCHAR;
	sso.named_parameters["role_arn"] = LogicalType::VARCHAR;
	sso.named_parameters["role_session_name"] = LogicalType::VARCHAR;
	sso.named_parameters["duration_seconds"] = LogicalType::VARCHAR;
	// S3 storage configuration carried into the resulting secret
	sso.named_parameters["region"] = LogicalType::VARCHAR;
	sso.named_parameters["endpoint"] = LogicalType::VARCHAR;
	sso.named_parameters["url_style"] = LogicalType::VARCHAR;
	sso.named_parameters["use_ssl"] = LogicalType::BOOLEAN;

	loader.RegisterFunction(sso);
}

static void LoadInternal(ExtensionLoader &loader) {
	RegisterSSOSecretProvider(loader);
}

void BlobssoExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
std::string BlobssoExtension::Name() {
	return "blobsso";
}
std::string BlobssoExtension::Version() const {
#ifdef EXT_VERSION_BLOBSSO
	return EXT_VERSION_BLOBSSO;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(blobsso, loader) {
	duckdb::LoadInternal(loader);
}
}
