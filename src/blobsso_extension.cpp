#define DUCKDB_EXTENSION_MAIN

#include "blobsso_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/common/vector_operations/unary_executor.hpp"
#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/function/function_set.hpp"

#include "spnego_token.hpp" // shared submodule (spnego-token): preemptive SPNEGO token via dlopen'd GSS-API

#include <cctype>
#include <chrono>
#include <cstdio>

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

// Optional per-step timing for the SSO chain. Set BLOBSSO_TIMING=1 to print a stderr
// breakdown; off by default (a single getenv check, no other overhead).
static std::chrono::steady_clock::time_point TimingNow() {
	return std::chrono::steady_clock::now();
}
static void TimingMark(const char *label, std::chrono::steady_clock::time_point since) {
	if (std::getenv("BLOBSSO_TIMING")) {
		auto ms = std::chrono::duration<double, std::milli>(TimingNow() - since).count();
		fprintf(stderr, "blobsso: %-20s %8.2f ms\n", label, ms);
	}
}

//===--------------------------------------------------------------------===//
// HTTP via httpfs's core HTTPUtil (no HTTP library linked here)
//===--------------------------------------------------------------------===//

// `client` (optional): a persistent HTTPClient to reuse the connection (keep-alive) across
// calls to the same host — pass it to collapse repeated TLS handshakes into one.
static unique_ptr<HTTPResponse> HttpGet(HTTPUtil &http_util, HTTPParams &params, const string &url,
                                        const HTTPHeaders &headers, string &body_out,
                                        unique_ptr<HTTPClient> *client = nullptr) {
	GetRequestInfo req(
	    url, headers, params, [](const HTTPResponse &) { return true; },
	    [&body_out](const_data_ptr_t data, idx_t len) {
		    body_out.append(reinterpret_cast<const char *>(data), len);
		    return true;
	    });
	return client ? http_util.Request(req, *client) : http_util.Request(req);
}

static string HttpPostForm(HTTPUtil &http_util, HTTPParams &params, const string &url, const string &body,
                           unique_ptr<HTTPClient> *client = nullptr) {
	HTTPHeaders headers;
	headers.Insert("Content-Type", "application/x-www-form-urlencoded");
	PostRequestInfo post(url, headers, params, reinterpret_cast<const_data_ptr_t>(body.data()), body.size());
	if (client) {
		http_util.Request(post, *client);
	} else {
		http_util.Request(post);
	}
	return post.buffer_out;
}

//===--------------------------------------------------------------------===//
// Stage 1: acquire the JWT. Factored into the *generic* OIDC authorization-code flow
// (OidcDiscover / OidcExchangeCode — no credential knowledge) and the single credential
// step that authenticates to the authorization endpoint (SpnegoAuthorize). SPNEGO is just
// the non-interactive, browserless way we obtain the code — which is what lets this run
// headless from ODBC/Tableau. Swapping the IdP-auth method means swapping SpnegoAuthorize;
// the OIDC pipeline (the reusable part of the proof) is untouched.
//
// The host's krb5.conf should set `dns_canonicalize_hostname = false` so the SPN matches
// the issuer host (HTTP/<issuer-host>) rather than a DNS CNAME.
//===--------------------------------------------------------------------===//

struct OidcEndpoints {
	string authorization_endpoint;
	string token_endpoint;
};

// Generic OIDC discovery — credential-agnostic.
static OidcEndpoints OidcDiscover(HTTPUtil &http_util, HTTPParams &params, const string &issuer,
                                  unique_ptr<HTTPClient> *client = nullptr) {
	params.follow_location = true;
	string disc_body;
	HTTPHeaders no_headers;
	HttpGet(http_util, params, issuer + "/.well-known/openid-configuration", no_headers, disc_body, client);
	OidcEndpoints ep;
	ep.authorization_endpoint = ExtractJsonString(disc_body, "authorization_endpoint");
	ep.token_endpoint = ExtractJsonString(disc_body, "token_endpoint");
	if (ep.authorization_endpoint.empty() || ep.token_endpoint.empty()) {
		throw InvalidInputException("blobsso 'sso' provider: OIDC discovery failed at "
		                            "%s/.well-known/openid-configuration",
		                            issuer);
	}
	return ep;
}

// Credential step (the only SPNEGO-specific piece): obtain an authorization code from the
// authorization endpoint with a pre-flight Negotiate token minted from the ambient Kerberos
// ticket — no browser, so it works headless (ODBC/Tableau). allow_http opts into plain HTTP
// when the transport is already encrypted (e.g. Tailscale).
static string SpnegoAuthorize(HTTPUtil &http_util, HTTPParams &params, const string &authorization_endpoint,
                              const string &client_id, const string &redirect_uri, bool allow_http,
                              unique_ptr<HTTPClient> *client = nullptr) {
	auto t = TimingNow();
	string negotiate;
	try {
		negotiate = spnego::GenerateTokenForUrl(authorization_endpoint, allow_http).token;
	} catch (const std::exception &e) {
		throw InvalidInputException("blobsso 'sso' provider: SPNEGO/Kerberos token generation failed (%s). "
		                            "Do you have a ticket (kinit)?",
		                            e.what());
	}
	TimingMark("  spnego_gen", t);
	const string auth_url = authorization_endpoint + "?client_id=" + UrlEncode(client_id) +
	                        "&response_type=code&scope=openid&redirect_uri=" + UrlEncode(redirect_uri) +
	                        "&state=blobsso";
	HTTPHeaders auth_headers;
	auth_headers.Insert("Authorization", "Negotiate " + negotiate);
	params.follow_location = false;
	string ignore;
	t = TimingNow();
	auto resp = HttpGet(http_util, params, auth_url, auth_headers, ignore, client);
	TimingMark("  authorize_get", t);
	const string location = (resp && resp->HasHeader("Location")) ? resp->GetHeaderValue("Location") : "";
	auto cpos = location.find("code=");
	if (cpos == string::npos) {
		throw InvalidInputException("blobsso 'sso' provider: SPNEGO auth did not yield an authorization code "
		                            "(status %d). Check the SPN/keytab and client_id.",
		                            resp ? static_cast<int>(resp->status) : 0);
	}
	cpos += 5;
	auto cend = location.find('&', cpos);
	return location.substr(cpos, cend == string::npos ? string::npos : cend - cpos);
}

// Generic OIDC authorization-code -> token exchange — credential-agnostic.
static string OidcExchangeCode(HTTPUtil &http_util, HTTPParams &params, const string &token_endpoint,
                               const string &code, const string &client_id, const string &client_secret,
                               const string &redirect_uri, unique_ptr<HTTPClient> *client = nullptr) {
	string token_body = "grant_type=authorization_code&code=" + UrlEncode(code) + "&client_id=" + UrlEncode(client_id) +
	                    "&redirect_uri=" + UrlEncode(redirect_uri);
	if (!client_secret.empty()) {
		token_body += "&client_secret=" + UrlEncode(client_secret);
	}
	params.follow_location = true;
	const string token_resp = HttpPostForm(http_util, params, token_endpoint, token_body, client);
	const string jwt = ExtractJsonString(token_resp, "access_token");
	if (jwt.empty()) {
		throw InvalidInputException("blobsso 'sso' provider: code exchange returned no access_token. Body: %s",
		                            token_resp);
	}
	return jwt;
}

// Compose: OIDC discovery -> SPNEGO authorization -> code exchange -> JWT.
static string AcquireTokenViaSpnego(ClientContext &context, HTTPUtil &http_util, const CreateSecretInput &input) {
	const string issuer = GetOption(input, "oidc_issuer");
	const string client_id = GetOption(input, "client_id");
	const string client_secret = GetOption(input, "client_secret");
	const string redirect_uri = GetOption(input, "redirect_uri", "http://localhost/cb");
	const bool allow_http = GetOption(input, "allow_http_negotiate") == "true";
	if (client_id.empty()) {
		throw InvalidInputException("blobsso 'sso' provider: 'client_id' is required with 'oidc_issuer'.");
	}

	auto params = http_util.InitializeParameters(context, issuer);
	// One keep-alive client for the Keycloak host: discovery, authorize, and token all hit the
	// same host, so reuse one TLS connection instead of a fresh handshake per call.
	auto authority_end = issuer.find('/', issuer.find("://") + 3);
	const string keycloak_authority = authority_end == string::npos ? issuer : issuer.substr(0, authority_end);
	auto kc = http_util.InitializeClient(*params, keycloak_authority);

	auto t = TimingNow();
	const OidcEndpoints ep = OidcDiscover(http_util, *params, issuer, &kc);
	TimingMark("oidc_discover", t);
	t = TimingNow();
	// NOTE: authorize must NOT reuse the client — it needs follow_location=false to capture the
	// 302 (code in Location), which a reused client overrides. It uses its own connection.
	const string code =
	    SpnegoAuthorize(http_util, *params, ep.authorization_endpoint, client_id, redirect_uri, allow_http);
	TimingMark("spnego_authorize", t);
	t = TimingNow();
	const string jwt =
	    OidcExchangeCode(http_util, *params, ep.token_endpoint, code, client_id, client_secret, redirect_uri, &kc);
	TimingMark("oidc_token_exchange", t);
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

	auto t_jwt = TimingNow();
	const string token = AcquireWebIdentityToken(context, http_util, input);
	TimingMark("jwt_total", t_jwt);
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
	auto t_sts = TimingNow();
	const string xml = HttpPostForm(http_util, *params, sts_endpoint, body);
	TimingMark("sts_assume_role", t_sts);

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

//===--------------------------------------------------------------------===//
// Scalar UDFs over the shared spnego-token atom: mint a preemptive Negotiate token for
// any URL (optionally a non-HTTP service class) so it can be dropped into other requests
// (EXTRA_HTTP_HEADERS, a TYPE http secret, ad-hoc SQL). VOLATILE — the token embeds a
// timestamp, so a fresh one is produced per call (never constant-folded).
//===--------------------------------------------------------------------===//
static void NegotiateTokenFun(DataChunk &args, ExpressionState &, Vector &result) {
	if (args.ColumnCount() > 1) {
		BinaryExecutor::Execute<string_t, string_t, string_t>(
		    args.data[0], args.data[1], result, args.size(), [&](string_t url, string_t service) {
			    auto tok = spnego::GenerateTokenForUrl(url.GetString(), false, service.GetString()).token;
			    return StringVector::AddString(result, tok);
		    });
	} else {
		UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url) {
			auto tok = spnego::GenerateTokenForUrl(url.GetString()).token;
			return StringVector::AddString(result, tok);
		});
	}
}

static void NegotiateTokenDescribeFun(DataChunk &args, ExpressionState &, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url) {
		return StringVector::AddString(result, spnego::DescribeTokenForUrl(url.GetString()));
	});
}

static void NegotiateTokenFromJsonFun(DataChunk &args, ExpressionState &, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t config) {
		return StringVector::AddString(result, spnego::GenerateTokenFromConfig(config.GetString()).token);
	});
}

static void RegisterNegotiateFunctions(ExtensionLoader &loader) {
	// negotiate_token(url[, service]) -> base64 SPNEGO token (raises on failure)
	ScalarFunctionSet token("negotiate_token");
	ScalarFunction one({LogicalType::VARCHAR}, LogicalType::VARCHAR, NegotiateTokenFun);
	one.stability = FunctionStability::VOLATILE;
	token.AddFunction(one);
	ScalarFunction two({LogicalType::VARCHAR, LogicalType::VARCHAR}, LogicalType::VARCHAR, NegotiateTokenFun);
	two.stability = FunctionStability::VOLATILE;
	token.AddFunction(two);
	loader.RegisterFunction(token);

	// negotiate_token_describe(url) -> JSON diagnostics (never raises)
	ScalarFunction describe("negotiate_token_describe", {LogicalType::VARCHAR}, LogicalType::VARCHAR,
	                        NegotiateTokenDescribeFun);
	describe.stability = FunctionStability::VOLATILE;
	loader.RegisterFunction(describe);

	// negotiate_token_from_json(config) -> token (strict property-bag; raises on bad config/failure)
	ScalarFunction from_json("negotiate_token_from_json", {LogicalType::VARCHAR}, LogicalType::VARCHAR,
	                         NegotiateTokenFromJsonFun);
	from_json.stability = FunctionStability::VOLATILE;
	loader.RegisterFunction(from_json);
}

static void LoadInternal(ExtensionLoader &loader) {
	RegisterSSOSecretProvider(loader);
	RegisterNegotiateFunctions(loader);
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
