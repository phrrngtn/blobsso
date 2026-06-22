#define DUCKDB_EXTENSION_MAIN

#include "blobsso_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/secret/secret.hpp"

#include <cctype>

namespace duckdb {

//===--------------------------------------------------------------------===//
// Small helpers (kept dependency-free — no XML/HTTP library linked)
//===--------------------------------------------------------------------===//

// Percent-encode a value for an application/x-www-form-urlencoded body.
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

// Extract the inner text of the first <tag>...</tag> (namespace-agnostic on the
// local name). Returns empty string if absent. Sufficient for STS responses,
// whose Credentials fields are simple text without nested markup or entities.
static string ExtractXmlTag(const string &xml, const string &tag) {
	const string open = "<" + tag + ">";
	auto start = xml.find(open);
	if (start == string::npos) {
		return "";
	}
	start += open.size();
	auto end = xml.find("</" + tag + ">", start);
	if (end == string::npos) {
		return "";
	}
	return xml.substr(start, end - start);
}

static string ReadFileToString(ClientContext &context, const string &path) {
	auto &fs = FileSystem::GetFileSystem(context);
	auto handle = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ);
	auto size = fs.GetFileSize(*handle);
	string buffer(static_cast<size_t>(size), '\0');
	fs.Read(*handle, const_cast<char *>(buffer.data()), static_cast<int64_t>(size));
	// JWTs sometimes carry a trailing newline in token files — trim whitespace.
	while (!buffer.empty() && (buffer.back() == '\n' || buffer.back() == '\r' || buffer.back() == ' ')) {
		buffer.pop_back();
	}
	return buffer;
}

// Resolve the web-identity JWT for Stage 1: an inline `token`, a
// `web_identity_token_file` path, or the AWS_WEB_IDENTITY_TOKEN_FILE env var.
// (Stage 2 will add SPNEGO/Kerberos acquisition over the shared blobhttp core.)
static string AcquireWebIdentityToken(ClientContext &context, const CreateSecretInput &input) {
	auto it = input.options.find("token");
	if (it != input.options.end() && !it->second.IsNull()) {
		return it->second.ToString();
	}
	it = input.options.find("web_identity_token_file");
	if (it != input.options.end() && !it->second.IsNull()) {
		return ReadFileToString(context, it->second.ToString());
	}
	const char *env_file = std::getenv("AWS_WEB_IDENTITY_TOKEN_FILE");
	if (env_file) {
		return ReadFileToString(context, env_file);
	}
	throw InvalidInputException(
	    "blobsso 'sso' provider: no web-identity token. Supply 'token', "
	    "'web_identity_token_file', or set AWS_WEB_IDENTITY_TOKEN_FILE.");
}

static string GetOption(const CreateSecretInput &input, const string &key, const string &fallback = "") {
	auto it = input.options.find(key);
	if (it != input.options.end() && !it->second.IsNull()) {
		return it->second.ToString();
	}
	return fallback;
}

//===--------------------------------------------------------------------===//
// 'sso' provider for the s3 secret type — Stage 1: JWT -> STS -> temp creds.
//
// Performs one outbound AssumeRoleWithWebIdentity POST to `sts_endpoint` using
// httpfs's core HTTPUtil (no HTTP library linked here), parses the temporary
// credentials out of the XML, and returns them as an s3 KeyValueSecret that
// httpfs consumes exactly like static keys.
//===--------------------------------------------------------------------===//
static unique_ptr<BaseSecret> CreateS3SecretFromSSO(ClientContext &context, CreateSecretInput &input) {
	const string sts_endpoint = GetOption(input, "sts_endpoint");
	if (sts_endpoint.empty()) {
		throw InvalidInputException("blobsso 'sso' provider: 'sts_endpoint' is required (e.g. the MinIO/STS URL).");
	}
	const string token = AcquireWebIdentityToken(context, input);
	const string role_arn = GetOption(input, "role_arn");
	const string duration = GetOption(input, "duration_seconds");
	const string session_name = GetOption(input, "role_session_name", "blobsso");

	// Build the form-encoded STS request body.
	string body = "Action=AssumeRoleWithWebIdentity&Version=2011-06-15";
	body += "&WebIdentityToken=" + UrlEncode(token);
	body += "&RoleSessionName=" + UrlEncode(session_name);
	if (!role_arn.empty()) {
		body += "&RoleArn=" + UrlEncode(role_arn);
	}
	if (!duration.empty()) {
		body += "&DurationSeconds=" + UrlEncode(duration);
	}

	// Issue the POST via httpfs's core HTTP client (requires httpfs loaded).
	auto &db = DatabaseInstance::GetDatabase(context);
	auto &http_util = HTTPUtil::Get(db);
	auto params = http_util.InitializeParameters(context, sts_endpoint);
	HTTPHeaders headers;
	headers.Insert("Content-Type", "application/x-www-form-urlencoded");

	PostRequestInfo post(sts_endpoint, headers, *params, reinterpret_cast<const_data_ptr_t>(body.data()), body.size());
	auto response = http_util.Request(post);
	const string &xml = post.buffer_out;

	if (!response || !response->Success() || xml.find("<ErrorResponse") != string::npos ||
	    xml.find("<Error>") != string::npos) {
		string code = ExtractXmlTag(xml, "Code");
		string message = ExtractXmlTag(xml, "Message");
		string detail = code.empty() && message.empty()
		                    ? (response ? response->GetError() : string("no response"))
		                    : (code + ": " + message);
		throw InvalidInputException("blobsso 'sso' provider: STS AssumeRoleWithWebIdentity failed (%s) at %s",
		                            detail, sts_endpoint);
	}

	const string key_id = ExtractXmlTag(xml, "AccessKeyId");
	const string secret = ExtractXmlTag(xml, "SecretAccessKey");
	const string session_token = ExtractXmlTag(xml, "SessionToken");
	const string expiration = ExtractXmlTag(xml, "Expiration");
	if (key_id.empty() || secret.empty()) {
		throw InvalidInputException("blobsso 'sso' provider: STS response missing credentials. Body: %s", xml);
	}

	// Build the s3 secret. Default scope to the standard s3 prefixes.
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
	// Carry the s3 storage config through so httpfs can reach the bucket.
	for (const auto *key : {"region", "endpoint", "url_style", "use_ssl"}) {
		result->TrySetValue(key, input);
	}

	// TODO(refresh): wire auto-rotation on expiry. DuckDB re-invokes the create
	// function when a secret carries refresh info; for now the creation params
	// are recoverable from secret_map for a future replay path.
	return std::move(result);
}

static void RegisterSSOSecretProvider(ExtensionLoader &loader) {
	// {secret_type, provider, create_fn}
	CreateSecretFunction sso = {"s3", "sso", CreateS3SecretFromSSO};

	// Token acquisition + STS target
	sso.named_parameters["token"] = LogicalType::VARCHAR;                   // inline JWT (testing / pre-fetched)
	sso.named_parameters["web_identity_token_file"] = LogicalType::VARCHAR; // path to a JWT file
	sso.named_parameters["sts_endpoint"] = LogicalType::VARCHAR;            // AWS STS or MinIO STS URL
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
