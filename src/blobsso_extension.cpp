#define DUCKDB_EXTENSION_MAIN

#include "blobsso_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/secret/secret.hpp"

namespace duckdb {

//===--------------------------------------------------------------------===//
// 'sso' provider for the s3 secret type
//
// Stage 1 tracer bullet: this round-trips the supplied configuration straight
// into a KeyValueSecret with placeholder credentials, so the provider builds,
// loads, and shows up in duckdb_secrets(). The real work — an outbound STS
// AssumeRoleWithWebIdentity POST over httpfs's core HTTPUtil, parsed into
// temporary creds — replaces the placeholder block below (see CONTEXT.md §4).
//===--------------------------------------------------------------------===//
static unique_ptr<BaseSecret> CreateS3SecretFromSSO(ClientContext &context, CreateSecretInput &input) {
	// Default the scope to the standard s3 prefixes when the user gives none
	// (mirrors duckdb-aws ConstructBaseS3Secret).
	auto scope = input.scope;
	if (scope.empty()) {
		scope = {"s3://", "s3n://", "s3a://"};
	}

	auto secret = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);
	secret->redact_keys = {"secret", "session_token"};

	// Carry the provider configuration through verbatim (Stage 1 stub).
	for (const auto *key : {"region", "endpoint", "sts_endpoint", "url_style", "use_ssl", "token_endpoint", "role_arn",
	                        "web_identity_token_file"}) {
		secret->TrySetValue(key, input);
	}

	// TODO(Stage 1): replace these placeholders with the parsed result of an
	// AssumeRoleWithWebIdentity STS call (key_id / secret / session_token /
	// expiration), issued via HTTPUtil::Get(db).Request(post_request).
	secret->secret_map["key_id"] = Value("SSO_STUB_KEY_ID");
	secret->secret_map["secret"] = Value("SSO_STUB_SECRET");
	secret->secret_map["session_token"] = Value("SSO_STUB_SESSION_TOKEN");

	// Rotation hook: DuckDB re-invokes this create_fn when the creds expire.
	secret->secret_map["refresh"] = Value("auto");

	return std::move(secret);
}

static void RegisterSSOSecretProvider(ExtensionLoader &loader) {
	// {secret_type, provider, create_fn}
	CreateSecretFunction sso = {"s3", "sso", CreateS3SecretFromSSO};

	// Token acquisition / STS target
	sso.named_parameters["token_endpoint"] = LogicalType::VARCHAR;
	sso.named_parameters["web_identity_token_file"] = LogicalType::VARCHAR;
	sso.named_parameters["role_arn"] = LogicalType::VARCHAR;
	sso.named_parameters["sts_endpoint"] = LogicalType::VARCHAR;
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
