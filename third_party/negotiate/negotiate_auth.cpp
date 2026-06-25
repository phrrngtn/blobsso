// ---------------------------------------------------------------------------
// Pre-flight HTTP Negotiate (SPNEGO/Kerberos) authentication
// ---------------------------------------------------------------------------
//
// This module generates Authorization: Negotiate tokens for HTTP requests,
// enabling DuckDB to access resources on Kerberos-secured intranets (e.g.
// corporate data lakes, internal APIs, SharePoint, HDFS WebHDFS endpoints)
// without requiring interactive login — the user's existing Kerberos ticket
// (from kinit or OS-level SSO) is used automatically.
//
// Unlike curl's built-in CURLAUTH_NEGOTIATE, this uses a pre-flight approach:
// the SPNEGO token is generated and attached to the first request, avoiding
// the 401 challenge/response round-trip. A fresh token is generated per HTTP
// request, which is correct for single-use token policies.
//
// The implementation loads the platform's security provider at runtime via
// dlopen (GSS-API on macOS/Linux) or links directly against SSPI on Windows,
// so no additional build dependencies are required.
//
// Thanks to Richard E. Silverman for suggesting the pre-flight Negotiate
// approach for accessing Kerberos-secured intranet resources.
//
// Inspired by the pyspnego project (https://github.com/jborean93/pyspnego)
// which provides a clean cross-platform SPNEGO interface for Python and
// was used to validate the technique before this C++ implementation.
// ---------------------------------------------------------------------------

#include "negotiate_auth.hpp"

#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace blobhttp {

// ---------------------------------------------------------------------------
// Base64 encoder (standalone, no DuckDB dependency)
// ---------------------------------------------------------------------------

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string Base64Encode(const void *data, size_t len) {
	auto src = static_cast<const uint8_t *>(data);
	std::string result;
	result.reserve(((len + 2) / 3) * 4);
	for (size_t i = 0; i < len; i += 3) {
		uint32_t n = static_cast<uint32_t>(src[i]) << 16;
		if (i + 1 < len) {
			n |= static_cast<uint32_t>(src[i + 1]) << 8;
		}
		if (i + 2 < len) {
			n |= static_cast<uint32_t>(src[i + 2]);
		}
		result.push_back(b64_table[(n >> 18) & 0x3F]);
		result.push_back(b64_table[(n >> 12) & 0x3F]);
		result.push_back((i + 1 < len) ? b64_table[(n >> 6) & 0x3F] : '=');
		result.push_back((i + 2 < len) ? b64_table[n & 0x3F] : '=');
	}
	return result;
}

// ---------------------------------------------------------------------------
// URL hostname extraction (standalone, no curl dependency)
// ---------------------------------------------------------------------------

static std::string ExtractHostname(const std::string &url) {
	// Simple hostname extraction: skip scheme, extract host before port/path
	auto pos = url.find("://");
	if (pos == std::string::npos) {
		throw std::runtime_error("Invalid URL (no scheme): " + url);
	}
	auto scheme = url.substr(0, pos);
	if (scheme != "https") {
		throw std::runtime_error("Negotiate authentication requires HTTPS. "
		                         "Sending Kerberos tokens over plain HTTP exposes credentials to replay attacks.");
	}
	auto host_start = pos + 3;
	// Skip userinfo if present
	auto at_pos = url.find('@', host_start);
	auto slash_pos = url.find('/', host_start);
	if (at_pos != std::string::npos && (slash_pos == std::string::npos || at_pos < slash_pos)) {
		host_start = at_pos + 1;
	}
	// Find end of host (port or path)
	auto host_end = url.find_first_of(":/?#", host_start);
	if (host_end == std::string::npos) {
		host_end = url.length();
	}
	auto hostname = url.substr(host_start, host_end - host_start);
	if (hostname.empty()) {
		throw std::runtime_error("Failed to extract hostname from URL: " + url);
	}
	return hostname;
}

#ifdef _WIN32

// ---------------------------------------------------------------------------
// Windows: SSPI (Security Support Provider Interface)
// secur32.dll is always present on Windows — link directly, no dlopen needed.
// ---------------------------------------------------------------------------

#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#pragma comment(lib, "secur32.lib")

bool NegotiateAuthIsAvailable() {
	return true;
}

std::string GetSecurityLibraryName() {
	return "secur32.dll";
}

std::string GetProviderName() {
	return "SSPI";
}

NegotiateResult GenerateNegotiateToken(const std::string &url) {
	auto hostname = ExtractHostname(url);

	// SSPI uses "HTTP/hostname" (forward slash) for the SPN
	auto spn_narrow = "HTTP/" + hostname;
	int wlen = MultiByteToWideChar(CP_UTF8, 0, spn_narrow.c_str(), -1, nullptr, 0);
	std::vector<wchar_t> spn_wide(wlen);
	MultiByteToWideChar(CP_UTF8, 0, spn_narrow.c_str(), -1, spn_wide.data(), wlen);

	// Acquire credentials for the current user
	CredHandle cred_handle;
	TimeStamp expiry;

	SECURITY_STATUS status = AcquireCredentialsHandleW(nullptr, const_cast<LPWSTR>(L"Negotiate"), SECPKG_CRED_OUTBOUND,
	                                                   nullptr, nullptr, nullptr, nullptr, &cred_handle, &expiry);
	if (status != SEC_E_OK) {
		throw std::runtime_error("Failed to acquire SSPI credentials for '" + spn_narrow + "'");
	}

	// Initialize security context
	CtxtHandle ctx_handle;
	SecBuffer out_buf = {0, SECBUFFER_TOKEN, nullptr};
	SecBufferDesc out_desc = {SECBUFFER_VERSION, 1, &out_buf};
	ULONG context_attr = 0;

	status = InitializeSecurityContextW(&cred_handle, nullptr, spn_wide.data(),
	                                    ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP, nullptr,
	                                    0, &ctx_handle, &out_desc, &context_attr, &expiry);

	if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
		FreeCredentialsHandle(&cred_handle);
		throw std::runtime_error("Failed to initialize SSPI security context for '" + spn_narrow + "'");
	}

	// Base64 encode the output token
	std::string token_b64;
	if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
		token_b64 = Base64Encode(out_buf.pvBuffer, out_buf.cbBuffer);
		FreeContextBuffer(out_buf.pvBuffer);
	}

	// Clean up
	DeleteSecurityContext(&ctx_handle);
	FreeCredentialsHandle(&cred_handle);

	NegotiateResult result;
	result.token = token_b64;
	result.url = url;
	result.hostname = hostname;
	result.spn = spn_narrow;
	result.provider = "SSPI";
	result.library = "secur32.dll";
	return result;
}

#else // !_WIN32

// ---------------------------------------------------------------------------
// Unix (macOS / Linux): GSS-API via dlopen
// ---------------------------------------------------------------------------

#include <dlfcn.h>

// GSS-API type definitions (from RFC 2744) — avoids requiring gssapi.h at build time
typedef uint32_t OM_uint32;

struct gss_OID_desc {
	uint32_t length;
	void *elements;
};
typedef gss_OID_desc *gss_OID;

struct gss_buffer_desc {
	size_t length;
	void *value;
};
typedef gss_buffer_desc *gss_buffer_t;

typedef void *gss_name_t;
typedef void *gss_ctx_id_t;
typedef void *gss_cred_id_t;
typedef void *gss_channel_bindings_t;

// GSS-API status codes
static constexpr OM_uint32 GSS_S_COMPLETE = 0;
static constexpr OM_uint32 GSS_S_CONTINUE_NEEDED = 1;
static constexpr OM_uint32 GSS_C_MUTUAL_FLAG = 2;

// Null values
#define GSS_C_NO_CREDENTIAL ((gss_cred_id_t)0)
#define GSS_C_NO_CONTEXT    ((gss_ctx_id_t)0)
#define GSS_C_NO_BUFFER     ((gss_buffer_t)0)
#define GSS_C_NO_BINDINGS   ((gss_channel_bindings_t)0)
#define GSS_C_NO_OID        ((gss_OID)0)
#define GSS_C_INDEFINITE    0xFFFFFFFF

// Well-known OID: GSS_C_NT_HOSTBASED_SERVICE = 1.2.840.113554.1.2.1.4
static uint8_t gss_nt_hostbased_service_oid_bytes[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04};
static gss_OID_desc gss_nt_hostbased_service_oid = {sizeof(gss_nt_hostbased_service_oid_bytes),
                                                    gss_nt_hostbased_service_oid_bytes};

// Well-known OID: SPNEGO = 1.3.6.1.5.5.2
static uint8_t spnego_oid_bytes[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
static gss_OID_desc spnego_oid = {sizeof(spnego_oid_bytes), spnego_oid_bytes};

// Function pointer types for the GSS-API functions we need
typedef OM_uint32 (*gss_import_name_fn)(OM_uint32 *, gss_buffer_t, gss_OID, gss_name_t *);
typedef OM_uint32 (*gss_init_sec_context_fn)(OM_uint32 *, gss_cred_id_t, gss_ctx_id_t *, gss_name_t, gss_OID, OM_uint32,
                                             OM_uint32, gss_channel_bindings_t, gss_buffer_t, gss_OID *, gss_buffer_t,
                                             OM_uint32 *, OM_uint32 *);
typedef OM_uint32 (*gss_release_buffer_fn)(OM_uint32 *, gss_buffer_t);
typedef OM_uint32 (*gss_release_name_fn)(OM_uint32 *, gss_name_t *);
typedef OM_uint32 (*gss_delete_sec_context_fn)(OM_uint32 *, gss_ctx_id_t *, gss_buffer_t);
typedef OM_uint32 (*gss_display_status_fn)(OM_uint32 *, OM_uint32, int, gss_OID, OM_uint32 *, gss_buffer_t);

struct GSSAPIFunctions {
	void *lib_handle = nullptr;
	gss_import_name_fn import_name = nullptr;
	gss_init_sec_context_fn init_sec_context = nullptr;
	gss_release_buffer_fn release_buffer = nullptr;
	gss_release_name_fn release_name = nullptr;
	gss_delete_sec_context_fn delete_sec_context = nullptr;
	gss_display_status_fn display_status = nullptr;
};

static GSSAPIFunctions gss_funcs;
static std::once_flag gss_init_flag;
static bool gss_available = false;

static void InitGSSAPI() {
	// Try platform-specific GSS-API libraries
#ifdef __APPLE__
	const char *lib_paths[] = {"/System/Library/Frameworks/GSS.framework/GSS", nullptr};
#else
	const char *lib_paths[] = {"libgssapi_krb5.so.2", "libgssapi_krb5.so", nullptr};
#endif

	for (int i = 0; lib_paths[i] != nullptr; i++) {
		gss_funcs.lib_handle = dlopen(lib_paths[i], RTLD_LAZY);
		if (gss_funcs.lib_handle) {
			break;
		}
	}

	if (!gss_funcs.lib_handle) {
		return;
	}

	gss_funcs.import_name = (gss_import_name_fn)dlsym(gss_funcs.lib_handle, "gss_import_name");
	gss_funcs.init_sec_context = (gss_init_sec_context_fn)dlsym(gss_funcs.lib_handle, "gss_init_sec_context");
	gss_funcs.release_buffer = (gss_release_buffer_fn)dlsym(gss_funcs.lib_handle, "gss_release_buffer");
	gss_funcs.release_name = (gss_release_name_fn)dlsym(gss_funcs.lib_handle, "gss_release_name");
	gss_funcs.delete_sec_context = (gss_delete_sec_context_fn)dlsym(gss_funcs.lib_handle, "gss_delete_sec_context");
	gss_funcs.display_status = (gss_display_status_fn)dlsym(gss_funcs.lib_handle, "gss_display_status");

	gss_available = gss_funcs.import_name && gss_funcs.init_sec_context && gss_funcs.release_buffer &&
	                gss_funcs.release_name && gss_funcs.delete_sec_context;
}

static std::string GSSStatusToString(OM_uint32 major, OM_uint32 minor) {
	if (!gss_funcs.display_status) {
		return "GSS-API error: major=" + std::to_string(major) + ", minor=" + std::to_string(minor);
	}

	std::string result;
	OM_uint32 msg_ctx = 0;
	OM_uint32 min_stat;
	gss_buffer_desc msg_buf;

	// Display major status
	do {
		gss_funcs.display_status(&min_stat, major, 1 /* GSS_C_GSS_CODE */, GSS_C_NO_OID, &msg_ctx, &msg_buf);
		if (msg_buf.length > 0) {
			if (!result.empty()) {
				result += "; ";
			}
			result += std::string((char *)msg_buf.value, msg_buf.length);
			gss_funcs.release_buffer(&min_stat, &msg_buf);
		}
	} while (msg_ctx != 0);

	// Display minor status
	msg_ctx = 0;
	do {
		gss_funcs.display_status(&min_stat, minor, 2 /* GSS_C_MECH_CODE */, GSS_C_NO_OID, &msg_ctx, &msg_buf);
		if (msg_buf.length > 0) {
			result += "; ";
			result += std::string((char *)msg_buf.value, msg_buf.length);
			gss_funcs.release_buffer(&min_stat, &msg_buf);
		}
	} while (msg_ctx != 0);

	return result;
}

static std::string GetLoadedLibraryPath() {
	std::call_once(gss_init_flag, InitGSSAPI);
	if (!gss_funcs.lib_handle) {
		return "";
	}
#ifdef __APPLE__
	// Try the known path
	const char *paths[] = {"/System/Library/Frameworks/GSS.framework/GSS", nullptr};
	for (int i = 0; paths[i]; i++) {
		void *test = dlopen(paths[i], RTLD_LAZY | RTLD_NOLOAD);
		if (test) {
			dlclose(test);
			return paths[i];
		}
	}
	return "GSS.framework";
#else
	// Use dladdr to find the loaded library path
	Dl_info info;
	if (gss_funcs.import_name && dladdr((void *)gss_funcs.import_name, &info) && info.dli_fname) {
		return info.dli_fname;
	}
	return "libgssapi_krb5.so";
#endif
}

bool NegotiateAuthIsAvailable() {
	std::call_once(gss_init_flag, InitGSSAPI);
	return gss_available;
}

std::string GetSecurityLibraryName() {
	return GetLoadedLibraryPath();
}

std::string GetProviderName() {
	std::call_once(gss_init_flag, InitGSSAPI);
	if (!gss_available) {
		return "unavailable";
	}
#ifdef __APPLE__
	return "GSS-API (GSS.framework)";
#else
	return "GSS-API";
#endif
}

NegotiateResult GenerateNegotiateToken(const std::string &url) {
	std::call_once(gss_init_flag, InitGSSAPI);

	if (!gss_available) {
		throw std::runtime_error("SPNEGO/Negotiate authentication requested but no GSS-API library is available. "
		                         "On Linux, install libkrb5-dev or krb5-libs. On macOS, GSS.framework should be present.");
	}

	auto hostname = ExtractHostname(url);

	// Build the SPN: "HTTP@hostname"
	auto spn = "HTTP@" + hostname;
	gss_buffer_desc name_buf;
	name_buf.value = (void *)spn.c_str();
	name_buf.length = spn.length();

	OM_uint32 major, minor;
	gss_name_t target_name = nullptr;

	major = gss_funcs.import_name(&minor, &name_buf, &gss_nt_hostbased_service_oid, &target_name);
	if (major != GSS_S_COMPLETE) {
		throw std::runtime_error("Failed to import GSS-API name '" + spn + "': " + GSSStatusToString(major, minor));
	}

	// Generate the SPNEGO token
	gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
	gss_buffer_desc output_token = {0, nullptr};
	OM_uint32 ret_flags = 0;

	major = gss_funcs.init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &ctx, target_name, &spnego_oid, GSS_C_MUTUAL_FLAG,
	                                   GSS_C_INDEFINITE, GSS_C_NO_BINDINGS, GSS_C_NO_BUFFER, nullptr, &output_token,
	                                   &ret_flags, nullptr);

	// Clean up the name immediately
	OM_uint32 min_ignore;
	gss_funcs.release_name(&min_ignore, &target_name);

	if (major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED) {
		if (ctx != GSS_C_NO_CONTEXT) {
			gss_funcs.delete_sec_context(&min_ignore, &ctx, GSS_C_NO_BUFFER);
		}
		throw std::runtime_error("Failed to initialize GSS-API security context for '" + spn +
		                         "': " + GSSStatusToString(major, minor));
	}

	// Base64 encode the output token
	std::string token_b64;
	if (output_token.length > 0 && output_token.value) {
		token_b64 = Base64Encode(output_token.value, output_token.length);
		gss_funcs.release_buffer(&min_ignore, &output_token);
	}

	// Clean up the context — for pre-flight auth we don't maintain it
	if (ctx != GSS_C_NO_CONTEXT) {
		gss_funcs.delete_sec_context(&min_ignore, &ctx, GSS_C_NO_BUFFER);
	}

	NegotiateResult result;
	result.token = token_b64;
	result.url = url;
	result.hostname = hostname;
	result.spn = spn;
	result.provider = GetProviderName();
	result.library = GetLoadedLibraryPath();
	return result;
}

#endif // _WIN32

} // namespace blobhttp
