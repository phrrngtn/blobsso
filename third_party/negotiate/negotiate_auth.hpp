#pragma once

#include <string>

namespace blobhttp {

//! Result of a Negotiate token generation attempt.
struct NegotiateResult {
	std::string token;    // base64-encoded SPNEGO token
	std::string url;      // the original URL
	std::string hostname; // extracted hostname
	std::string spn;      // constructed Service Principal Name
	std::string provider; // "SSPI" or "GSS-API" or "GSS-API (GSS.framework)" etc.
	std::string library;  // path/name of the loaded security library (Unix only)
};

//! Generate a pre-flight HTTP Negotiate authentication token.
//! Extracts the hostname from the URL to construct the SPN,
//! then acquires a SPNEGO token via GSS-API (macOS/Linux) or SSPI (Windows).
//! Throws std::runtime_error if no security provider is available or token generation fails.
//! allow_insecure permits plain-HTTP target URLs (e.g. when the transport is
//! already encrypted by an overlay such as Tailscale/WireGuard); default false.
NegotiateResult GenerateNegotiateToken(const std::string &url, bool allow_insecure = false);

//! Returns true if a security provider (GSS-API or SSPI) is available on this system.
bool NegotiateAuthIsAvailable();

//! Returns the name/path of the loaded security library, or empty if none.
std::string GetSecurityLibraryName();

//! Returns the provider name ("SSPI", "GSS-API", or "unavailable").
std::string GetProviderName();

} // namespace blobhttp
