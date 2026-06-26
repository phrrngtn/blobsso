# blobsso  *(working name — may change)*

> **Note:** This code is almost entirely AI-authored (Claude, Anthropic), albeit under close human supervision, and is for research and experimentation purposes. Successful experiments may be re-implemented in a more coordinated and curated manner.

A **DuckDB C++ extension** that acts as an enterprise **SSO / STS secret provider**
for object-store (S3-compatible) access — and optionally a **SPNEGO/Negotiate**
helper so stock `httpfs` can talk to Kerberos-protected HTTPS without static keys.

> **Read `CONTEXT.md` first** — it is the full design/decision handoff (written so a
> fresh session can resume cleanly). This README is the short version.

## Key reframe (the "do we even need libcurl?" insight)

The provider surface is tiny: a `create_fn` that returns a `KeyValueSecret`. The only
real work is **one outbound STS call** (`AssumeRoleWithWebIdentity`) + parsing its XML.
- The **STS POST** (JWT already in hand) is a plain HTTPS POST with no special auth →
  it can ride **DuckDB's core `HTTPUtil`/`HTTPClient`** (the abstraction `httpfs`
  implements) so we link **no HTTP library** ourselves. *(Cross-extension API
  reachability still to verify — see CONTEXT.md.)*
- **libcurl + GSSAPI is needed ONLY** to acquire the JWT from a **Kerberos-protected**
  endpoint (SPNEGO) or to inject `Authorization: Negotiate`. If the JWT comes from a
  file / env / plain OIDC GET, **no GSSAPI, no libcurl.**

Hence the staging: **Stage 1 = zero new deps** (JWT→STS→secret over httpfs's HTTP);
**Stage 2 = GSSAPI** only for the Kerberos pre-auth path.

## Why a C++ extension (not C)

The DuckDB **secret-provider** API is core C++ — `CreateSecretFunction`,
`BaseSecret`/`KeyValueSecret`, `ExtensionLoader`, `ClientContext`. None of it is
exposed in the C extension API, so the provider must be C++ (verified against
`duckdb/duckdb-aws` `src/aws_secret.cpp`).

## The provider interface (from duckdb-aws)

A provider registration is literally:
```cpp
CreateSecretFunction f = {/*type*/ "s3", /*provider*/ "sso", CreateS3SecretFromSSO};
f.named_parameters["token_endpoint"] = LogicalType::VARCHAR;   // etc.
loader.RegisterFunction(f);
```
The create function reads `CreateSecretInput`, builds a `KeyValueSecret` whose
`secret_map` carries `key_id` / `secret` / `session_token` / `region` / `endpoint`,
and sets `refresh = "auto"` so DuckDB re-invokes it when the temporary credentials
expire. `httpfs` then consumes that secret for S3 exactly as if it were static keys.

## Architecture — two faces, one auth core

**Face 1 — S3 SSO/STS secret provider** *(the definite, well-fitting piece)*
```
CREATE SECRET (TYPE s3, PROVIDER sso, token_endpoint '…', role_arn '…',
               sts_endpoint '…', endpoint 's3.host', url_style 'path');
```
Flow: **acquire a JWT** (file / env / plain OIDC GET / — later — SPNEGO) →
**STS `AssumeRoleWithWebIdentity`** (AWS STS or MinIO STS) → **temporary creds** →
`KeyValueSecret` + `refresh="auto"`. No static keys; rotation is automatic.

**Face 2 — SPNEGO/Negotiate for httpfs** *(optional; Stage 2)*
- The JWT acquisition in Face 1 can itself authenticate to the token endpoint via
  **SPNEGO** (`Authorization: Negotiate …`), i.e. OS/Kerberos identity → JWT.
- Separately, a `negotiate_token(spn)` scalar function (or a `TYPE http` secret) can
  emit a preemptive `Authorization: Negotiate <b64>` header for **stock httpfs** —
  *no httpfs patch*. (`TYPE http` supports `BEARER_TOKEN` / `EXTRA_HTTP_HEADERS` —
  confirmed it exists; exact mechanics to verify.)

**The GSSAPI/SPNEGO core is shared**, not duplicated — `blobhttp` already has the
Negotiate/GSSAPI implementation. blob* principle: business logic in the shared C
library; this extension is the thin DuckDB secret-provider/function shim over it.

## Open decisions (see CONTEXT.md)

1. **Reuse httpfs's `HTTPUtil` for the STS POST** (preferred, zero deps) vs link our
   own libcurl. Verify the core HTTP API is reachable from another extension.
2. **SPNEGO placement** (Stage 2): reuse/extend `blobhttp`'s GSSAPI core vs self-contain.
3. **Name** (working: `blobsso`).

## Layout (planned, blob* pattern)

```
CMakeLists.txt          # FetchContent duckdb + deps; blob* CMake style
src/                    # the C++ extension + secret-provider registration
  blobsso_extension.cpp
  s3_sso_secret.cpp     # Face 1: JWT -> STS -> KeyValueSecret + refresh
  negotiate.cpp         # Face 2 (Stage 2): SPNEGO token (over the shared GSSAPI core)
test/                   # sqllogictest: CREATE SECRET (PROVIDER sso ...) round-trips
docs/                   # design notes (symlinked into ~/research)
```
