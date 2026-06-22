# blobsso — Context & Handoff

*Written 2026-06-22 to let a fresh Claude Code session resume with minimal context.
Working name `blobsso` (was `blobauth`; may still change). Owner: phrrngtn.*

## 1. What we're building

A **DuckDB C++ extension** providing **enterprise SSO → temporary S3 credentials**,
so DuckDB `httpfs` can read/write an S3-compatible store (MinIO on dc1) using the
**OS/enterprise identity** instead of static, long-lived access keys.

Motivation: the `ha_ducklake` lakehouse (Postgres catalog + MinIO Parquet + DuckDB
compute) currently uses **static MinIO access keys** in a DuckDB `CREATE SECRET
(TYPE s3, KEY_ID …, SECRET …)`. We made the *Postgres* side password-less (peer auth);
the object-store side is the remaining secret. This extension closes that gap with
**STS temporary credentials** that auto-rotate — the object-store analogue of
"integrated security."

## 2. Current status

- Local git repo at `~/checkouts/blobsso` (renamed from `blobauth`; **no remote yet**).
- **Scaffolded 2026-06-22** from the official `duckdb/extension-template` (chosen over
  mirroring blobhttp's hand-rolled harness). `src/blobsso_extension.cpp` registers the
  **Stage 1 tracer-bullet `sso` provider for `TYPE s3`** — round-trips config into a
  `KeyValueSecret` (placeholder creds + `refresh=auto`); real STS call is the next edit.
  Test: `test/sql/blobsso.test`.
- **Pinned to duckdb `v1.5.4`** (and `extension-ci-tools v1.5.4`) as git submodules —
  NOT a `main` commit. Why: the C++ extension ABI is version-locked, and we want
  runtime `INSTALL httpfs; LOAD httpfs;` in tests to resolve a **prebuilt** httpfs from
  extensions.duckdb.org. A `main`/untagged shallow clone reports version `v0.0.1` →
  `INSTALL httpfs` 404s. A real release tag fixes both. To bump duckdb, re-pin BOTH
  submodules to the same `vX.Y.Z` tag and clean-rebuild.
- **httpfs is NOT compiled in** (it's out-of-tree; `duckdb_extension_load(httpfs)`
  fails — "not an existing directory"). We only need the **s3 secret type** it
  registers (and later its core HTTPUtil), both available at runtime → tests do
  `INSTALL httpfs; LOAD httpfs;`. So blobsso links **zero** external libs (no OpenSSL).
- **Build:** `VCPKG_TOOLCHAIN_PATH=~/vcpkg/scripts/buildsystems/vcpkg.cmake make`
  (first build compiles duckdb core once — unavoidable, see §3; later edits relink in
  seconds). Artifacts: `build/release/duckdb`, `build/release/test/unittest`.
- **Develop locally on the Mac** (confirmed). dc1 is the *deploy/test* target
  (MinIO + the lake live there), not the dev box.

## 3. The DuckDB secret-provider API (verified, the crux)

Verified against `duckdb/duckdb-aws` `src/aws_secret.cpp` (cloned on dc1 at
`/tmp/duckdb-aws`). It is **core C++ only — NOT in the C extension API**, so a C++
extension is mandatory (the user independently reached the same conclusion).

**Confirmed 2026-06-22 at the header level** (local duckdb submodule @ 08e34c44): the
security/secret surface is entirely absent from the stable **C jump table** — both
`src/include/duckdb.h` and the C-extension struct `src/include/duckdb_extension.h`
have **zero** occurrences of `secret` (vs. `duckdb_register_scalar_function` which IS
present at `duckdb.h:3821`). Consequence chain: secret provider ⇒ C++-only API ⇒
unstable ABI ⇒ must build against matching duckdb **source** (this is why the one-time
duckdb-core compile is unavoidable; a stable-ABI version-independent C extension is
**not** possible for a secret provider).

A provider is literally a struct + a create function:
```cpp
// {secret_type, provider_name, create_fn}
CreateSecretFunction f = {"s3", "sso", CreateS3SecretFromSSO};
f.named_parameters["token_endpoint"] = LogicalType::VARCHAR;   // CREATE SECRET params
f.named_parameters["role_arn"]       = LogicalType::VARCHAR;
// ... region, sts_endpoint, endpoint, url_style, web_identity_token_file, etc.
loader.RegisterFunction(f);   // ExtensionLoader& in Load(); also register the s3 type

// create_fn(ClientContext&, CreateSecretInput&) -> unique_ptr<BaseSecret>:
//   1. read params from CreateSecretInput
//   2. obtain temp creds (the real work — see §4)
//   3. build a KeyValueSecret; set secret_map["key_id"/"secret"/"session_token"/
//      "region"/"endpoint"/"url_style"/"use_ssl"]
//   4. result->secret_map["refresh"] = "auto";   // DuckDB re-invokes create_fn on expiry
```
Key facts:
- `refresh="auto"` is the rotation hook — DuckDB re-runs `create_fn` when creds expire.
  This is how STS short-lived creds stay fresh transparently.
- In duckdb-aws, the base S3 secret is built by `ConstructBaseS3Secret(scope, type,
  provider, name)`; `secret_map["region"]=…` etc. Mirror that shape.
- Registration (`CreateAwsSecretFunctions::Register(ExtensionLoader&)`) loops secret
  types {s3,r2,gcs,aws,rds} and sets `named_parameters` per function. We only need `s3`
  (and maybe `r2`/`gcs` later).
- duckdb-aws's `credential_chain` provider auto-sets `refresh="auto"` for the
  web_identity/STS chains — same idea we want.

## 4. The reframe that shrinks the project (IMPORTANT)

The provider function is tiny. **The only real work is one outbound STS call**
(`AssumeRoleWithWebIdentity`) + parsing its small XML response into
key_id/secret/session_token/expiration. So the question "what HTTP/crypto deps do we
need?" decomposes:

1. **STS exchange (JWT already in hand → temp creds):** a plain HTTPS POST, no special
   auth. Body is form-encoded (`Action=AssumeRoleWithWebIdentity&WebIdentityToken=<jwt>
   &RoleArn=<arn>&Version=2011-06-15`); response is XML. This can ride **DuckDB's core
   `HTTPUtil`/`HTTPClient`** abstraction (the one `httpfs` implements) → **we link no
   HTTP library**. We'd only need a tiny XML scrape (hand-rolled or tinyxml2).
   - **VERIFIED 2026-06-22 — YES, reachable cross-extension (zero new deps).** Evidence
     (against local clone `~/checkouts/duckdb-httpfs`, which vendors duckdb core):
     - Header to include: `duckdb/common/http_util.hpp` (core, **`common/` not `main/`**),
       defines `HTTPUtil`, `HTTPParams`, `HTTPHeaders`, `HTTPResponse`, `PostRequestInfo`.
     - Retrieval: `static HTTPUtil &HTTPUtil::Get(DatabaseInstance &db)` returns
       `db.config.http_util` (`duckdb/src/main/http/http_util.cpp:91`). It's a
       `shared_ptr<HTTPUtil>` on `DBConfig` — a base class **set by httpfs at load**
       (`httpfs_extension.cpp:206` and `:230`, `make_shared_ptr<HTTPFSCurlUtil>()`).
     - POST: build `PostRequestInfo(url, headers, params, body_ptr, body_len)`, call
       `http_util.Request(post_req)` → `unique_ptr<HTTPResponse>`; response body in
       `post_req.buffer_out` / `response->body`. Real caller pattern:
       `HTTPFileSystem::PostRequest` (`src/httpfs.cpp:172`). Core also self-uses it in
       `extension_install.cpp` (`auto &http_util = HTTPUtil::Get(db);`).
     - **Only constraint:** httpfs must be loaded before our create_fn runs (we depend on
       it for S3 anyway). If `config.http_util` is unset → require/`LoadExtension("httpfs")`
       or error with a clear message.
   - Fallback (now unlikely needed): link our **own libcurl** for the STS POST. aws-sdk-cpp
     stays rejected as too heavy for one call.

2. **Acquiring the JWT via Kerberos/SPNEGO** (`Authorization: Negotiate`): httpfs's HTTP
   stack will **not** do GSSAPI/`CURLAUTH_NEGOTIATE`. This needs **libcurl + GSSAPI**
   (the `blobhttp` core). BUT it's only needed if the JWT comes from a Kerberos-
   protected endpoint. **If the JWT is supplied via file / env / plain OIDC GET, no
   GSSAPI and no libcurl at all.**

**Staging that falls out of this:**
- **Stage 1 (zero new deps):** S3 SSO provider. JWT obtained from `web_identity_token_file`
  / env / plain GET → STS POST (via httpfs `HTTPUtil`, or our curl fallback) →
  `KeyValueSecret` + `refresh="auto"`. ~80% of the value: rotating, key-less S3 access.
- **Stage 2 (adds GSSAPI):** SPNEGO to *obtain* the JWT from a Kerberos endpoint, and/or
  a `negotiate_token()` / `TYPE http` secret to inject `Authorization: Negotiate` for
  stock httpfs. Reuse `blobhttp`'s GSSAPI core.

## 5. Decisions

| # | Decision | Status |
|---|----------|--------|
| C++ (not C) extension | secret-provider API is C++-core only | **settled** |
| Name | `blobsso` | settled (may still change) |
| Dev location | local Mac; dc1 is deploy/test | **settled** |
| STS via aws-sdk-cpp? | **No** — too heavy for one POST | settled |
| STS HTTP transport | **reuse httpfs `HTTPUtil`** (zero deps) — verified reachable | **settled (2026-06-22, see §4.1)** |
| SPNEGO placement | reuse/extend **blobhttp** GSSAPI core (`negotiate_auth.{hpp,cpp}`) | leaning, Stage 2 |
| Scope first cut | **Stage 1** (JWT→STS→secret), no SPNEGO yet | settled |

## 6. Prior art / community extensions (don't reinvent)

Searched 2026-06-22:
- **`quack-oauth`** (DataZooDE) — OAuth 2.1/OIDC for the *duckdb-quack server* protocol:
  validates bearer JWTs (JWKS / RFC 7662 introspection / tokeninfo) and gates
  ATTACH/SELECT/COPY by policy. **Server-side auth, not a secret provider** — different
  problem, but a reference for JWT validation code in a DuckDB extension.
  https://github.com/DataZooDE/quack-oauth
- **`jwt`** community extension — decode/inspect JWTs in SQL. Useful primitive if we
  need to read token claims (e.g. exp) in-engine.
  https://duckdb.org/community_extensions/extensions/jwt
- **httpfs `TYPE http` secret** — `CREATE SECRET (TYPE http, BEARER_TOKEN '…')` and
  custom/`EXTRA_HTTP_HEADERS` **exist** — this is the injection point for Face 2
  (Negotiate header) without patching httpfs. Confirm exact param names against the
  installed httpfs version.
- A community **HTTP-client TVF extension with SPNEGO/Negotiate** reportedly exists
  (GET/POST table functions). Possibly relevant prior art for the Kerberos path — and
  the user's own **`blobhttp`** already implements SPNEGO/GSSAPI. **Next session:** scan
  https://duckdb.org/community_extensions/list_of_extensions and
  https://github.com/mehd-io/duckdb-extension-radar for an existing STS/SSO secret
  provider before writing our own, to avoid duplicating effort.
- **`duckdb-aws`** core extension — the template we're mirroring; its `credential_chain`
  provider already does env/profile/web_identity → creds with `refresh=auto`. We are
  essentially adding an **`sso` provider variant** that does the JWT→STS step explicitly
  (and, later, the SPNEGO-for-JWT step) for **non-AWS / MinIO** STS endpoints.
  - **CONFIRMED 2026-06-22 (read `aws_secret.cpp` on GitHub) — `credential_chain` cannot
    do our job.** It accepts `web_identity_token_file` + `assume_role_arn`, but routes
    everything through **aws-sdk-cpp's** provider chain → **AWS STS only**. Its `endpoint`
    param configures the **S3 storage** service, *not* STS; there is **no custom STS
    endpoint** and no custom token-source/endpoint param. So it categorically can't target
    MinIO STS or a SPNEGO/OIDC token endpoint. **No existing extension fills this niche.**

## 7. Resources & locations

- **This repo:** `~/checkouts/blobsso` (Mac).
- **Reference clones on dc1** (`ssh phrrngtn@dc1`):
  - `/tmp/duckdb-aws` — `src/aws_secret.cpp` is THE provider template (see §3).
  - `/tmp/duckdb-httpfs` — for finding the HTTP secret type + the `HTTPUtil` abstraction.
  - `/tmp/ducklake_src` — DuckLake source (unrelated to this project).
  (These are throwaway `/tmp` clones; re-clone locally on the Mac for dev.)
- **blob\* family convention** (`~/checkouts/CLAUDE.md`): C/C++ core + thin
  SQLite/DuckDB/Python wrappers, CMake + FetchContent; *business logic in the shared C
  library, thin shims*. Siblings: `blobtemplates`, `blobboxes`, `blobfilters`,
  `blobodbc`, `blobhttp` (← has the SPNEGO/GSSAPI code to reuse), `blobrule4`, `blobembed`.
- **Consumer / why this exists:** `~/checkouts/ha_ducklake` (the lakehouse replicator)
  and `~/checkouts/ducklake_oob_writer`. The S3 secret it would replace is in
  `ha_ducklake/src/ha_ducklake/config.py` → `S3Config.create_secret_sql()` (currently
  static `KEY_ID`/`SECRET`). MinIO runs in `/opt/ha-stack` on dc1 (endpoint
  `127.0.0.1:9000`, console open). Roadmap note parked in
  `~/research/DuckLake Lakehouse Roadmap.md` ("SPNEGO→STS secret provider [must be C++]").
- **Docs convention:** high-level `docs/*.md` get symlinked into `~/research/`
  (Obsidian vault) — `ln -s ~/checkouts/blobsso/docs/<Note>.md ~/research/<Note>.md`.

## 8. Next steps (for the fresh session)

1. ~~**Verify the `HTTPUtil` cross-extension API**~~ — **DONE 2026-06-22: reuse it, zero
   HTTP deps** (§4.1). CMake deps list for Stage 1 = just duckdb + httpfs headers.
2. ~~**Scan community extensions**~~ — **DONE 2026-06-22: niche unfilled** (§6); duckdb-aws
   `credential_chain` is AWS-STS-only and can't target MinIO STS.
3. ~~**Scaffold**~~ — **DONE 2026-06-22** (official extension-template, duckdb v1.5.4).
4. ~~**Stage 1 impl**~~ — **DONE 2026-06-22 (client-first).** `CreateS3SecretFromSSO`:
   JWT (`token` inline / `web_identity_token_file` / `AWS_WEB_IDENTITY_TOKEN_FILE`) →
   form-encoded `AssumeRoleWithWebIdentity` POST via httpfs `HTTPUtil` → parse XML →
   `KeyValueSecret` (key_id/secret/session_token/expiration, redacted). Verified:
   `test/mock_sts_test.py` (mock STS success round-trip) + live POST to MinIO on dc1
   (surfaces real STS XML; errors only because the dummy token isn't trusted yet).
   **Refresh-on-expiry NOT yet wired** (TODO in create_fn).
5. **Stage 2 (← NEXT): the Kerberos→JWT bridge.** dc1 has Samba AD (Kerberos/LDAP) but
   **no OIDC IdP** — see [[dc1-infrastructure-inventory]]. Plan agreed with user
   2026-06-22: *client-first then Keycloak; skip the AD/LDAP-bind mechanism.* So next:
   deploy **Keycloak** on dc1 federated to Samba AD with SPNEGO, register an SPN/keytab,
   configure MinIO `identity_openid` to trust it; blobsso acquires the JWT via
   `Authorization: Negotiate` (reuse `blobhttp` `negotiate_auth.{hpp,cpp}`). Needs user
   go-ahead to provision the Keycloak container on dc1 (shared state).

## 9. User working preferences (from CLAUDE.md + this session)

- Terse; lead with action/result, no trailing summaries. Don't ask permission for
  trivially reversible local actions; **do** ask before shared-state ops (git push, PR,
  Docker). Outline a plan before large architectural/vendoring decisions.
- Python: brew Python via `uv` only (`uv run python`), inline scripts to a temp file
  then `uv run`. (Mostly irrelevant here — this is C++.)
- Prefers **integrated security / password-less** everywhere (drove this whole project).
- "Business logic in the shared C library; thin shims." Don't duplicate (→ reuse blobhttp).
- Forgejo on dc1 for self-hosted remotes (see `~/checkouts/CLAUDE.md` for API/mTLS);
  also publishes to GitHub. No remote created for blobsso yet.
