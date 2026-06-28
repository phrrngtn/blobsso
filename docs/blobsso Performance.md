# blobsso — Performance Notes

> Why this matters: in an enterprise setting the interesting costs aren't the SQL engine —
> they're the **authentication handshake** and the **per-object overhead of object storage**.
> This note characterizes both with measurements, and the layered mitigations that retire
> them. Related: [[blobsso]], [[spnego-token]].

All figures are **warm** measurements on a LAN — DuckDB on a laptop; MinIO, Keycloak, and a
Samba KDC on a single host. Absolute numbers vary with network and hardware; the **shape** is
the point. Reproduce your own with `BLOBSSO_TIMING=1` (per-step SSO breakdown to stderr) and
the DuckDB CLI `.timer on` (per-statement wall-clock).

---

## 1. The SSO cost — one-time, ~230 ms per secret

`CREATE SECRET (TYPE s3, PROVIDER sso, …)` runs the whole identity → STS chain once:

| step | ~time | what it is |
|---|---|---|
| `oidc_discover` | 46 ms | first TLS handshake + `.well-known` GET |
| `spnego_authorize` | 93 ms | its own connection (needs `follow_location=false` to capture the 302) + Keycloak `gss_accept_sec_context` |
| `oidc_token_exchange` | 10 ms | reuses the discovery connection (keep-alive) |
| `sts_assume_role` | 70 ms | MinIO verifies the JWT + mints temp creds (no TLS — plain HTTP) |
| **total** | **~230 ms** | |

Paid **once per secret** — the temporary credentials are then cached and only re-minted on
expiry ([auto-rotation](../README.md#refresh--auto-rotation), ~hourly). The dominant costs are
**inherent**: serial OIDC+STS round trips plus server-side crypto (Keycloak validating the
Kerberos ticket, MinIO verifying the JWT). The one avoidable cost — repeated TLS handshakes —
was removed by **reusing a single keep-alive HTTP client** for the discovery + token calls.
The authorize step keeps its own connection on purpose (it must read the 302 redirect rather
than follow it). Measured effect: token exchange ~25 ms → ~10 ms; `jwt_total` ~200 ms → ~150 ms.

> **Measurement gotcha:** the *first* run after a rebuild can show a multi-second
> `oidc_discover`. That is a local application firewall (e.g. Little Snitch) prompting on the
> new binary, or a cold DNS resolution — **not** blobsso. Warm runs are the real numbers.

## 2. The per-object S3 overhead — ~8–12 ms per object

Independent of blobsso; this is the cost of reading an object from S3/MinIO via `httpfs`:

| query | time |
|---|---|
| `read_parquet` of one small file from MinIO (cold) | ~13 ms |
| same (warm) | ~8 ms |
| **same file from local disk** | **<1 ms** |

So **~8–12 ms per object *open*** — almost entirely HTTP round-trip overhead (object size +
parquet footer + data range requests), not data transfer. A 551-byte file and a 500 MB file
pay nearly the same *fixed open cost*; it scales with the **number of objects**, not their
size. A glob over **269 tiny DuckLake files cost 222 ms** (LIST + 269 footer probes) to return
176 rows of actual data.

This is the well-known object-storage analytics tax: favour **few, large** files; avoid
many-tiny-files and point lookups.

## 3. Mitigations (each at a different layer)

### DuckLake catalog — retires the metadata round trips

A metadata catalog (DuckLake here; Iceberg/Delta are analogous) keeps schema, file lists, row
counts, and column stats in a SQL database. Planning becomes **one catalog query** — no
per-file footer probing.

| | time | parquet files opened |
|---|---|---|
| raw glob (269 files) | 222 ms | 269 |
| DuckLake `count(*)` (cold) | 12 ms | **0** |
| DuckLake `count(*)` (warm) | 3.9 ms | **0** |

The count came from the catalog's row-count statistics — **zero parquet files opened**
(proven: it ran with *no S3 secret loaded at all*). It is **O(1) in the catalog vs O(N) in
file-opens**: add 10,000 files and the catalog count stays ~4 ms while the raw glob grows
linearly.

### cache_httpfs — retires repeated data fetches

The community `cache_httpfs` extension caches S3 reads on local disk:

| read of the 269 files | time |
|---|---|
| #1 cold (fetch from MinIO + populate cache) | 208 ms |
| #2 / #3 (cache hit) | ~4 ms |

**~40–50× on repeated reads**, and it works **transparently through blobsso's secret** (it
wraps `httpfs`, so the temp creds flow straight through). The usual cache-correctness hazard —
invalidation — **does not apply to lake data**: those parquet files are immutable (a path's
bytes never change; new data = new files, tracked by the catalog). A URL-keyed byte cache is
therefore **correct by construction** for this workload. It is a community extension, so vet
its maturity before production, but it is a sound fit for immutable lake data.

## The layered picture

All three are driven by one keyless `CREATE SECRET`, and they compose because each sits at a
different layer:

| concern | without | with |
|---|---|---|
| **planning / metadata** (which files, how many rows) | 222 ms raw glob, O(N files) | **DuckLake catalog** — ~4 ms `count`, 0 files, O(1) |
| **repeated data bytes** | 208 ms re-fetch every query | **cache_httpfs** — ~4 ms from local cache |
| **auth** | static keys distributed per client | **blobsso** — ambient Kerberos → STS, no keys, auto-rotating |

The ~8–12 ms-per-object S3 tax is only paid on **cold, catalog-less, uncached** access — which
is exactly the case all three of these are designed to retire. blobsso's job is the auth layer:
turn an enterprise identity into short-lived, keyless credentials once, transparently to the
catalog and the cache above it.

## Reproducing

```sh
# Per-step SSO breakdown (stderr) + per-statement timing:
BLOBSSO_TIMING=1 duckdb -c ".timer on" -f your_queries.sql
```

- `BLOBSSO_TIMING=1` — `oidc_discover` / `spnego_authorize` / `oidc_token_exchange` /
  `jwt_total` / `sts_assume_role` to stderr (env-gated; off by default).
- `.timer on` — DuckDB CLI per-statement real/user/sys time.
- DuckLake `count(*)` vs raw `read_parquet(... '*.parquet')` isolates catalog vs file-open cost.
- Reading the same S3 path twice (with `cache_httpfs` loaded) isolates cold-fetch vs cache-hit.

## Related

- [[blobsso]] — the SSO → STS → S3 secret provider this note measures.
- [[spnego-token]] — the curl-free preemptive-SPNEGO atom behind the `oidc_discover` /
  `spnego_authorize` steps.
