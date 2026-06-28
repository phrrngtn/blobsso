# Disaggregated Lakehouse — Out-of-Band Writers, Keyless Readers

> Where blobsso sits in a bigger picture: it governs the **read** side of a lakehouse whose
> **write** side is deliberately decoupled from any query engine. This note works through the
> pattern and a concrete use-case — **constructing arbitrary facets over pre-existing data by
> writing independent catalogs out-of-band, with zero data copy** — and why it's compelling for
> **cloud → on-premises data repatriation**. Related: [[blobsso]], [[spnego-token]],
> [[blobsso Performance]].

## The two planes of a lakehouse

[DuckLake](https://ducklake.select) (like Iceberg/Delta) splits a lakehouse into two independent
planes:

- **Data plane** — immutable Parquet files in object storage. A file at a given path never
  changes; new data is new files.
- **Catalog plane** — snapshots, schema, file lists, and per-column statistics, stored as
  ordinary tables in a SQL database (Postgres / SQLite / DuckDB).

The engine that *writes* the catalog need not be the engine that *reads* it, and **neither has
to be the engine that produced the Parquet**. That decoupling is the whole opportunity.

## Out-of-band writes — no engine on the write path

Normally you populate a lakehouse *through* the query engine (`INSERT … `/`COPY` via DuckDB's
`ducklake` extension), which writes the Parquet and updates the catalog in one transaction. An
**out-of-band (OOB) writer** instead:

1. lets a producer write the Parquet files by any means (Spark, Arrow, pandas, a cloud ETL job,
   `mc`/`aws s3 cp`), and
2. registers them by writing the **catalog tables directly** (e.g. via SQLAlchemy), so DuckDB
   reads the result as if it had been written natively.

The producer needs **no DuckDB and no query engine at all** — just the ability to put Parquet in
object storage and `INSERT` rows into a SQL catalog. Two properties fall out:

- **Source-time fidelity.** The native write path stamps each snapshot with the ETL process's
  `now()`. An OOB writer can stamp it with the *source system's* transaction-time, making the
  lake **bitemporal**: `AS OF` time-travel reflects source reality, and late-arriving / backfilled
  data lands at the correct point in history rather than smeared onto catch-up time.
- **Zero-copy facets.** Because registration only *references* Parquet by path, you can register
  the *same* physical files into *different* catalogs — see the use-case below.

## Use-case: arbitrary facets over pre-existing data

**Goal:** given immutable Parquet already sitting in on-prem object storage, present several
independent, governed **views/facets** over it — different consumers, different curation — with
**no data movement and no engine on the write path**.

Because a catalog is just SQL rows pointing at Parquet paths, you build *N* independent catalogs
over the *same* artifacts:

| facet (independent catalog) | how it differs | data copied |
|---|---|---|
| `full` | every file, every column | **none** |
| `public` | same files, **subset of columns** (e.g. omit a sensitive measure) | **none** |
| `recent` | **subset of files** (one time window / partition) | **none** |
| `team_x` | renamed schema, its own snapshot lineage | **none** |

Each facet is a few hundred rows in a SQL catalog. The Parquet is written once and shared by
reference. A consumer attaches *their* catalog and queries *their* facet; the data plane is
identical underneath.

### Where blobsso fits

The facets are governed on the **read** side by identity, not by static keys:

```sql
-- one keyless preamble, then query any facet:
CREATE SECRET lake (TYPE s3, PROVIDER sso, oidc_issuer '…', sts_endpoint '…', endpoint '…');
ATTACH 'ducklake:…public_catalog…' AS pub (DATA_PATH 's3://lake/data/');
SELECT * FROM pub.readings;   -- reads the shared Parquet with SSO'd temporary creds
```

- **Write path** (OOB producer → Parquet + catalog) is fully independent of DuckDB and of blobsso.
- **Read path** (DuckDB + the facet catalog) gets keyless, auto-rotating S3 access from blobsso —
  the consumer's enterprise identity, not a distributed access key, decides what they can read.

The two are orthogonal: producers land artifacts and register facets; consumers authenticate via
SSO and read. Neither knows about the other's credentials.

## Why this matters for cloud → on-prem repatriation

The disaggregation is exactly what a repatriation flow wants:

1. **Land the artifacts on-prem, once.** A producer (wherever it runs) writes Parquet to on-prem
   object storage (MinIO). No re-export through a query engine, no vendor data format.
2. **Build governed facets on-prem, out-of-band.** Independent catalogs over those artifacts
   express each team's view — column/row curation, bitemporal source-time — without copying data
   or standing up a write-side engine.
3. **Govern reads by on-prem identity.** blobsso turns the existing enterprise SSO (Kerberos →
   OIDC → STS) into short-lived, keyless credentials, so on-prem access control — not cloud IAM,
   not shared keys — decides who reads what.

The result: data physically repatriated to on-prem storage, logically organized by lightweight
catalogs, and access-governed by the identity system the enterprise already runs — with no static
credentials and no lock-in on the producer side.

## Building blocks (verified)

The pieces this composes from were each exercised against a live on-prem stack (Samba KDC,
Keycloak, MinIO):

- **blobsso** reads *and writes* MinIO with SSO'd STS creds (no static keys) — the read/write
  feasibility for both consumers and OOB stagers.
- **DuckLake catalog** answers metadata queries from the catalog alone — e.g. `count(*)` in ~4 ms
  having opened **zero** Parquet files (see [[blobsso Performance]] for the numbers).
- **OOB catalog writes** populate the ~28 DuckLake catalog tables directly via SQLAlchemy
  (Postgres / SQLite / DuckDB), so any producer can register data with no DuckDB on the write path.

### Worked example — outline

1. **Pre-existing data:** Parquet files already in `s3://…/data/main/readings/` (immutable).
2. **Facet A (`full`):** create a SQLite catalog, `init_catalog(data_path='s3://…/data')`,
   `create_table('main','readings', <all columns>)`, register each Parquet file.
3. **Facet B (`public`):** a *second*, independent catalog over the *same* `data_path`, declaring
   `readings` with a **subset of columns** — a governance view, zero copy.
4. **Read (keyless):** from any client, `CREATE SECRET … PROVIDER sso`, `ATTACH` each catalog with
   `DATA_PATH 's3://…/data/'`, and query — the shared Parquet is read with blobsso's temporary
   credentials.

The catalogs are independent SQL artifacts; the data plane is one set of files; identity governs
the reads.
