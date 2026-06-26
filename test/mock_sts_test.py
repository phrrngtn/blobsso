#!/usr/bin/env python3
"""Integration test: blobsso 'sso' provider against a mock STS server.

Starts a local HTTP server that mimics MinIO/AWS STS
AssumeRoleWithWebIdentity, drives the built duckdb CLI through
CREATE SECRET (..., PROVIDER sso, ...), and asserts that the temporary
credentials parsed out of the STS XML land in the secret. Also checks the
request body blobsso sent was correctly form-encoded.

Run: uv run --no-project python test/mock_sts_test.py
Requires a prior `make` (uses build/release/duckdb). Stdlib only.
"""
import http.server
import subprocess
import sys
import threading
from pathlib import Path
from urllib.parse import parse_qs

REPO = Path(__file__).resolve().parent.parent
DUCKDB = REPO / "build" / "release" / "duckdb"

CREDS = {
    "AccessKeyId": "MOCKKEYID123",
    "SecretAccessKey": "mockSecretKeyABC",
    "SessionToken": "mockSessionTokenXYZ",
    "Expiration": "2026-06-22T23:59:59Z",
}

STS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
    "<AssumeRoleWithWebIdentityResult><Credentials>"
    f"<AccessKeyId>{CREDS['AccessKeyId']}</AccessKeyId>"
    f"<SecretAccessKey>{CREDS['SecretAccessKey']}</SecretAccessKey>"
    f"<SessionToken>{CREDS['SessionToken']}</SessionToken>"
    f"<Expiration>{CREDS['Expiration']}</Expiration>"
    "</Credentials></AssumeRoleWithWebIdentityResult>"
    "</AssumeRoleWithWebIdentityResponse>"
)

received = {}


class STSHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        received["body"] = body
        received["form"] = parse_qs(body)
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.end_headers()
        self.wfile.write(STS_XML.encode())

    def log_message(self, *args):
        pass  # quiet


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main():
    if not DUCKDB.exists():
        fail(f"{DUCKDB} not found — run `make` first")

    server = http.server.HTTPServer(("127.0.0.1", 0), STSHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    sts_url = f"http://127.0.0.1:{port}/"

    sql = f"""
INSTALL httpfs; LOAD httpfs;
CREATE SECRET mock_sso (
    TYPE s3, PROVIDER sso,
    token 'header.payload.signature',
    sts_endpoint '{sts_url}',
    role_arn 'arn:aws:iam::000000000000:role/duck',
    region 'us-east-1', endpoint '127.0.0.1:9000', url_style 'path'
);
SELECT name, type, provider, secret_string FROM duckdb_secrets() WHERE name='mock_sso';
"""
    out = subprocess.run(
        [str(DUCKDB), "-noheader", "-list"],
        input=sql,
        capture_output=True,
        text=True,
        timeout=60,
    )
    server.shutdown()

    combined = out.stdout + out.stderr
    if out.returncode != 0:
        fail(f"duckdb exited {out.returncode}\n{combined}")

    # 1. blobsso sent a well-formed STS request
    form = received.get("form", {})
    if form.get("Action") != ["AssumeRoleWithWebIdentity"]:
        fail(f"STS Action wrong/absent. body={received.get('body')!r}")
    if form.get("WebIdentityToken") != ["header.payload.signature"]:
        fail(f"WebIdentityToken not forwarded. form={form}")

    # 2. parsed creds landed in the secret
    if "sso" not in out.stdout or "s3" not in out.stdout:
        fail(f"secret not created as s3/sso:\n{out.stdout}")
    if CREDS["AccessKeyId"] not in out.stdout:
        fail(f"AccessKeyId from STS not in secret:\n{out.stdout}")
    if "redacted" not in out.stdout.lower():
        fail(f"expected redacted secret/session_token marker:\n{out.stdout}")
    # The secret value must NOT leak in the (redacted) listing.
    if CREDS["SecretAccessKey"] in out.stdout:
        fail("SecretAccessKey leaked unredacted in duckdb_secrets()")

    print("PASS: blobsso sso provider — STS round-trip via mock server")
    print(f"  Action + WebIdentityToken forwarded; AccessKeyId {CREDS['AccessKeyId']} in secret; secret redacted")


if __name__ == "__main__":
    main()
