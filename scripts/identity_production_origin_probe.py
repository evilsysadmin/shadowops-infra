#!/usr/bin/env python3
"""Operator-only, read-only live TLS origin check for production Identity.

The ONLY network destination is 127.0.0.1:19443. The TLS handshake uses
id.shadowops.dpdns.org as SNI/verified hostname and a private operator-provided
CA. No DNS, Cloudflare API, credentials, POSTs or redirects are attempted.
Successful local health/JWKS/login is not a signed-in consumer E2E.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import sys

import bridgesquad_prod_identity_probe as public_probe

HOST = "id.shadowops.dpdns.org"
PORT = 19443
DESTINATION = "127.0.0.1"
MAX_RESPONSE = public_probe.MAX_RESPONSE
PATHS = ("/livez",) + public_probe.ROUTES + (
    "/login?app=football",
    "/api/identity/register",
    "/readyz?unexpected=1",
)
CA_ENV = "IDENTITY_PRODUCTION_ORIGIN_CA_FILE"


class Refused(ValueError):
    pass


def ca_file(filename: str) -> Path:
    if not filename or "\x00" in filename:
        raise Refused("origin CA path required")
    path = Path(filename)
    if not path.is_absolute() or path == Path("/"):
        raise Refused("origin CA must be an absolute file")
    try:
        for part in (path, *path.parents):
            if stat.S_ISLNK(os.lstat(part).st_mode):
                raise Refused("origin CA path contains a symlink")
        info = os.lstat(path)
    except OSError as exc:
        raise Refused("origin CA unavailable") from exc
    if (not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= 131072 or
            info.st_uid not in (0, os.geteuid()) or
            stat.S_IMODE(info.st_mode) & 0o022):
        raise Refused("origin CA owner or permissions unsafe")
    return path


class LoopbackTLS(http.client.HTTPSConnection):
    def __init__(self, context: ssl.SSLContext, *, port: int = PORT):
        if not 1 <= port <= 65535:
            raise Refused("invalid test port")
        super().__init__(HOST, port, timeout=4, context=context)

    def connect(self):
        # Deliberately bypasses DNS and HTTPS_PROXY; public host is SNI only.
        raw = socket.create_connection((DESTINATION, self.port), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except BaseException:
            raw.close()
            raise


def tls_context(ca: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def read_origin(context: ssl.SSLContext, path: str, *,
                port: int = PORT, host: str = HOST) -> tuple[int, dict, bytes]:
    if path not in PATHS or host not in (HOST, "id-staging.shadowops.dpdns.org"):
        raise Refused("non-admitted origin request")
    conn = LoopbackTLS(context, port=port)
    try:
        conn.request("GET", path, headers={
            "Host": host,
            "Accept": "application/json, text/html",
            "User-Agent": "ShadowOps-Identity-Local-Origin-Readiness/1.0",
            "Connection": "close",
        })
        res = conn.getresponse()
        items = res.getheaders()
        if len(items) > 48:
            raise Refused("too many origin headers")
        names = [k.lower() for k, _ in items]
        if any(names.count(key) > 1 for key in
               ("content-type", "cache-control", "strict-transport-security",
                "x-content-type-options", "set-cookie", "location")):
            raise Refused("ambiguous HTTP headers")
        headers = {k.lower(): v for k, v in items}
        body = res.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE or res.status < 100 or res.status > 599:
            raise Refused("oversized or invalid response")
        if (headers.get("cache-control") != "no-store" or
                headers.get("x-content-type-options") != "nosniff" or
                headers.get("strict-transport-security") != "max-age=31536000" or
                "set-cookie" in headers or "location" in headers):
            raise Refused("origin leaked session or omitted security headers")
        return res.status, headers, body
    finally:
        conn.close()


def audit_jwks(body: bytes) -> None:
    try:
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict) or len(data.get("keys", [])) != 1:
            raise Refused("production origin must publish one Ed25519 key")
        key = data["keys"][0]
        if key.get("alg") != "EdDSA":
            raise Refused("production signature algorithm changed")
        raw = base64.urlsafe_b64decode(key["x"] + "===")
        if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != key["x"]:
            raise Refused("invalid canonical production public key")
    except (ValueError, KeyError, TypeError, UnicodeError, base64.binascii.Error) as exc:
        raise Refused("invalid production JWK") from exc


def inspect(ca: Path, *, port: int = PORT) -> dict[str, str]:
    context = tls_context(ca)

    def reader(url: str):
        if not url.startswith(public_probe.ISSUER):
            raise Refused("foreign identity issuer")
        path = url[len(public_probe.ISSUER):]
        return read_origin(context, path, port=port)

    # Reuse the existing strict JWKS, HTML return URL and CSP inspection.
    receipt = public_probe.inspect(reader=reader)
    if receipt["public_surface"] != "present":
        raise Refused("production origin is not ready")
    for path, expected in (
        ("/livez", 200),
        ("/login?app=football", 400),
        ("/api/identity/register", 503),
        ("/readyz?unexpected=1", 405),
    ):
        status, _, _ = read_origin(context, path, port=port)
        if status != expected:
            raise Refused("production origin method or forbidden route mismatch")
    status, _, _ = read_origin(
        context, "/readyz", port=port, host="id-staging.shadowops.dpdns.org")
    if status != 403:
        raise Refused("production origin accepted foreign Host")
    _, _, jwks_body = read_origin(context, "/api/identity/jwks", port=port)
    audit_jwks(jwks_body)
    return {
        "tls": "verified",
        "sni": "production-host",
        "ready": "yes",
        "jwks": "ed25519-public",
        "login": "bridgesquad-only",
        "foreign_host": "denied",
        "registration": "disabled",
        "authorization": "not-verified",
        "deployment": "none",
    }


def main(argv: list[str]) -> int:
    if argv != ["inspect"]:
        print("Usage: identity_production_origin_probe.py inspect", file=sys.stderr)
        return 2
    try:
        result = inspect(ca_file(os.environ.get(CA_ENV, "")))
    except (Refused, public_probe.UnsafeIssuer, OSError, ssl.SSLError,
            http.client.HTTPException, TimeoutError, ValueError):
        # Never include local URL, secret material, provider errors or certs.
        print("IDENTITY_PRODUCTION_ORIGIN_REFUSED", file=sys.stderr)
        return 1
    print("IDENTITY_PRODUCTION_ORIGIN_OK " +
          " ".join(f"{key}={value}" for key, value in result.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
