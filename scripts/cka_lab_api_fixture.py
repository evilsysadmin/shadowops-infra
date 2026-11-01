"""Synthetic TLS Identity authority for disposable CI; never a deployable IdP.

The real published controller remains unchanged. Only its test CA bundle, DNS
and operator configuration select this isolated authority in the disposable job.
No live password, cookie, token, service credential or signing key is used.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID


HOST = "id-staging.shadowops.dpdns.org"
ISSUER = "https://" + HOST
ORIGIN = "https://staging.cka.shadowops.dpdns.org"
OWNER = "11111111-1111-4111-8111-111111111111"
FOREIGN = "22222222-2222-4222-8222-222222222222"
SOC = "soc1_" + "A" * 43  # canonical synthetic zero bytes, never a real secret
KID = "cka-ci-authority"


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def private_write(path, value):
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(value)


def generate(directory, build):
    if len(build) != 40 or any(c not in "0123456789abcdef" for c in build):
        raise ValueError("Immutable fixture source required")
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable CKA API CI CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    tls_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .issuer_name(ca_name).public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    signing = ed25519.Ed25519PrivateKey.generate()
    jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                       "kid": KID, "x": b64(signing.public_key().public_bytes(
                           serialization.Encoding.Raw, serialization.PublicFormat.Raw))}]}
    private_write(directory / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    private_write(directory / "tls.pem", leaf.public_bytes(serialization.Encoding.PEM))
    for name, key in [("tls.key", tls_key), ("token.key", signing)]:
        private_write(directory / name, key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private_write(directory / "lab.json", json.dumps({"environment": "staging", "jwks": jwks,
        "service_credential": SOC, "pilot_subject": OWNER, "build": build}).encode())


class Authority:
    def __init__(self, directory):
        self.key = serialization.load_pem_private_key((directory / "token.key").read_bytes(), password=None)
        self.lock = threading.Lock()
        self.registry = {}
        self.revoked = False
        self.checks = 0

    def token(self, case="owner"):
        if case not in {"owner", "foreign", "wrong-audience"}:
            raise ValueError("Unknown synthetic browser")
        with self.lock:
            if self.revoked:
                raise ValueError("Synthetic session revoked")
            now, jti = int(time.time()), b64(secrets.token_bytes(16))
            claims = {"iss": ISSUER, "aud": "chronicles" if case == "wrong-audience" else "cka-simulator",
                      "sub": FOREIGN if case == "foreign" else OWNER, "sv": 1,
                      "iat": now, "nbf": now, "exp": now + 120, "jti": jti}
            self.registry[jti] = claims
            for key in list(self.registry):
                if self.registry[key]["exp"] <= now:
                    del self.registry[key]
            head = b64(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": KID}, separators=(",", ":")).encode())
            payload = b64(json.dumps(claims, separators=(",", ":")).encode())
            raw = (head + "." + payload).encode()
            return raw.decode() + "." + b64(self.key.sign(raw))

    def freshness(self, data):
        with self.lock:
            self.checks += 1
            if self.revoked or set(data) != {"subject", "session_version", "token_jti"}:
                raise ValueError("Synthetic authority denied")
            claims = self.registry.get(data["token_jti"])
            if (not claims or claims["exp"] <= int(time.time()) or claims["sub"] != data["subject"]
                    or type(data["session_version"]) is not int or data["session_version"] != claims["sv"]
                    or claims["aud"] != "cka-simulator"):
                raise ValueError("Synthetic authority denied")
            return {"issuer": ISSUER, "audience": "cka-simulator", "subject": claims["sub"],
                    "session_version": 1, "token_jti": claims["jti"], "checked_at": int(time.time()),
                    "account_active": True, "session_active": True, "token_active": True}


def serve(directory):
    state = Authority(directory)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def answer(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 2048 or self.headers.get("Host") != HOST:
                    raise ValueError()
                data = json.loads(self.rfile.read(length))
                if self.path == "/api/identity/token":
                    if self.headers.get("Origin") != ORIGIN or data != {}:
                        raise ValueError()
                    cookie = self.headers.get("Cookie", "")
                    if not cookie.startswith("ci-browser="):
                        raise ValueError()
                    return self.answer(200, {"token": state.token(cookie.removeprefix("ci-browser="))})
                if self.path == "/api/identity/freshness":
                    if (self.headers.get("Authorization") != "Bearer " + SOC
                            or self.headers.get("Origin") is not None or self.headers.get("Cookie") is not None):
                        raise ValueError()
                    return self.answer(200, state.freshness(data))
                if self.path in {"/fixture/revoke", "/fixture/restore"} and data == {}:
                    with state.lock:
                        state.revoked = self.path == "/fixture/revoke"
                    return self.answer(200, {"status": "ok"})
                if self.path == "/fixture/status" and data == {}:
                    with state.lock:
                        result = {"revoked": state.revoked, "freshness_checks": state.checks}
                    return self.answer(200, result)
                self.answer(404, {})
            except (ValueError, TypeError, KeyError):
                self.answer(401, {"detail": "Synthetic authority denied"})

    server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory / "tls.pem", directory / "tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    if os.environ.get("CKA_DISPOSABLE_CI") != "true":
        raise SystemExit("Disposable CI only")
    directory = Path("/fixture")
    if len(sys.argv) == 3 and sys.argv[1] == "generate":
        generate(directory, sys.argv[2])
        print("CKA_LAB_SYNTHETIC_AUTHORITY_CREATED")
    elif sys.argv[1:] == ["serve"]:
        serve(directory)
    else:
        raise SystemExit("Fixed synthetic fixture operation required")
