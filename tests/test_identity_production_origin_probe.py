"""Loopback TLS origin admission: real x509/SNI, HTTP, strict JWKS and deny paths."""
from __future__ import annotations

import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import identity_production_origin_probe as origin
import bridgesquad_prod_identity_probe as public

KEY = base64.urlsafe_b64encode(b"\x13" * 32).decode().rstrip("=")
JWKS = json.dumps({"keys": [{
    "kty": "OKP", "crv": "Ed25519", "use": "sig",
    "alg": "EdDSA", "kid": "synthetic-production", "x": KEY,
}]}).encode()
BACK = public.ORIGIN + "/?shadowops=central"
LOGIN = (f'<html><body data-return-url="{BACK}"><h1>Bridge Squad</h1>'
         f'<a class="brand" href="{BACK}">SHADOWOPS</a>'
         f'<a class="return-link" href="{BACK}">Volver a Bridge Squad</a>'
         f'</body></html>').encode()
CSP = "default-src 'none'; form-action 'self'; frame-ancestors 'none'"


def make_certificate(folder: Path, *, host: str = origin.HOST, stem: str = "prod"):
    ca = folder / "synthetic-ca.pem"
    ca_key = folder / "synthetic-ca.key"
    if not ca.exists():
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "2", "-keyout", str(ca_key), "-out", str(ca),
            "-subj", "/CN=ShadowOps-local-CI-test-CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key, csr, crt = (folder / f"{stem}.{part}" for part in ("key", "csr", "crt"))
    ext = folder / f"{stem}.ext"
    ext.write_text("subjectAltName=DNS:" + host + "\nextendedKeyUsage=serverAuth\n")
    subprocess.run([
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(csr),
        "-subj", "/CN=" + host,
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
        "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(crt), "-days", "2", "-extfile", str(ext),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return ca, crt, key


class IdentityHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parent = self.server
        code, content_type, body = {
            "/livez": (200, "text/plain", b"production identity service alive\n"),
            "/readyz": (200, "text/plain", b"production identity ready\n"),
            "/api/identity/jwks": (200, "application/json", JWKS),
            "/login?app=bridgesquad": (200, "text/html; charset=utf-8", LOGIN),
            "/login?app=football": (400, "text/plain", b"Bad Request"),
            "/api/identity/register": (503, "text/plain", b"Service Unavailable"),
            "/readyz?unexpected=1": (405, "text/plain", b"Method Not Allowed"),
        }.get(self.path, (404, "text/plain", b"Not Found"))
        if self.headers.get("Host") != origin.HOST:
            code = 403
        code = parent.statuses.get(self.path, code)
        body = parent.bodies.get(self.path, body)
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        if not parent.omit_cache:
            self.send_header("Cache-Control", "no-store")
        if not parent.omit_hsts:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.path == "/login?app=bridgesquad":
            self.send_header("Content-Security-Policy", CSP)
        if parent.set_cookie:
            self.send_header("Set-Cookie", "synthetic=must-be-rejected")
        if parent.location:
            self.send_header("Location", "https://id-staging.shadowops.dpdns.org")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class TLSServer:
    def __init__(self, cert: Path, key: Path):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), IdentityHandler)
        self.srv.statuses = {}
        self.srv.bodies = {}
        self.srv.omit_cache = False
        self.srv.omit_hsts = False
        self.srv.set_cookie = False
        self.srv.location = False
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.load_cert_chain(str(cert), str(key))
        self.srv.socket = ssl_context.wrap_socket(self.srv.socket, server_side=True)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=5)

    @property
    def port(self):
        return self.srv.server_port


class ProductionOriginProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="identity-origin-tls-ci-")
        cls.folder = Path(cls.temp.name)
        cls.ca, cls.crt, cls.key = make_certificate(cls.folder)
        _, cls.bad_crt, cls.bad_key = make_certificate(
            cls.folder, host="id-staging.shadowops.dpdns.org", stem="wronghost")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_tls_production_sni_jwks_login_and_denied_paths(self):
        with TLSServer(self.crt, self.key) as server:
            receipt = origin.inspect(self.ca, port=server.port)
            self.assertEqual(receipt["tls"], "verified")
            self.assertEqual(receipt["sni"], "production-host")
            self.assertEqual(receipt["ready"], "yes")
            self.assertEqual(receipt["foreign_host"], "denied")
            self.assertEqual(receipt["registration"], "disabled")
            self.assertEqual(receipt["authorization"], "not-verified")
            self.assertEqual(receipt["deployment"], "none")
            # All traffic goes to localhost. TLS and HTTP Host remain distinct.
            status, _, _ = origin.read_origin(origin.tls_context(self.ca),
                                              "/readyz", port=server.port)
            self.assertEqual(status, 200)
            with self.assertRaises(origin.Refused):
                origin.read_origin(origin.tls_context(self.ca),
                                   "https://evil.example", port=server.port)

    def test_real_tls_refuses_staging_hostname_and_wrong_ca(self):
        with TLSServer(self.bad_crt, self.bad_key) as server:
            with self.assertRaises(ssl.SSLCertVerificationError):
                origin.inspect(self.ca, port=server.port)
        other = self.folder / "untrusted-ca.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "2", "-keyout", str(self.folder / "untrusted-ca.key"),
            "-out", str(other), "-subj", "/CN=unrelated-test-trust-root",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with TLSServer(self.crt, self.key) as server:
            with self.assertRaises(ssl.SSLCertVerificationError):
                origin.inspect(other, port=server.port)

    def test_tls_required_no_plaintext_acceptance(self):
        class PlainServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
        class PlainHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                try:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass
        with PlainServer(("127.0.0.1", 0), PlainHandler) as srv:
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaises((ssl.SSLError, OSError)):
                    origin.inspect(self.ca, port=srv.server_address[1])
            finally:
                srv.shutdown()
                thread.join(timeout=5)

    def test_readyz_jwks_login_and_security_headers_fail_closed(self):
        for bad in ("notready", "missing_hsts", "missing_cache", "cookie",
                    "redirect", "broken_jwks", "second_key", "foreign_login", "registration_enabled"):
            with self.subTest(failure=bad), TLSServer(self.crt, self.key) as server:
                cfg = server.srv
                if bad == "notready":
                    cfg.statuses["/readyz"] = 503
                elif bad == "missing_hsts":
                    cfg.omit_hsts = True
                elif bad == "missing_cache":
                    cfg.omit_cache = True
                elif bad == "cookie":
                    cfg.set_cookie = True
                elif bad == "redirect":
                    cfg.location = True
                elif bad == "broken_jwks":
                    cfg.bodies["/api/identity/jwks"] = json.dumps({
                        "keys": [{**json.loads(JWKS)["keys"][0], "alg": "RS256"}]
                    }).encode()
                elif bad == "second_key":
                    cfg.bodies["/api/identity/jwks"] = json.dumps({
                        "keys": [json.loads(JWKS)["keys"][0]] * 2
                    }).encode()
                elif bad == "foreign_login":
                    cfg.bodies["/login?app=bridgesquad"] = LOGIN.replace(
                        public.ORIGIN.encode(), b"https://id-staging.shadowops.dpdns.org")
                elif bad == "registration_enabled":
                    cfg.statuses["/api/identity/register"] = 200
                with self.assertRaises((origin.Refused, public.UnsafeIssuer)):
                    origin.inspect(self.ca, port=server.port)

    def test_local_ca_preflight_denies_relative_symlink_and_writable(self):
        self.assertEqual(origin.ca_file(str(self.ca)), self.ca)
        with self.assertRaises(origin.Refused):
            origin.ca_file("relative-ca.pem")
        link = self.folder / "ca-link.pem"
        link.symlink_to(self.ca)
        with self.assertRaises(origin.Refused):
            origin.ca_file(str(link))
        backup = self.ca.stat().st_mode
        try:
            self.ca.chmod(0o666)
            with self.assertRaises(origin.Refused):
                origin.ca_file(str(self.ca))
        finally:
            self.ca.chmod(backup)
        self.assertEqual(origin.main([]), 2)
        self.assertEqual(origin.main(["inspect"]), 1)  # No real operator CA in CI

if __name__ == "__main__":
    unittest.main()
