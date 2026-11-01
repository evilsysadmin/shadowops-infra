"""Independently verify the synthetic authority used by the published-image test."""
import base64
import json
from pathlib import Path
import sys
import ssl
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cka_lab_api_fixture import Authority, HOST, ISSUER, OWNER, generate


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SyntheticAuthority(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cka-api-authority-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        generate(self.root, "a" * 40)
        self.authority = Authority(self.root)
        self.config = json.loads((self.root / "lab.json").read_bytes())

    def token(self, case="owner"):
        token = self.authority.token(case)
        header, payload, signature = token.split(".")
        key = Ed25519PublicKey.from_public_bytes(decode(self.config["jwks"]["keys"][0]["x"]))
        key.verify(decode(signature), (header + "." + payload).encode())
        return json.loads(decode(payload))

    def check(self, claims, **changes):
        return self.authority.freshness({"subject": claims["sub"], "session_version": claims["sv"],
                                         "token_jti": claims["jti"], **changes})

    def test_real_signatures_fixed_issuer_and_independent_expiring_jtis(self):
        first, second = self.token(), self.token()
        self.assertEqual(first["iss"], ISSUER)
        self.assertEqual(first["aud"], "cka-simulator")
        self.assertEqual(first["sub"], OWNER)
        self.assertEqual(first["exp"] - first["iat"], 120)
        self.assertEqual(first["nbf"], first["iat"])
        self.assertNotEqual(first["jti"], second["jti"])
        self.assertEqual(self.check(first)["token_jti"], first["jti"])

    def test_exact_registry_relationship_and_revocation_are_required(self):
        claims = self.token()
        for changes in [{"subject": "foreign"}, {"session_version": True},
                        {"session_version": 2}, {"token_jti": "unregistered"}, {"extra": "claim"}]:
            with self.assertRaises(ValueError):
                self.check(claims, **changes)
        self.authority.revoked = True
        with self.assertRaises(ValueError):
            self.check(claims)
        self.assertEqual(self.authority.checks, 6)
        with self.assertRaises(ValueError):
            self.authority.token()

    def test_tls_hostname_and_private_material_do_not_become_browser_configuration(self):
        leaf = x509.load_pem_x509_certificate((self.root / "tls.pem").read_bytes())
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(names.get_values_for_type(x509.DNSName), [HOST])
        self.assertEqual(set(self.config), {"environment", "jwks", "service_credential", "pilot_subject", "build"})
        for path in self.root.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_actual_strict_tls_handshake_and_wrong_hostname_without_opening_a_socket(self):
        def handshake(hostname):
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(self.root / "tls.pem", self.root / "tls.key")
            client_context = ssl.create_default_context(cafile=str(self.root / "ca.pem"))
            client_context.verify_flags |= ssl.VERIFY_X509_STRICT
            incoming_client, outgoing_client = ssl.MemoryBIO(), ssl.MemoryBIO()
            incoming_server, outgoing_server = ssl.MemoryBIO(), ssl.MemoryBIO()
            client = client_context.wrap_bio(incoming_client, outgoing_client, server_hostname=hostname)
            server = server_context.wrap_bio(incoming_server, outgoing_server, server_side=True)
            for _ in range(20):
                complete = 0
                for connection in (client, server):
                    try:
                        connection.do_handshake()
                        complete += 1
                    except ssl.SSLWantReadError:
                        pass
                for outgoing, incoming in [(outgoing_client, incoming_server), (outgoing_server, incoming_client)]:
                    if outgoing.pending:
                        incoming.write(outgoing.read())
                if complete == 2:
                    return
            self.fail("Strict TLS handshake did not complete")
        handshake(HOST)
        with self.assertRaises(ssl.SSLCertVerificationError):
            handshake("wrong-identity.invalid")


if __name__ == "__main__":
    unittest.main()
