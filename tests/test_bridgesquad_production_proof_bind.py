"""Production Bridge Squad proof binding: deny-by-default, mock-only tests."""
import copy
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bridgesquad_production_proof_bind as bind
import bridgesquad_dns_quarantine as q
import bridgesquad_alias_watchdog as watchdog
import test_bridgesquad_dns_quarantine as fixture

SHA = fixture.SHA
KEY = bind.KEY


def audit(client, *, allow_bound=False):
    with mock.patch.object(q.socket, "getaddrinfo", return_value=[("ip",)]):
        return q.audit(client, guest=fixture.guest, web=fixture.web,
                       allow_bound=allow_bound)


def production_public():
    return {"service": "present", "jwks": "present",
            "login": "present", "public_surface": "present",
            "service_proof": "not-verified", "token_issuance": "not-verified"}


class Client(fixture.FakeClient):
    def __init__(self):
        super().__init__()
        self.secret_writes = []

    def patch_proof(self, proof, flags):
        self.secret_writes.append((proof, flags))
        self.project["deployment_configs"]["production"]["env_vars"] = {
            KEY: {"type": "secret_text", "value": "REDACTED"}
        }


class BindingTests(unittest.TestCase):
    def ready(self):
        client = Client()
        q.attach(client, guest=fixture.guest)
        return client

    def test_binding_is_production_only_and_guest_stays_denied(self):
        c = self.ready()
        result = bind.bind_once(c, SHA, "soc1_" + "Z" * 43,
                                audit=audit, public=production_public)
        self.assertEqual(result["proof"], "encrypted-production-only")
        self.assertEqual(result["authenticated"], "NOT_VERIFIED")
        self.assertEqual(len(c.secret_writes), 1)
        self.assertEqual(c.project["deployment_configs"]["preview"]["env_vars"], {})
        self.assertEqual(audit(c, allow_bound=True)["production_identity"],
                         "proof-bound-unverified")
        with mock.patch.object(q, "https_probe", side_effect=fixture.web):
            with mock.patch.object(q.socket, "getaddrinfo", return_value=[("ip",)]):
                result = watchdog.audit(c, probe=fixture.guest)
        self.assertEqual(result["assets"], "denied")
        self.assertEqual(result["aliases"], "2")
        # The DNS attach workflow must NOT become a way to bind or overwrite secrets.
        with self.assertRaises(q.QuarantineError):
            q.attach(c, guest=fixture.guest)

    def test_quarantine_requires_no_secret_and_preview_stays_empty(self):
        c = self.ready()
        c.project["deployment_configs"]["production"]["env_vars"] = {
            KEY: {"type": "secret_text", "value": "hidden"}}
        with self.assertRaises(q.QuarantineError):
            q.project(c)
        q.project(c, allow_bound=True)
        for invalid in (
            {KEY: {"type": "plain_text", "value": "danger"}},
            {"unexpected": {"type": "secret_text", "value": "hidden"}},
            {KEY: {"type": "secret_text"}, "other": {"type": "secret_text"}},
        ):
            c.project["deployment_configs"]["production"]["env_vars"] = copy.deepcopy(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(q.QuarantineError):
                q.project(c, allow_bound=True)
        c.project["deployment_configs"]["production"]["env_vars"] = {}
        c.project["deployment_configs"]["preview"]["env_vars"] = {
            KEY: {"type": "secret_text"}}
        with self.assertRaises(q.QuarantineError):
            q.project(c, allow_bound=True)

    def test_no_write_without_real_dns_correct_release_and_public_id(self):
        for override in (
            {"sha": "b" * 40},
            {"public": {"public_surface": "not-ready"}},
            {"audit": lambda client: {"https": "401-login-shell", "assets": "denied"}},
        ):
            with self.subTest(override=override):
                c = self.ready()
                with self.assertRaises(bind.Refused):
                    bind.bind_once(c, override.get("sha", SHA), "soc1_" + "Z" * 43,
                        audit=override.get("audit", audit),
                        public=lambda: override.get("public", production_public()))
                self.assertEqual(c.secret_writes, [])

    def test_postflight_rejects_secret_without_encrypted_type_or_host_401(self):
        c = self.ready()
        c.project["deployment_configs"]["production"]["env_vars"] = {
            KEY: {"type": "plain_text", "value": "leak"}}
        with self.assertRaises(q.QuarantineError):
            bind.postflight(c, SHA, audit=audit, public=production_public)
        c.project["deployment_configs"]["production"]["env_vars"] = {
            KEY: {"type": "secret_text"}}
        with self.assertRaises(bind.Refused):
            bind.postflight(c, SHA,
                            audit=lambda client, **kwargs: {"source_sha": SHA, "https": "200",
                                "production_identity": "proof-bound-unverified", "assets": "denied"},
                            public=production_public)

    def test_cloudflare_patch_is_only_encrypted_production_update(self):
        client = bind.CloudflareClient.__new__(bind.CloudflareClient)
        client.account = "b" * 32
        client._token = "unused-test-token"
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = json.dumps({
            "success": True, "result": {"name": "bridgesquad-production"}
        }).encode()
        response.__enter__.return_value = response
        with mock.patch.object(bind.urllib.request, "urlopen", return_value=response) as opened:
            client.patch_proof("soc1_" + "X" * 43, ["global_fetch_strictly_public"])
        req = opened.call_args.args[0]
        self.assertEqual(req.method, "PATCH")
        self.assertEqual(req.full_url,
            "https://api.cloudflare.com/client/v4/accounts/" + client.account +
            "/pages/projects/bridgesquad-production")
        document = json.loads(req.data)
        self.assertEqual(set(document), {"deployment_configs"})
        self.assertEqual(set(document["deployment_configs"]), {"production"})
        prod = document["deployment_configs"]["production"]
        self.assertEqual(prod["fail_open"], False)
        self.assertEqual(prod["env_vars"][KEY]["type"], "secret_text")
        self.assertNotIn("preview", document["deployment_configs"])
        with self.assertRaises(bind.Refused):
            client.patch_proof("invalid-secret", ["global_fetch_strictly_public"])
        with self.assertRaises(bind.Refused):
            client.patch_proof("soc1_" + "X" * 43,
                               ["global_fetch_private_origin"])

    def test_ci_and_missing_private_proof_cannot_activate(self):
        self.assertEqual(bind.main(["plan"]), 0)
        with mock.patch.dict(bind.os.environ, {
            "CI": "true", "CLOUDFLARE_ACCOUNT_ID": "b" * 32,
            "CLOUDFLARE_API_TOKEN": "fixture",
        }):
            self.assertEqual(bind.main(["bind", SHA]), 1)
        for path in ("", "relative/path", "/", "/nonexistent/secret"):
            with self.subTest(path=path), self.assertRaises(bind.Refused):
                bind.read_private_proof(path)


if __name__ == "__main__":
    unittest.main()
