"""Read-only Star Adventures ShadowOps ID cutover checks: no secrets, no writes."""
from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_identity_readiness as r

ALIAS = "staradvs-staging.pages.dev"
RETURN = b'<html><a href="https://staging.staradvs.shadowops.dpdns.org/?shadowops=central">Star Adventures</a></html>'


def project():
    conf = lambda: {"fail_open": False,
                    "compatibility_flags": ["global_fetch_strictly_public"],
                    "env_vars": {}}
    return {
        "name": "staradvs-staging", "production_branch": "main",
        "subdomain": ALIAS, "domains": [ALIAS, r.pages.HOST],
        "deployment_configs": {"production": conf(), "preview": conf()},
        "canonical_deployment": {"url": "https://abc123." + ALIAS},
        "latest_deployment": {"url": "https://abc123." + ALIAS},
    }


def ready_project():
    obj = project()
    obj["deployment_configs"]["production"]["env_vars"] = {
        r.BINDING: {"type": "secret_text", "value": "MUST_NOT_PRINT"}
    }
    return obj


class Client:
    account = "f" * 32

    def __init__(self, instance=None, missing=False):
        self.instance = instance if instance is not None else project()
        self.missing = missing
        self.calls = []

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if method != "GET" or data is not None:
            raise AssertionError("Cutover inventory must never mutate Cloudflare")
        if path.startswith("/zones?"):
            return 200, [{"name": r.pages.ZONE, "id": "z" * 32}]
        if "/dns_records?" in path:
            return 200, [{"name": r.pages.HOST, "type": "CNAME",
                          "content": r.pages.TARGET, "proxied": True}]
        if path.endswith("/pages/projects/" + r.pages.PROJECT):
            return (404, None) if self.missing else (200, copy.deepcopy(self.instance))
        if path.endswith("/domains/" + r.pages.HOST):
            return (404, None) if self.missing else (
                200, {"name": r.pages.HOST, "status": "active"})
        raise AssertionError("Unexpected Cloudflare path: " + path)


def public(url, method):
    if url == r.ISSUER + "/login?app=staradvs":
        return 200, RETURN
    if url.startswith("https://staging.staradvs.shadowops.dpdns.org/"):
        return 401, b""
    if url.endswith(".pages.dev/") or ".pages.dev/" in url:
        return 404, b""
    raise AssertionError("Unexpected public URL " + url)


class CutoverReadinessTests(unittest.TestCase):
    def test_fully_prepared_environment_only_admits_future_signed_in_e2e(self):
        cf = Client(ready_project())
        result = r.collect(cf, public)
        self.assertTrue(result["next_gate_ready"])
        self.assertIs(result["can_activate"], False)
        self.assertEqual(result["signed_in_e2e"], "not-performed")
        self.assertEqual(result["pages_app_proof"], "bound")
        self.assertEqual(result["identity_login"], "audience-recognized")
        self.assertEqual(result["pages_alias_guest"], "denied-404")
        self.assertNotIn("MUST_NOT_PRINT", json.dumps(result))
        self.assertTrue(all(method == "GET" and data is None for method, _, data in cf.calls))

    def test_current_static_public_200_is_an_exposure_not_a_green_signin(self):
        cf = Client(ready_project())
        def static_probe(url, method):
            if url.startswith(r.ISSUER):
                return 200, RETURN
            if ".pages.dev" in url or url.startswith("https://" + r.pages.HOST):
                return 200, b"game"
            return 0, b""
        state = r.collect(cf, static_probe)
        self.assertFalse(state["next_gate_ready"])
        self.assertEqual(state["canonical_guest"], "anonymous-content-observed")
        self.assertEqual(state["pages_alias_guest"], "anonymous-content-observed")

    def test_missing_proof_policy_or_login_never_approves_cutover(self):
        variations = [
            (project(), public, "pages_app_proof"),
            (ready_project(), lambda url, method: (400, b"") if url.startswith(r.ISSUER) else public(url, method), "identity_login"),
        ]
        for obj, probe, key in variations:
            with self.subTest(key=key):
                state = r.collect(Client(obj), probe)
                self.assertFalse(state["next_gate_ready"])
                self.assertNotIn(state[key], ("bound", "audience-recognized"))
        self.assertFalse(r.collect(Client(ready_project(), missing=True), public)["next_gate_ready"])

    def test_reject_foreign_or_untrusted_deployment_aliases(self):
        for url in ("https://not-staradvs.pages.dev",
                    "http://abc123.staradvs-staging.pages.dev",
                    "https://abc123.staradvs-staging.pages.dev.evil.test",
                    "https://abc123.staradvs-staging.pages.dev/?x=1",
                    "https://abc123.staradvs-staging.pages.dev:8443/"):
            with self.subTest(url=url):
                p = ready_project()
                p["latest_deployment"]["url"] = url
                with self.assertRaises(r.CutoverBlocked):
                    r.alias_hosts(p)
        p = ready_project()
        p["domains"].append("foreign.example")
        with self.assertRaises(r.CutoverBlocked):
            r.pages_posture(p)

    def test_any_missing_security_property_is_not_ready(self):
        for change in ("fail-open", "compat", "proof-type", "other-binding"):
            with self.subTest(change=change):
                p = ready_project()
                prod = p["deployment_configs"]["production"]
                if change == "fail-open":
                    prod["fail_open"] = True
                elif change == "compat":
                    p["deployment_configs"]["preview"]["compatibility_flags"] = []
                elif change == "proof-type":
                    prod["env_vars"][r.BINDING]["type"] = "plain_text"
                else:
                    prod["env_vars"]["FOREIGN_SECRET"] = {"type": "secret_text"}
                state = r.collect(Client(p), public)
                self.assertFalse(state["next_gate_ready"])

    def test_workflow_is_read_only_never_admits_a_cloud_write(self):
        path = ROOT / ".github/workflows/staradvs-identity-readiness.yml"
        flow = path.read_text()
        self.assertIn("staradvs_identity_readiness.py inspect", flow)
        self.assertIn("github.event_name == 'push'", flow)
        self.assertIn("github.ref == 'refs/heads/main'", flow)
        self.assertIn("environment:", flow)
        self.assertIn("test_staradvs_identity_readiness.py", flow)
        self.assertNotIn("pages deploy", flow)
        self.assertNotIn("wrangler", flow)
        self.assertNotIn("secrets.SOC", flow)
        self.assertNotIn("provision", flow.lower())


if __name__ == "__main__":
    unittest.main()
