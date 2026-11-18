import copy
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bridgesquad_alias_bootstrap as bootstrap
import bridgesquad_pages_readiness as readiness

SHA = "a" * 40
ACCOUNT = "b" * 32
ALIAS = "bridgesquad-production.pages.dev"
PROJECT = f"/accounts/{ACCOUNT}/pages/projects/{readiness.PROJECT}"
INVENTORY = {
    "project": "present", "domain": "absent", "dns": "absent",
    "identity_gate": "not-verified", "deployment": "not-verified",
}


def project(deployed=False):
    value = {
        "name": readiness.PROJECT, "production_branch": "main",
        "source": None, "subdomain": ALIAS, "domains": [],
        "deployment_configs": {
            mode: {"fail_open": False, "compatibility_flags": ["global_fetch_strictly_public"],
                   "env_vars": {}} for mode in ("production", "preview")
        },
        "latest_deployment": None, "canonical_deployment": None,
    }
    if deployed:
        d = {
            "url": "https://abc123." + ALIAS,
            "environment": "production", "is_skipped": False,
            "latest_stage": {"status": "success"},
            "deployment_trigger": {"type": "ad_hoc", "metadata": {
                "branch": "main", "commit_dirty": False, "commit_hash": SHA,
            }},
        }
        value["latest_deployment"] = copy.deepcopy(d)
        value["canonical_deployment"] = copy.deepcopy(d)
    return value


class FakeClient:
    account = ACCOUNT

    def __init__(self, data):
        self.project = data
        self.gets = []

    def get(self, path):
        self.gets.append(path)
        if path == PROJECT:
            return self.project
        raise AssertionError("Unexpected Cloudflare GET: " + path)


class AliasBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.inventory = mock.patch.object(readiness, "inspect", return_value=INVENTORY)
        self.inventory.start()
        self.addCleanup(self.inventory.stop)

    def test_empty_private_project_ready_without_cloudflare_writes(self):
        client = FakeClient(project())
        self.assertEqual(bootstrap.preflight(client), {
            "project": readiness.PROJECT, "alias": ALIAS, "status": "empty-private",
        })
        self.assertEqual(client.gets, [PROJECT])

    def test_unexpected_live_deployment_blocks_one_time_bootstrap(self):
        with self.assertRaises(bootstrap.BootstrapBlocked):
            bootstrap.preflight(FakeClient(project(deployed=True)))

    def test_project_cannot_have_dns_or_domain_or_wrong_ownership(self):
        scenarios = []
        for key, changed in [
            ("source", {"type": "github"}),
            ("production_branch", "unreviewed"),
            ("subdomain", "other.pages.dev"),
            ("domains", ["bridgesquad.shadowops.dpdns.org"]),
        ]:
            p = project()
            p[key] = changed
            scenarios.append(p)
        with mock.patch.object(readiness, "inspect", return_value={
            **INVENTORY, "dns": "present"
        }):
            with self.assertRaises(bootstrap.BootstrapBlocked):
                bootstrap.preflight(FakeClient(project()))
        for value in scenarios:
            with self.subTest(value=value), self.assertRaises(bootstrap.BootstrapBlocked):
                bootstrap.preflight(FakeClient(value))

    def test_fail_open_unsupported_compatibility_or_binding_is_refused(self):
        for mode in ("production", "preview"):
            for change in (
                {"fail_open": True}, {"compatibility_flags": []},
                {"compatibility_flags": ["global_fetch_private_origin"]},
                {"env_vars": {"SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL": {"type": "secret_text"}}},
            ):
                p = project()
                p["deployment_configs"][mode].update(change)
                with self.subTest(mode=mode, change=change), self.assertRaises(
                        bootstrap.BootstrapBlocked):
                    bootstrap.preflight(FakeClient(p))

    def test_deployed_canonical_source_and_all_aliases_deny_every_route(self):
        client = FakeClient(project(deployed=True))
        calls = []
        def deny(url, method):
            calls.append((url, method))
            return 404
        proof = bootstrap.postflight(client, SHA, deny)
        self.assertEqual(proof["aliases"], 2)
        self.assertEqual(proof["anonymous_access"], "denied")
        self.assertEqual(proof["source_sha"], SHA)
        self.assertEqual(len(calls), 2 * (len(bootstrap.PATHS) + 3 + 1))
        self.assertIn(("https://" + ALIAS + "/index.html", "GET"), calls)
        self.assertIn(("https://abc123." + ALIAS + "/index.html", "GET"), calls)
        self.assertIn(("https://" + ALIAS + "/release.json", "HEAD"), calls)
        self.assertIn(("https://abc123." + ALIAS + "/api/bridgesquad/session", "POST"), calls)

    def test_any_public_asset_or_error_status_fails_denial_audit(self):
        for leaked_status in (200, 201, 301, 401, 403, 500, 503):
            i = 0
            def partly_open(url, method):
                nonlocal i
                i += 1
                return leaked_status if i == 1 else 404
            with self.subTest(status=leaked_status), self.assertRaises(
                    bootstrap.BootstrapBlocked):
                bootstrap.postflight(FakeClient(project(deployed=True)), SHA, partly_open)

    def test_canonical_proof_rejects_wrong_branch_sha_and_preview(self):
        for key, value in [
            ("environment", "preview"), ("is_skipped", True),
            ("latest_stage", {"status": "failure"}),
            ("deployment_trigger", {"type": "ad_hoc", "metadata": {
                "branch": "preview", "commit_dirty": False, "commit_hash": SHA,
            }}),
            ("deployment_trigger", {"type": "ad_hoc", "metadata": {
                "branch": "main", "commit_dirty": False, "commit_hash": "c"*40,
            }}),
        ]:
            p = project(deployed=True)
            p["canonical_deployment"][key] = value
            with self.subTest(field=key, value=value), self.assertRaises(
                    bootstrap.BootstrapBlocked):
                bootstrap.postflight(FakeClient(p), SHA, lambda u, m: 404)
        with self.assertRaises(bootstrap.BootstrapBlocked):
            bootstrap.postflight(FakeClient(project()), SHA, lambda u, m: 404)

    def test_external_or_malformed_immutable_url_fails(self):
        for bad in (
            "https://evil.test/",
            "http://abc123." + ALIAS,
            "https://evil.test/abc123." + ALIAS,
            "https://abc123." + ALIAS + "/index.html",
            "https://abc123." + ALIAS + "?token=foo",
        ):
            p = project(deployed=True)
            p["latest_deployment"]["url"] = bad
            with self.subTest(url=bad), self.assertRaises(bootstrap.BootstrapBlocked):
                bootstrap.postflight(FakeClient(p), SHA, lambda u, m: 404)


if __name__ == "__main__":
    unittest.main()
