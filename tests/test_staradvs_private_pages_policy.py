"""Pages fail-closed policy is scoped to one owned Star Adventures staging project."""
import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_private_pages_policy as policy
import staradvs_pages as pages


def project():
    return {
        "name": pages.PROJECT, "production_branch": "main",
        "source": None, "subdomain": pages.TARGET,
        "domains": [pages.HOST, pages.TARGET],
        "deployment_configs": {
            "production": {
                "fail_open": True, "compatibility_flags": ["nodejs_compat"],
                "env_vars": {},
            },
            "preview": {
                "fail_open": True, "compatibility_flags": [],
                "env_vars": {},
            },
        },
    }


class FakeCloudflare:
    account = "a" * 32

    def __init__(self, value=None):
        self.value = value or project()
        self.calls = []

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if path.startswith("/zones?"):
            return 200, [{"id": "z" * 32, "name": pages.ZONE}]
        if "/dns_records?" in path:
            return 200, [{"name": pages.HOST, "type": "CNAME",
                          "content": pages.TARGET, "proxied": True}]
        if path.endswith("/pages/projects/" + pages.PROJECT):
            if method == "GET":
                return 200, copy.deepcopy(self.value)
            if method == "PATCH":
                assert set(data) == {"deployment_configs"}
                assert set(data["deployment_configs"]) == {"production", "preview"}
                for mode in ("production", "preview"):
                    assert set(data["deployment_configs"][mode]) == {"fail_open", "compatibility_flags"}
                    self.value["deployment_configs"][mode].update(data["deployment_configs"][mode])
                return 200, copy.deepcopy(self.value)
        if path.endswith("/domains/" + pages.HOST):
            return 200, {"name": pages.HOST, "status": "active"}
        raise AssertionError("Unexpected Cloudflare URL " + method + " " + path)


class PagesPrivatePolicyTests(unittest.TestCase):
    def test_preflight_uses_get_only_and_prepares_minimal_patch(self):
        cf = FakeCloudflare()
        plan = policy.preflight(cf)
        self.assertFalse(plan["already_private"])
        self.assertEqual(plan["patch"]["deployment_configs"]["production"], {
            "fail_open": False,
            "compatibility_flags": [policy.GOOD, "nodejs_compat"],
        })
        self.assertTrue(all(method == "GET" for method, _, _ in cf.calls))
        self.assertNotIn("env_vars", str(plan["patch"]))

    def test_apply_changes_only_flags_then_idempotently_preserves_existing_binding(self):
        p = project()
        p["deployment_configs"]["production"]["env_vars"] = {
            policy.KEY: {"type": "secret_text", "value": "NEVER_LOG_THIS"}
        }
        cf = FakeCloudflare(p)
        self.assertEqual(policy.apply(cf), "updated-private")
        self.assertEqual(policy.apply(cf), "already-private")
        self.assertEqual(sum(1 for method, _, _ in cf.calls if method == "PATCH"), 1)
        self.assertEqual(cf.value["deployment_configs"]["production"]["env_vars"],
                         p["deployment_configs"]["production"]["env_vars"])
        self.assertTrue(policy.preflight(cf)["already_private"])

    def test_refuses_foreign_project_and_unexpected_domains_before_mutation(self):
        for change in ("project", "branch", "alias", "domain", "source"):
            with self.subTest(change=change):
                p = project()
                if change == "project":
                    p["name"] = "foreign"
                elif change == "branch":
                    p["production_branch"] = "preview"
                elif change == "alias":
                    p["subdomain"] = "different.pages.dev"
                elif change == "domain":
                    p["domains"].append("other.example.org")
                else:
                    p["source"] = {"type": "github"}
                cf = FakeCloudflare(p)
                with self.assertRaises((policy.PrivatePolicyError, pages.AdmissionError)):
                    policy.apply(cf)
                self.assertFalse(any(method == "PATCH" for method, _, _ in cf.calls))

    def test_refuses_unsafe_flags_or_secret_bindings_before_mutation(self):
        for issue in ("private-origin", "flags-not-list", "preview-secret", "foreign-secret", "plain-secret"):
            with self.subTest(issue=issue):
                p = project()
                prod = p["deployment_configs"]["production"]
                if issue == "private-origin":
                    prod["compatibility_flags"].append(policy.BAD)
                elif issue == "flags-not-list":
                    prod["compatibility_flags"] = "unknown"
                elif issue == "preview-secret":
                    p["deployment_configs"]["preview"]["env_vars"]["FOREIGN"] = {"type": "secret_text"}
                elif issue == "foreign-secret":
                    prod["env_vars"]["MALICIOUS"] = {"type": "secret_text"}
                else:
                    prod["env_vars"][policy.KEY] = {"type": "plain_text", "value": "bad"}
                cf = FakeCloudflare(p)
                with self.assertRaises((policy.PrivatePolicyError, pages.AdmissionError)):
                    policy.apply(cf)
                self.assertFalse(any(method == "PATCH" for method, _, _ in cf.calls))

    def test_workflow_requires_trusted_main_manual_apply_and_exact_confirmation(self):
        f = (ROOT / ".github/workflows/staradvs-private-pages-policy.yml").read_text()
        self.assertIn("workflow_dispatch:", f)
        self.assertIn("STARADVS_PRIVATE_PAGES_POLICY", f)
        self.assertIn("inputs.operation == 'apply'", f)
        self.assertIn("inputs.confirm == 'STARADVS_PRIVATE_PAGES_POLICY'", f)
        self.assertIn("github.ref == 'refs/heads/main'", f)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", f)
        self.assertIn("environment: staging", f)
        self.assertNotIn("pages deploy", f)
        self.assertNotIn("wrangler", f)


if __name__ == "__main__":
    unittest.main()
