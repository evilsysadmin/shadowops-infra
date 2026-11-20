"""Single-host, manual Access pilot must not touch production or other games."""
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import chronicles_staging_access_preview as pilot

ACCOUNT = "a" * 32
EMAIL = "operator@private.invalid"
APP_ID = "00000000-0000-4000-8000-000000000001"


class Pages:
    account = ACCOUNT

    def __init__(self, data=None):
        self.calls = []
        self.project = data if data is not None else {
            "name": pilot.PROJECT,
            "production_branch": "main",
            "subdomain": pilot.PROJECT + ".pages.dev",
            "source": None,
            "domains": [pilot.CUSTOM],
        }

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        assert method == "GET" and data is None
        assert path == f"/accounts/{ACCOUNT}/pages/projects/{pilot.PROJECT}"
        return 200, self.project


class Access:
    account = ACCOUNT

    def __init__(self, *, existing=None, policy=None):
        self.apps = list(existing or [])
        self.policy = policy if policy is not None else [
            {"decision": "allow", "include": [{"email": {"email": EMAIL}}]}
        ]
        self.calls = []
        self.posts = []

    def get(self, path):
        self.calls.append(("GET", path))
        assert path.startswith(f"/accounts/{ACCOUNT}/access/apps")
        if path == f"/accounts/{ACCOUNT}/access/apps":
            return {"result": self.apps, "result_info": {
                "count": len(self.apps), "total_count": len(self.apps),
                "total_pages": 1}}
        assert path == f"/accounts/{ACCOUNT}/access/apps/{APP_ID}/policies"
        return {"result": self.policy, "result_info": {
            "count": len(self.policy), "total_count": len(self.policy),
            "total_pages": 1}}

    def create_app(self, body):
        self.calls.append(("POST", f"/accounts/{ACCOUNT}/access/apps"))
        self.posts.append(body)
        self.apps.append({
            "id": APP_ID, "name": pilot.APP_NAME,
            "type": "self_hosted", "domain": pilot.WILDCARD
        })
        return {"success": True}


def app(name=pilot.APP_NAME, domain=pilot.WILDCARD):
    return {"id": APP_ID, "name": name, "type": "self_hosted", "domain": domain}


class PilotTest(unittest.TestCase):
    def test_plan_only_reads_exact_scope_and_never_logs_email(self):
        cf, pages = Access(), Pages()
        self.assertEqual(pilot.plan(cf, pages, EMAIL), "needs-operator-creation")
        self.assertEqual(cf.calls, [("GET", f"/accounts/{ACCOUNT}/access/apps")])
        self.assertEqual(len(pages.calls), 1)
        self.assertEqual(cf.posts, [])
        self.assertNotIn(EMAIL, "needs-operator-creation")

    def test_apply_creates_exactly_one_private_allow_and_is_idempotent(self):
        cf, pages = Access(), Pages()
        self.assertEqual(pilot.apply(cf, pages, EMAIL), "created-pending-guest-probe")
        self.assertEqual(cf.posts, [pilot.app_payload(EMAIL)])
        self.assertEqual(cf.posts[0]["domain"], "*.chronicles-staging.pages.dev")
        self.assertEqual(cf.posts[0]["type"], "self_hosted")
        self.assertEqual(cf.posts[0]["policies"], [{
            "name": pilot.POLICY_NAME, "decision": "allow",
            "include": [{"email": {"email": EMAIL}}],
            "precedence": 1,
        }])
        self.assertEqual(pilot.plan(cf, pages, EMAIL), "already-configured")
        self.assertEqual(pilot.apply(cf, pages, EMAIL), "already-configured")
        self.assertEqual(len(cf.posts), 1)
        self.assertTrue(all(m == "GET" for m, _, _ in pages.calls))

    def test_do_not_adopt_foreign_existing_app_or_broad_policies(self):
        for scenario in ("foreign-name", "everyone", "different-operator",
                         "additional-allow", "different-domain"):
            with self.subTest(scenario=scenario):
                obj = app()
                policy = None
                if scenario == "foreign-name":
                    obj["name"] = "Someone else's Access app"
                if scenario == "everyone":
                    policy = [{"decision": "allow", "include": [{"everyone": {}}]}]
                if scenario == "different-operator":
                    policy = [{"decision": "allow", "include": [
                        {"email": {"email": "elsewhere@example.com"}}]}]
                if scenario == "additional-allow":
                    policy = [{"decision": "allow", "include": [
                        {"email": {"email": EMAIL}}]},
                        {"decision": "allow", "include": [
                            {"email": {"email": "other@example.com"}}]}]
                if scenario == "different-domain":
                    obj["destinations"] = [{"type": "public", "uri": pilot.WILDCARD},
                                           {"type": "public", "uri": "chronicles-production.pages.dev"}]
                cf = Access(existing=[obj], policy=policy)
                with self.assertRaises(pilot.CutoverError):
                    pilot.apply(cf, Pages(), EMAIL)
                self.assertFalse(cf.posts)

    def test_wrong_project_domain_or_source_never_writes(self):
        for delta in ({"name": "chronicles-production"},
                      {"production_branch": "feature"},
                      {"subdomain": "chronicles-production.pages.dev"},
                      {"source": {"type": "github"}},
                      {"domains": ["chronicles.shadowops.dpdns.org"]}):
            with self.subTest(delta=delta):
                page = Pages()
                page.project.update(delta)
                cf = Access()
                with self.assertRaises(pilot.CutoverError):
                    pilot.apply(cf, page, EMAIL)
                self.assertFalse(cf.posts)

    def test_no_wildcard_or_everyone_operator_email(self):
        for invalid in ("", "not-an-email", "all@*", "*@example.com",
                        "operator@example.com\nX-Secret: test"):
            with self.subTest(email=invalid):
                cf, page = Access(), Pages()
                with self.assertRaises(pilot.CutoverError):
                    pilot.apply(cf, page, invalid)
                self.assertEqual(cf.calls, [])
                self.assertEqual(page.calls, [])

    def test_manual_workflow_strict_confirm_staging_and_exact_source_sha(self):
        flow = (ROOT / ".github/workflows/chronicles-staging-access-preview.yml").read_text()
        for token in ("workflow_dispatch:",
                      "inputs.operation == 'apply'",
                      "inputs.confirm == 'CHRONICLES_STAGING_PREVIEW_ACCESS'",
                      "github.repository == 'evilsysadmin/shadowops-infra'",
                      "github.ref == 'refs/heads/main'",
                      'environment: staging',
                      'chronicles_staging_access_preview.py apply',
                      'chronicles_staging_access_preview.py plan',
                      "shadowops-cloudflare-chronicles-pages-staging",
                      "CLOUDFLARE_ACCESS_WRITE_TOKEN",
                      "CLOUDFLARE_ACCESS_READ_TOKEN"):
            self.assertIn(token, flow)
        self.assertIn('gh api repos/evilsysadmin/shadowops-infra/commits/main', flow)
        for forbidden in ("pages deploy", "wrangler", "DELETE", "chronicles-production",
                          "identity_staging_provision.py", "CLOUDFLARE_IDENTITY_SERVICE_PROOF"):
            self.assertNotIn(forbidden, flow)


if __name__ == "__main__":
    unittest.main()
