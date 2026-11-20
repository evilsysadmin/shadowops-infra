"""Cloudflare Access metadata check: exact Pages hosts, no bypass, no writes."""
from __future__ import annotations

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pages_access_readiness as a


def ident(n):
    return "00000000-0000-4000-8000-" + f"{n:012d}"


def app(host, n, *, dest=True):
    value = {"id": ident(n), "type": "self_hosted", "name": "PRIVATE-" + host}
    if dest:
        value["destinations"] = [{"type": "public", "uri": host}]
    else:
        value["domain"] = host
    return value


def full_apps():
    result = []
    for project, custom in a.HOSTS.items():
        for host in (project + ".pages.dev", "*." + project + ".pages.dev", custom):
            result.append(app(host, len(result) + 1))
    return result


class Fake:
    account = "a" * 32

    def __init__(self, apps=None, policies=None):
        self.apps = full_apps() if apps is None else apps
        self.policies = policies or {}
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        if path == f"/accounts/{self.account}/access/apps":
            return {"success": True, "result": self.apps,
                    "result_info": {"page": 1, "total_pages": 1,
                                    "count": len(self.apps),
                                    "total_count": len(self.apps)}}
        suffix = path.split("/access/apps/")[1]
        ident_part, tail = suffix.split("/")
        if tail != "policies" or ident_part not in {x["id"] for x in self.apps}:
            raise AssertionError("Unknown Access policy GET path")
        policy = self.policies.get(ident_part, [
            {"decision": "allow", "include": [{"email": {"email": "operator@private.invalid"}}]}
        ])
        return {"success": True, "result": policy,
                "result_info": {"page": 1, "total_pages": 1,
                                "count": len(policy), "total_count": len(policy)}}


class AccessReadinessTests(unittest.TestCase):
    def test_fully_populated_metadata_still_cannot_claim_live_protection(self):
        cf = Fake()
        result = a.inspect(cf)
        self.assertEqual(result["state"], "CONFIGURED_FOR_GUEST_TEST")
        self.assertIs(result["can_activate"], False)
        self.assertIs(result["claim_all_games_protected"], False)
        self.assertEqual(len(result["projects"]), 3)
        for row in result["projects"]:
            self.assertEqual(set(row["application_scopes"]),
                             {"main", "immutable", "custom_companion"})
            self.assertTrue(all(v == "restricted-policy-candidate"
                                for v in row["application_scopes"].values()))
            self.assertEqual(row["shadowops_id_e2e"], "not-performed")
        self.assertEqual(len(cf.paths), 10)
        self.assertNotIn("operator@private.invalid", json.dumps(result))
        self.assertNotIn(ident(1), json.dumps(result))

    def test_previews_app_does_not_cover_main_alias(self):
        apps = [x for x in full_apps()
                if x["destinations"][0]["uri"] != "staradvs-staging.pages.dev"]
        result = a.inspect(Fake(apps))
        row = next(r for r in result["projects"] if r["project"] == "staradvs-staging")
        self.assertEqual(row["application_scopes"]["main"], "missing")
        self.assertEqual(row["application_scopes"]["immutable"], "restricted-policy-candidate")
        self.assertEqual(result["state"], "ACCESS_REMEDIATION_REQUIRED")

    def test_companion_custom_domain_required_before_dashboard_cutover(self):
        apps = [x for x in full_apps()
                if x["destinations"][0]["uri"] != "chronicles.shadowops.dpdns.org"]
        rows = a.inspect(Fake(apps))["projects"]
        row = next(r for r in rows if r["project"] == "chronicles-production")
        self.assertEqual(row["application_scopes"]["custom_companion"], "missing")

    def test_duplicate_or_public_override_never_approves(self):
        apps = full_apps()
        apps.append(app("staradvs-staging.pages.dev", 28))
        result = a.inspect(Fake(apps))
        row = next(r for r in result["projects"] if r["project"] == "staradvs-staging")
        self.assertEqual(row["application_scopes"]["main"], "ambiguous")
        apps = full_apps()
        apps[0]["destinations"][0]["overrides"] = [
            {"behavior": "public", "path_pattern": "/*"}]
        self.assertEqual(a.inspect(Fake(apps))["state"], "ACCESS_REMEDIATION_REQUIRED")

    def test_cross_game_or_cross_mode_multi_host_app_cannot_pass_review(self):
        for foreign in ("chronicles-production.pages.dev",
                        "*.chronicles-staging.pages.dev",
                        "staging.chronicles.shadowops.dpdns.org"):
            with self.subTest(foreign=foreign):
                apps = full_apps()
                apps[0]["destinations"].append({"type": "public", "uri": foreign})
                domains, safe = a.app_destinations(apps[0])
                self.assertFalse(safe)
                self.assertEqual(len(domains), 2)
                result = a.inspect(Fake(apps))
                self.assertEqual(result["state"], "ACCESS_REMEDIATION_REQUIRED")
                row = next(r for r in result["projects"]
                           if r["project"] == "chronicles-staging")
                self.assertEqual(row["application_scopes"]["main"], "ambiguous")

    def test_legacy_multiple_self_hosted_domains_are_untrusted(self):
        value = {
            "type": "self_hosted",
            "self_hosted_domains": [
                {"domain": "staradvs-staging.pages.dev"},
                {"domain": "chronicles-production.pages.dev"},
            ],
        }
        domains, safe = a.app_destinations(value)
        self.assertFalse(safe)
        self.assertEqual(len(domains), 2)

    def test_broad_app_overlapping_all_pages_cannot_hide_behind_valid_apps(self):
        examples = [
            {"type": "self_hosted", "domain": "*.pages.dev"},
            {"type": "self_hosted", "destinations": [
                {"type": "public", "uri": "https://*.pages.dev/private"}]},
            {"type": "self_hosted", "destinations": [
                {"type": "public", "uri": "*.chronicles-staging.pages.dev"},
                {"type": "private", "uri": "hidden.internal"}]},
            {"type": "self_hosted", "self_hosted_domains": [
                {"domain": "*.staradvs-staging.pages.dev"},
                {"domain": "other.pages.dev"}]},
            {"type": "self_hosted", "domain": "https://chronicles-production.pages.dev/path"},
            {"type": "self_hosted", "domain": "*.shadowops.dpdns.org"},
        ]
        for extra in examples:
            with self.subTest(extra=extra):
                apps = full_apps() + [dict(extra, id=ident(70))]
                report = a.inspect(Fake(apps))
                self.assertEqual(report["state"], "ACCESS_REMEDIATION_REQUIRED")
                self.assertTrue(any(
                    v == "ambiguous"
                    for row in report["projects"]
                    for v in row["application_scopes"].values()
                ))
                self.assertNotIn(ident(70), json.dumps(report))

    def test_specific_existing_deployment_conflicts_with_preview_wildcard(self):
        apps = full_apps() + [app("d1.chronicles-staging.pages.dev", 71)]
        result = a.inspect(Fake(apps))
        row = next(x for x in result["projects"]
                   if x["project"] == "chronicles-staging")
        self.assertEqual(row["application_scopes"]["immutable"], "ambiguous")
        self.assertEqual(result["state"], "ACCESS_REMEDIATION_REQUIRED")

    def test_unrelated_access_apps_do_not_block_complete_readiness(self):
        apps = full_apps() + [
            app("private-other.example.net", 60),
            app("*.snooker-staging.pages.dev", 61),
        ]
        result = a.inspect(Fake(apps))
        self.assertEqual(result["state"], "CONFIGURED_FOR_GUEST_TEST")

    def test_bypass_or_everyone_are_not_restricted_operator_access(self):
        for policy in (
            [{"action": "bypass", "include": [{"everyone": {}}]}],
            [{"decision": "allow", "include": [{"everyone": {}}]}],
            [{"decision": "allow", "include": []}],
            [{"decision": "service_auth", "include": [{"service_token": {}}]}],
            [],
        ):
            with self.subTest(policy=policy):
                cf = Fake(policies={ident(1): policy})
                result = a.inspect(cf)
                self.assertEqual(result["state"], "ACCESS_REMEDIATION_REQUIRED")

    def test_allow_rules_are_ored_and_each_must_name_one_operator(self):
        legitimate = {"decision": "allow", "include": [
            {"email": {"email": "operator@private.invalid"}},
            {"email": {"email": "backup@private.invalid"}},
        ]}
        self.assertEqual(
            a.inspect(Fake(policies={ident(1): [legitimate]}))["state"],
            "CONFIGURED_FOR_GUEST_TEST"
        )
        broad = [
            {"everyone": {}},
            {"email_domain": {"domain": "example.com"}},
            {"ip": {"ip": "0.0.0.0/0"}},
            {"country": {"country": "ES"}},
            {"group": {"id": ident(17)}},
            {"any_valid_service_token": {}},
            {"service_token": {"token_id": ident(2)}},
            {"email": {"email": "*@example.com"}},
            {"email": {"email": "not-an-email"}},
            {"email": {"email": "operator@private.invalid", "domain": "example.com"}},
            {"certificate": {}},
            {"email_list": {"id": ident(19)}},
            {},
        ]
        for extra in broad:
            with self.subTest(rule=extra):
                policy = {"decision": "allow", "include": [
                    {"email": {"email": "operator@private.invalid"}}, extra
                ]}
                result = a.inspect(Fake(policies={ident(1): [policy]}))
                self.assertEqual(result["state"], "ACCESS_REMEDIATION_REQUIRED")
                row = result["projects"][0]["application_scopes"]
                self.assertEqual(row["main"], "review-required")
                self.assertNotIn("operator@private.invalid", json.dumps(result))

    def test_deny_action_is_valid_but_deny_only_is_not_login_ready(self):
        deny = {"decision": "deny", "include": [{"everyone": {}}]}
        allow = {"decision": "allow", "include": [
            {"email": {"email": "operator@private.invalid"}}
        ]}
        self.assertEqual(
            a.inspect(Fake(policies={ident(1): [deny, allow]}))["state"],
            "CONFIGURED_FOR_GUEST_TEST"
        )
        self.assertEqual(
            a.inspect(Fake(policies={ident(1): [deny]}))["state"],
            "ACCESS_REMEDIATION_REQUIRED"
        )

    def test_incomplete_policy_inventory_never_conveys_safe_access(self):
        cf = Fake()

        class IncompletePolicies(Fake):
            def get(self, path):
                result = super().get(path)
                if path.endswith("/policies"):
                    result["result_info"]["total_pages"] = 2
                return result

        result = a.inspect(IncompletePolicies(cf.apps))
        self.assertEqual(result["state"], "ACCESS_REMEDIATION_REQUIRED")
        for project in result["projects"]:
            self.assertTrue(all(v == "not-verified"
                                for v in project["application_scopes"].values()))

    def test_legacy_domain_allowed_only_with_no_public_destinations(self):
        old = app("staradvs-staging.pages.dev", 1, dest=False)
        self.assertEqual(a.app_destinations(old), ({"staradvs-staging.pages.dev"}, True))
        old["destinations"] = [{"type": "public",
                                "uri": "*.staradvs-staging.pages.dev"}]
        # Destinations override the deprecated domain.
        self.assertEqual(a.app_destinations(old),
                         ({"*.staradvs-staging.pages.dev"}, True))
        for val in ("https://example.com/path", "evil.com:8443",
                    "evil.com?grant=yes", "evil.com#frag", "http://evil.com"):
            self.assertIsNone(a.normalized_destination(val))

    def test_page_of_access_apps_must_be_complete_before_review(self):
        apps = full_apps()
        for info in (None, {}, {"total_pages": 2, "count": 9, "total_count": 20},
                     {"total_pages": 1, "count": 9, "total_count": 99},
                     {"total_pages": "1", "count": 9, "total_count": 9}):
            with self.subTest(info=info):
                with self.assertRaises(a.ReadinessError):
                    a.parse_apps({"result": apps, "result_info": info})

    def test_access_api_scoped_only_to_read_apps_policies_without_redirects(self):
        token = a.AccessClient({
            "CLOUDFLARE_ACCOUNT_ID": "a" * 32,
            "CLOUDFLARE_ACCESS_READ_TOKEN": "fake-test-token",
        })
        path = f"/accounts/{token.account}/access/apps"
        for invalid in ("/zones/" + token.account + "/access/apps",
                        path + "?page=2", path + "/../secrets",
                        path + "/invalid/policies"):
            with self.subTest(path=invalid), self.assertRaises(a.ReadinessError):
                token.get(invalid)

    def test_github_action_never_mutates_access_or_pages(self):
        text = (ROOT / ".github/workflows/pages-access-readiness.yml").read_text()
        self.assertIn("pages_access_readiness.py inspect", text)
        self.assertIn("CLOUDFLARE_ACCESS_READ_TOKEN", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", text)
        self.assertIn("environment: staging", text)
        self.assertNotIn("curl -X POST", text)
        self.assertNotIn("pages deploy", text)
        self.assertNotIn("wrangler", text)
        self.assertNotIn("identity_staging_provision.py", text)


if __name__ == "__main__":
    unittest.main()
