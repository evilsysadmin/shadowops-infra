"""Historical Pages alias enumeration: no mutation and no false protected verdict."""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import game_identity_pages_history as audit

SHA = "a" * 40


class FakeCloudflare:
    account = "f" * 32

    def __init__(self, *, present=True, history_count=2, inject=None):
        self.present = present
        self.history_count = history_count
        self.inject = inject
        self.calls = []

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if method != "GET" or data is not None:
            raise AssertionError("Cloudflare mutations are forbidden")
        name = path.split("/pages/projects/")[1].split("/")[0]
        alias = name + ".pages.dev"
        if not self.present:
            return 404, None
        obj = {"name": name, "subdomain": alias,
               "production_branch": "main", "source": None,
               "domains": [alias],
               "canonical_deployment": {"url": "https://current." + alias},
               "latest_deployment": {"url": "https://current." + alias}}
        if "/deployments" not in path:
            return 200, self.inject or obj
        page = 1
        assert "?" not in path, "Cloudflare Pages deployment GET must not send per_page"
        if self.history_count >= audit.PAGE_SIZE:
            quantity = min(audit.PAGE_SIZE, max(0, self.history_count - (page-1)*audit.PAGE_SIZE))
        else:
            quantity = self.history_count if page == 1 else 0
        return 200, [
            {"project_name": name, "url": f"https://d{(page-1)*audit.PAGE_SIZE+n}.{alias}"}
            for n in range(quantity)
        ]


def denied(url, method):
    assert url.startswith("https://")
    assert ".pages.dev" in url and "?" not in url
    assert method == "GET"
    return 404


class PagesHistoryTests(unittest.TestCase):
    def test_every_known_pages_game_is_in_inventory(self):
        expected = {(g.slug, g.environment, g.pages_project)
                    for g in audit.exposure.GAMES if g.pages_project}
        self.assertEqual({(g.slug, g.environment, g.pages_project)
                          for g in audit.projects()}, expected)
        self.assertEqual(len(audit.projects()), 7)

    def test_bounded_history_returns_main_current_and_old_aliases(self):
        cf = FakeCloudflare(history_count=2)
        g = audit.projects()[0]
        hosts, complete = audit.list_hosts(cf, g)
        self.assertFalse(complete)
        self.assertEqual(hosts[0], g.pages_project + ".pages.dev")
        self.assertIn("current." + g.pages_project + ".pages.dev", hosts)
        self.assertIn("d0." + g.pages_project + ".pages.dev", hosts)
        self.assertEqual({m for m, _, _ in cf.calls}, {"GET"})

    def test_historic_anonymous_200_blocks_success_even_if_main_is_404(self):
        cf = FakeCloudflare()
        g = next(g for g in audit.projects() if g.slug == "star-adventures")
        def old_static(url, method):
            return 200 if "/release.json" in url and "d1." in url else 404
        report = audit.assess_one(cf, g, old_static)
        self.assertEqual(report["state"], "REVIEW_ANONYMOUS_200")
        self.assertEqual(report["exposed_host_count"], 1)
        self.assertNotIn("exposed_hosts", report)
        self.assertNotIn("d1.staradvs-staging.pages.dev", str(report))
        self.assertEqual(report["hosts_discovered"], 4)

    def test_incomplete_history_or_host_budget_never_yields_green(self):
        cf = FakeCloudflare(history_count=audit.PAGE_SIZE * 3)
        g = audit.projects()[0]
        report = audit.assess_one(cf, g, denied)
        self.assertEqual(report["state"], "NOT_FULLY_VERIFIED")
        self.assertFalse(report["historic_inventory_complete"])
        self.assertEqual(report["hosts_probed"], audit.MAX_HOSTS_PER_PROJECT)
        self.assertGreater(report["skipped_hosts"], 0)
        self.assertEqual(len([x for x in cf.calls if "/deployments" in x[1]]), 1)

    def test_fail_closed_when_provider_missing_or_cannot_reach_https(self):
        cf = FakeCloudflare(present=False)
        self.assertEqual(audit.assess_one(cf, audit.projects()[0], denied)["state"], "NOT_FULLY_VERIFIED")
        cf = FakeCloudflare()
        self.assertEqual(audit.assess_one(cf, audit.projects()[0], lambda url, method: 0)["state"],
                         "NOT_FULLY_VERIFIED")
        self.assertEqual(audit.audit(cf, lambda url, method: 404)["state"], "NOT_FULLY_VERIFIED")

    def test_alias_origin_validation_rejects_redirects_and_foreign_hosts(self):
        alias = "staradvs-staging.pages.dev"
        self.assertEqual(audit.deployment_host("https://abc." + alias, alias), "abc." + alias)
        for url in ("http://abc." + alias, "https://abc." + alias + "/game",
                    "https://abc." + alias + "?x=1", "https://abc." + alias + ".example.org",
                    "https://abc.other.pages.dev", "https://a.b." + alias,
                    "https://u:p@abc." + alias, "https://abc." + alias + ":443"):
            with self.subTest(url=url), self.assertRaises(audit.InventoryError):
                audit.deployment_host(url, alias)
        with self.assertRaises(audit.InventoryError):
            audit.main_alias("staradvs-staging", "evil.pages.dev")

    def test_foreign_project_or_source_does_not_trigger_http_probe(self):
        for issue in ("source", "domain", "branch", "alias"):
            with self.subTest(issue=issue):
                g = audit.projects()[0]
                name = g.pages_project
                obj = {"name": name, "subdomain": name + ".pages.dev",
                       "production_branch": "main", "source": None,
                       "domains": [g.hostname]}
                if issue == "source":
                    obj["source"] = {"type": "github"}
                elif issue == "domain":
                    obj["domains"] = ["foreign.invalid"]
                elif issue == "branch":
                    obj["production_branch"] = "dev"
                else:
                    obj["subdomain"] = "wrong.pages.dev"
                cf = FakeCloudflare(inject=obj)
                def fail(_url, _method):
                    raise AssertionError("Unsafe project should not be probed")
                result = audit.assess_one(cf, g, fail)
                self.assertIn(result["reason"], {"Foreign Pages source/project", "Unexpected Pages custom domains", "Unexpected Pages alias"})
                self.assertEqual(result["state"], "NOT_FULLY_VERIFIED")

    def test_public_actions_report_never_includes_opaque_deployment_hostname(self):
        import json
        cf = FakeCloudflare()
        result = audit.audit(cf, lambda url, method: 200 if "d0." in url else 404)
        self.assertEqual(result["state"], "REVIEW_ANONYMOUS_200")
        raw = json.dumps(result, sort_keys=True)
        for game in audit.projects():
            alias = game.pages_project + ".pages.dev"
            self.assertNotIn("d0." + alias, raw)
            self.assertNotIn("current." + alias, raw)
        for row in result["projects"]:
            self.assertNotIn("exposed_hosts", row)
            self.assertNotIn("unverified_hosts", row)
            self.assertGreater(row["exposed_host_count"], 0)

    def test_only_exact_cloudflare_access_login_redirect_is_recognized(self):
        origin = "https://old.pages-staging.pages.dev/"
        valid = "https://shadowops.cloudflareaccess.com/cdn-cgi/access/login/old.pages-staging.pages.dev?redirect_url=%2F"
        self.assertTrue(audit.is_access_login_redirect(origin, 302, valid))
        self.assertTrue(audit.is_access_login_redirect(origin, 303, valid))
        self.assertFalse(audit.is_access_login_redirect(origin, 301, valid))
        invalid = (
            "https://evil.invalid/login",
            "http://shadowops.cloudflareaccess.com/cdn-cgi/access/login/old.pages-staging.pages.dev",
            "https://evil.cloudflareaccess.com.evil.invalid/cdn-cgi/access/login/old.pages-staging.pages.dev",
            "https://shadowops.cloudflareaccess.com@evil.invalid/cdn-cgi/access/login/old.pages-staging.pages.dev",
            "https://shadowops.cloudflareaccess.com/cdn-cgi/access/login/different.pages.dev",
            "https://shadowops.cloudflareaccess.com/cdn-cgi/access/login/old.pages-staging.pages.dev/extra",
            "https://shadowops.cloudflareaccess.com:443/cdn-cgi/access/login/old.pages-staging.pages.dev",
            "https://shadowops.cloudflareaccess.com/cdn-cgi/access/login/old.pages-staging.pages.dev#fragment",
            "/cdn-cgi/access/login/old.pages-staging.pages.dev",
            "https://shadowops.cloudflareaccess.com/cdn-cgi/access/login/old.pages-staging.pages.dev" + "a" * 2100,
        )
        for target in invalid:
            with self.subTest(target=target[:100]):
                self.assertFalse(audit.is_access_login_redirect(origin, 302, target))
        self.assertFalse(audit.is_access_login_redirect("https://evil.invalid/", 302, valid))

    def test_access_login_response_never_proves_protected_historic_coverage(self):
        cf = FakeCloudflare()
        g = next(g for g in audit.projects() if g.slug == "star-adventures")
        challenge = audit.GuestProbe(302, True)
        safe = audit.assess_one(cf, g, lambda _u, _m: challenge)
        self.assertEqual(safe["access_login_challenge_count"], 4)
        self.assertEqual(safe["exposed_host_count"], 0)
        self.assertEqual(safe["unverified_host_count"], 0)
        self.assertFalse(safe["historic_inventory_complete"])
        self.assertEqual(safe["state"], "NOT_FULLY_VERIFIED")
        # A redirect to some other origin is NOT an Access challenge.
        unverified = audit.assess_one(cf, g, lambda _u, _m: audit.GuestProbe(302, False))
        self.assertEqual(unverified["access_login_challenge_count"], 0)
        self.assertEqual(unverified["unverified_host_count"], 4)
        # One anonymous static 200 still blocks, even with a valid challenge elsewhere.
        def mixed(url, _method):
            if "d1." in url and "/release.json" in url:
                return audit.GuestProbe(200)
            return audit.GuestProbe(302, True)
        exposed = audit.assess_one(cf, g, mixed)
        self.assertEqual(exposed["state"], "REVIEW_ANONYMOUS_200")
        self.assertEqual(exposed["exposed_host_count"], 1)
        self.assertNotIn("d1.staradvs-staging.pages.dev", json.dumps(exposed))

    def test_real_http_adapter_never_follows_redirects_or_logs_location(self):
        import urllib.error
        from unittest.mock import patch

        url = "https://d1.staradvs-staging.pages.dev/"
        location = "https://team.cloudflareaccess.com/cdn-cgi/access/login/d1.staradvs-staging.pages.dev"
        class RedirectOpener:
            def open(self, req, timeout):
                self.request = req
                self.timeout = timeout
                raise urllib.error.HTTPError(url, 302, "Found", {"Location": location}, None)
        opener = RedirectOpener()
        with patch.object(audit.urllib.request, "build_opener", return_value=opener):
            response = audit.fetch_pages_guest(url, "GET")
        self.assertEqual(response, audit.GuestProbe(302, True))
        self.assertEqual(opener.request.full_url, url)
        self.assertEqual(opener.request.get_method(), "GET")
        self.assertEqual(opener.timeout, 8)
        self.assertNotIn("team.cloudflareaccess.com", repr(response))

    def test_cloudflare_status_is_safe_but_provider_text_stays_private(self):
        g = audit.projects()[0]

        class FailingProvider(FakeCloudflare):
            def __init__(self, error):
                super().__init__()
                self.error = error

            def request(self, method, path, data=None):
                if "/deployments" in path:
                    raise self.error
                return super().request(method, path, data)

        for code in (400, 401, 403, 422, 429, 500, 503):
            with self.subTest(code=code):
                cf = FailingProvider(audit.AdmissionError(f"Cloudflare GET failed (HTTP {code})"))
                report = audit.assess_one(cf, g, denied)
                self.assertEqual(report["reason"], f"provider-http-{code}")
                self.assertEqual(report["state"], "NOT_FULLY_VERIFIED")
        cf = FailingProvider(audit.AdmissionError("secret-token=UNSAFE_TO_PRINT"))
        report = audit.assess_one(cf, g, denied)
        self.assertEqual(report["reason"], "provider_request_unavailable")
        self.assertNotIn("UNSAFE", str(report))

    def test_new_workflow_runs_live_on_exact_main_only_and_no_writes(self):
        file = ROOT / ".github/workflows/game-identity-pages-history.yml"
        content = file.read_text()
        self.assertIn("game_identity_pages_history.py audit", content)
        self.assertIn("github.event_name == 'push'", content)
        self.assertIn("github.ref == 'refs/heads/main'", content)
        self.assertIn("environment: staging", content)
        self.assertIn("test_game_identity_pages_history.py", content)
        self.assertIn('tee -a "$GITHUB_STEP_SUMMARY"', content)
        self.assertNotIn("pages deploy", content)
        self.assertNotIn("wrangler", content)
        self.assertNotIn("workflow_dispatch.inputs", content)
        self.assertNotIn("secrets.OCI", content)


if __name__ == "__main__":
    unittest.main()
