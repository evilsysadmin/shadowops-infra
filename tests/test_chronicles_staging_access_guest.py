"""Conservative anonymous guest check for protected Chronicles staging previews."""
from __future__ import annotations

import json
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import chronicles_staging_access_guest as guest
from game_identity_pages_history import GuestProbe


class Pages:
    account = "f" * 32

    def __init__(self, history=2, malformed=None):
        self.calls = []
        self.history = history
        self.malformed = malformed

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if method != "GET" or data is not None:
            raise AssertionError("Guest smoke must never mutate Cloudflare")
        if path.endswith("/deployments"):
            if self.malformed == "foreign":
                return 200, [{"url": "https://d1.other.pages.dev"}]
            if self.malformed == "missing":
                return 404, None
            return 200, [{
                "project_name": guest.PROJECT,
                "url": f"https://d{i}.{guest.ROOT}"
            } for i in range(self.history)]
        return 200, {
            "name": guest.PROJECT,
            "subdomain": guest.ROOT,
            "production_branch": "main", "source": None,
            "domains": ["staging.chronicles.shadowops.dpdns.org"],
            "latest_deployment": {"url": "https://current." + guest.ROOT},
        }


class GuestSampleTests(unittest.TestCase):
    def test_all_sampled_previews_challenged_but_not_claimed_protected(self):
        seen = []
        def probe(url, method):
            seen.append((url, method))
            self.assertNotEqual(url, "https://" + guest.ROOT + "/")
            self.assertTrue(url.endswith("/") or url.endswith("/release.json"))
            return GuestProbe(302, True)
        pages = Pages()
        result = guest.probe(pages, probe)
        self.assertEqual(result["state"], "GUEST_DENIAL_OBSERVED_SAMPLE_ONLY")
        self.assertEqual(result["preview_hosts_sampled"], 3)
        self.assertEqual(result["guest_requests"], 6)
        self.assertEqual(result["access_login_challenge_requests"], 6)
        self.assertFalse(result["historic_inventory_complete"])
        self.assertFalse(result["fully_protected"])
        self.assertFalse(result["shadowops_id_authenticated_e2e"])
        self.assertFalse(result["base_pages_alias_checked"])
        self.assertFalse(result["canonical_custom_domain_checked"])
        self.assertEqual(len(seen), 6)
        self.assertTrue(all(method == "GET" for _, method in seen))
        self.assertTrue(all(method == "GET" for method, _, _ in pages.calls))
        self.assertNotIn("d1." + guest.ROOT, json.dumps(result))

    def test_anonymous_200_is_blocker_even_if_other_previews_challenged(self):
        def probe(url, method):
            return GuestProbe(200) if "d1." in url and url.endswith("/release.json") else GuestProbe(302, True)
        result = guest.probe(Pages(), probe)
        self.assertEqual(result["state"], "ANONYMOUS_PREVIEW_CONTENT_OBSERVED")
        self.assertEqual(result["anonymous_200_206_requests"], 1)
        self.assertFalse(result["fully_protected"])

    def test_unrecognized_redirect_404_network_error_or_plain_status_not_green(self):
        for returned in (GuestProbe(302, False), GuestProbe(404),
                         GuestProbe(0), GuestProbe(503), 403, GuestProbe(True, True)):
            with self.subTest(returned=returned):
                result = guest.probe(Pages(), lambda url, method: returned)
                self.assertEqual(result["state"], "PREVIEW_GUEST_SAMPLE_UNVERIFIED")
                self.assertGreater(result["unverified_requests"], 0)

    def test_403_and_access_login_are_sampled_denial_only(self):
        result = guest.probe(Pages(), lambda url, method: GuestProbe(403))
        self.assertEqual(result["state"], "GUEST_DENIAL_OBSERVED_SAMPLE_ONLY")
        self.assertEqual(result["denied_401_403_requests"], 6)
        self.assertEqual(result["access_login_challenge_requests"], 0)

    def test_foreign_malformed_or_oversized_inventory_never_probed(self):
        for pages in (Pages(history=0, malformed="foreign"),
                      Pages(history=0, malformed="missing"),
                      Pages(history=guest.MAX_HOSTS_PER_PROJECT + 1)):
            with self.subTest(history=pages.history):
                calls = []
                with self.assertRaises(guest.PostflightError):
                    guest.probe(pages, lambda url, method: calls.append(url))
                self.assertEqual(calls, [])

    def test_missing_previews_are_not_a_fake_green(self):
        p = Pages(history=0)
        def custom(method, path, data=None):
            if path.endswith("/deployments"):
                return 200, []
            if path.endswith("/projects/" + guest.PROJECT):
                return 200, {
                    "name": guest.PROJECT, "production_branch": "main",
                    "source": None, "subdomain": guest.ROOT, "domains": []}
            raise AssertionError(path)
        p.request = custom
        with self.assertRaises(guest.PostflightError):
            guest.probe(p, lambda u, m: GuestProbe(403))

    def test_operator_workflow_always_runs_guest_probe_in_apply(self):
        content = (ROOT / ".github/workflows/chronicles-staging-access-preview.yml").read_text()
        self.assertIn("scripts/chronicles_staging_access_guest.py verify-sample", content)
        self.assertIn("test_chronicles_staging_access_guest.py", content)
        self.assertIn("guest sample", content.lower())
        self.assertIn("inputs.confirm == 'CHRONICLES_STAGING_PREVIEW_ACCESS'", content)
        self.assertNotIn("continue-on-error: true", content)
        self.assertNotIn("curl -k", content)

    def test_cli_never_prints_opaque_deployment_alias_or_exception(self):
        pages = Pages()
        with patch.object(guest, "CloudflareClient", return_value=pages), patch.object(guest, "fetch_pages_guest", return_value=GuestProbe(403)):
            # probe's default is bound on definition; override explicitly.
            with patch.object(guest, "probe", return_value={
                "state": "GUEST_DENIAL_OBSERVED_SAMPLE_ONLY",
                "fully_protected": False, "preview_hosts_sampled": 3}):
                from contextlib import redirect_stdout
                from io import StringIO
                stream = StringIO()
                with redirect_stdout(stream):
                    code = guest.main(["verify-sample"])
                self.assertEqual(code, 0)
                self.assertNotIn("d0." + guest.ROOT, stream.getvalue())


if __name__ == "__main__":
    unittest.main()
