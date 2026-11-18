import io
import sys
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bridgesquad_alias_bootstrap as bootstrap
import bridgesquad_alias_watchdog as watchdog
import bridgesquad_pages_readiness as readiness

SHA = "a" * 40
ALIAS = "bridgesquad-production.pages.dev"
ACCOUNT = "b" * 32
PROJECT = f"/accounts/{ACCOUNT}/pages/projects/{readiness.PROJECT}"
INVENTORY = {
    "project": "present", "domain": "absent", "dns": "absent",
    "identity_gate": "not-verified", "deployment": "not-verified",
}


def project():
    deployment = {
        "url": "https://abc123." + ALIAS,
        "environment": "production",
        "is_skipped": False,
        "latest_stage": {"status": "success"},
        "deployment_trigger": {"type": "ad_hoc", "metadata": {
            "branch": "main", "commit_dirty": False, "commit_hash": SHA,
        }},
    }
    return {
        "name": readiness.PROJECT, "production_branch": "main",
        "source": None, "subdomain": ALIAS, "domains": [],
        "deployment_configs": {
            x: {"fail_open": False, "compatibility_flags": ["global_fetch_strictly_public"],
                "env_vars": {}} for x in ("production", "preview")
        },
        "latest_deployment": deployment.copy(), "canonical_deployment": deployment.copy(),
    }


class Client:
    account = ACCOUNT

    def __init__(self, value):
        self.value = value
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if path != PROJECT:
            raise AssertionError("unexpected Cloudflare GET " + path)
        return self.value


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(readiness, "inspect", return_value=INVENTORY)
        patch.start()
        self.addCleanup(patch.stop)

    def test_current_canonical_release_is_audited_without_game_main_comparison(self):
        calls = []
        def guest(url, method):
            calls.append((url, method))
            return 404
        c = Client(project())
        result = watchdog.audit(c, probe=guest)
        self.assertEqual(result["source_sha"], SHA)
        self.assertEqual(result["aliases"], 2)
        self.assertEqual(result["anonymous_access"], "denied")
        self.assertGreaterEqual(len(c.calls), 2)
        self.assertIn(("https://" + ALIAS + "/index.html", "GET"), calls)
        self.assertIn(("https://abc123." + ALIAS + "/api/bridgesquad/session", "POST"), calls)

    def test_absent_canonical_or_invalid_source_is_blocked(self):
        for sha in (None, "", "../HEAD", "A"*40):
            p = project()
            p["canonical_deployment"]["deployment_trigger"]["metadata"]["commit_hash"] = sha
            with self.subTest(sha=sha), self.assertRaises(watchdog.WatchdogBlocked):
                watchdog.audit(Client(p), probe=lambda u, m: 404)
        p = project()
        p["canonical_deployment"] = None
        with self.assertRaises(watchdog.WatchdogBlocked):
            watchdog.audit(Client(p), probe=lambda u, m: 404)

    def test_fail_open_project_or_new_custom_domain_is_blocked(self):
        p = project()
        p["deployment_configs"]["production"]["fail_open"] = True
        with self.assertRaises(bootstrap.BootstrapBlocked):
            watchdog.audit(Client(p), probe=lambda u, m: 404)
        p = project()
        with mock.patch.object(readiness, "inspect", return_value={**INVENTORY, "dns": "present"}):
            with self.assertRaises(bootstrap.BootstrapBlocked):
                watchdog.audit(Client(p), probe=lambda u, m: 404)

    def test_redirect_public_content_or_denial_failure_is_fatal(self):
        for response in (200, 301, 302, 403, 500, 503, 599):
            with self.subTest(response=response), self.assertRaises(bootstrap.BootstrapBlocked):
                watchdog.audit(Client(project()), probe=lambda u, m: response)

    def test_worker_specific_404_body_is_required(self):
        url = "https://" + ALIAS + "/index.html"
        def response(body, code=404):
            return HTTPError(url, code, "status", {}, io.BytesIO(body))
        with mock.patch.object(bootstrap.urllib.request, "build_opener") as patched:
            opener = patched.return_value
            opener.open.side_effect = response(b"Not found")
            self.assertEqual(bootstrap.guest_status(url), 404)
            opener.open.side_effect = response(b"<html>this is an unprotected game</html>")
            self.assertEqual(bootstrap.guest_status(url), 599)
            opener.open.side_effect = response(b"Not found\n")
            self.assertEqual(bootstrap.guest_status(url), 599)
            opener.open.side_effect = response(b"game is available", code=200)
            self.assertEqual(bootstrap.guest_status(url), 200)
            opener.open.side_effect = response(b"", code=404)
            self.assertEqual(bootstrap.guest_status(url, "HEAD"), 404)


if __name__ == "__main__":
    unittest.main()
