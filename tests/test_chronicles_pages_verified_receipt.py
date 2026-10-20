"""Trust only a successful Pages receipt whose SHA still matches live HTTPS."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_pages_verified_receipt as gate

SHA = "a" * 40
TOKEN = "test-token"


def receipt(*, sha=SHA, run_id=123, expired=False, branch="main"):
    return {"name": "chronicles-pages-staging-" + sha,
            "expired": expired,
            "workflow_run": {"id": run_id, "head_branch": branch}}


def run(**overrides):
    data = {"id": 123, "status": "completed", "conclusion": "success",
            "path": gate.PAGES_WORKFLOW, "head_branch": "main",
            "repository": {"full_name": gate.INFRA}, "event": "schedule"}
    data.update(overrides)
    return data


class PagesVerifiedReceipt(unittest.TestCase):
    def test_only_successful_matching_workflow_receipt_is_trusted(self):
        listing = {"artifacts": [receipt()]}
        self.assertTrue(gate.receipt_ok(SHA, listing, lambda _: run()))
        for invalid in (
            run(conclusion="failure"), run(status="in_progress"),
            run(path=".github/workflows/chronicles-api-staging.yml"),
            run(head_branch="feature"), run(repository={"full_name": "fork/repo"}),
            run(event="pull_request"), run(id=999),
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(gate.receipt_ok(SHA, listing, lambda _: invalid))
        for invalid in (receipt(expired=True), receipt(branch="feature"),
                        receipt(sha="b" * 40), receipt(run_id=0)):
            with self.subTest(invalid=invalid):
                self.assertFalse(gate.receipt_ok(SHA, {"artifacts": [invalid]}, lambda _: run()))
        with self.assertRaises(gate.GateError):
            gate.receipt_ok(SHA, {}, lambda _: run())

    def test_skip_needs_verified_receipt_and_live_manifest(self):
        calls = []
        def get(path, token):
            calls.append((path, token))
            return {"artifacts": [receipt()]} if "/artifacts?" in path else run()
        public_calls = []
        def public(url):
            public_calls.append(url)
            return {"release": "v1", "build": SHA}
        self.assertTrue(gate.verified_live(SHA, TOKEN, get=get, public=public))
        self.assertEqual(len(public_calls), 1)
        self.assertIn("/release.json?receipt_check=", public_calls[0])
        self.assertTrue(all(token == TOKEN for _, token in calls))

    def test_live_drift_or_outage_triggers_republish(self):
        def get(path, token):
            return {"artifacts": [receipt()]} if "/artifacts?" in path else run()
        self.assertFalse(gate.verified_live(SHA, TOKEN, get=get,
                                            public=lambda _: {"build": "b" * 40}))
        self.assertFalse(gate.verified_live(SHA, TOKEN, get=get, public=lambda _: {}))
        def offline(_):
            raise TimeoutError("public Pages unavailable")
        self.assertFalse(gate.verified_live(SHA, TOKEN, get=get, public=offline))

    def test_live_only_probe_reuses_public_sha_check_without_receipt(self):
        self.assertTrue(gate.live_matches(SHA, public=lambda _: {"build": SHA}))
        self.assertFalse(gate.live_matches(SHA, public=lambda _: {"build": "b" * 40}))
        self.assertFalse(gate.live_matches(SHA, public=lambda _: {"release": "old"}))
        def unreachable(_):
            raise TimeoutError("public HTTPS not responding")
        self.assertFalse(gate.live_matches(SHA, public=unreachable))
        with self.assertRaises(gate.GateError):
            gate.live_matches("not-a-sha", public=lambda _: {"build": SHA})

    def test_absent_or_untrusted_receipt_never_consults_live_site(self):
        def get(path, token):
            return {"artifacts": []} if "/artifacts?" in path else run()
        def must_not_read(_):
            raise AssertionError("live check requires trusted receipt first")
        self.assertFalse(gate.verified_live(SHA, TOKEN, get=get, public=must_not_read))
        with self.assertRaises(gate.GateError):
            gate.verified_live(SHA, "")
        with self.assertRaises(gate.GateError):
            gate.verified_live("bogus", TOKEN)


if __name__ == "__main__":
    unittest.main()
