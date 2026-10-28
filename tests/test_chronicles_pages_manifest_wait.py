"""A Pages deployment is certified only after public exact-SHA convergence."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from chronicles_pages_manifest_wait import wait_for_public_manifest

SHA = "a" * 40
OLD = "b" * 40


class ManifestConvergenceTest(unittest.TestCase):
    def test_stale_then_unavailable_then_exact_sha(self):
        urls, sleeps = [], []
        responses = iter([{"build": OLD}, ValueError("invalid JSON"), {"build": SHA, "release": "v1"}])

        def read(url):
            urls.append(url)
            value = next(responses)
            if isinstance(value, Exception):
                raise value
            return value

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "release.json"
            self.assertTrue(wait_for_public_manifest(
                SHA, "123", path, read=read, sleep=sleeps.append,
                attempts=4, delay_seconds=2))
            self.assertEqual(json.loads(path.read_text()), {"build": SHA, "release": "v1"})
        self.assertEqual(sleeps, [2, 2])
        self.assertEqual(len(urls), 3)
        self.assertTrue(all(url.startswith(
            "https://staging.chronicles.shadowops.dpdns.org/release.json?receipt_check=123-")
            for url in urls))
        self.assertEqual(len(set(urls)), 3)

    def test_permanent_stale_manifest_fails_closed_without_receipt(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "release.json"
            self.assertFalse(wait_for_public_manifest(
                SHA, 42, path, read=lambda url: {"build": OLD},
                sleep=calls.append, attempts=3, delay_seconds=1))
            self.assertFalse(path.exists())
        self.assertEqual(calls, [1, 1])

    def test_outage_fails_closed_without_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "release.json"
            self.assertFalse(wait_for_public_manifest(
                SHA, 42, path, read=lambda url: (_ for _ in ()).throw(TimeoutError()),
                sleep=lambda _: None, attempts=2, delay_seconds=0))
            self.assertFalse(path.exists())

    def test_staging_workflow_waits_before_browser_and_receipt(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/chronicles-pages-release.yml").read_text()
        staging = workflow.split("\n  production:\n", 1)[0]
        proof = staging.index("python3 scripts/chronicles_pages_manifest_wait.py")
        browser = staging.index("Real public browser smoke")
        receipt = staging.index("Record the verified Chronicles Pages source generation")
        self.assertLess(proof, browser)
        self.assertLess(browser, receipt)
        self.assertIn("EXPECTED_SHA: ${{ steps.source.outputs.sha }}", staging)

    def test_invalid_inputs_never_request_public_host(self):
        for sha, run_id, attempts in (
            ("not-a-sha", "42", 2), (SHA, "0", 2),
            (SHA, "not-a-run", 2), (SHA, "42", 0),
        ):
            with self.subTest(sha=sha, run_id=run_id, attempts=attempts):
                with self.assertRaises(ValueError):
                    wait_for_public_manifest(
                        sha, run_id, "/unused", attempts=attempts,
                        read=lambda _: self.fail("invalid configuration made HTTP request"))


if __name__ == "__main__":
    unittest.main()
