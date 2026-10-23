import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_forward_baseline as forward
import staradvs_pages as pages

SHA = "a" * 40
PROJECT_ID = "4092240d-fdbb-4c7d-8f33-11a103f9c999"
URL = "https://4092240d.staradvs-staging.pages.dev"


def deployment(sha=SHA, **changes):
    d = {
        "id": PROJECT_ID,
        "project_name": pages.PROJECT,
        "environment": "production",
        "latest_stage": {"status": "success"},
        "deployment_trigger": {"metadata": {
            "branch": "main", "commit_hash": sha, "commit_dirty": False,
        }},
        "created_on": "2026-10-23T12:00:00Z",
        "url": URL,
    }
    d.update(changes)
    return d


class Cloudflare:
    account = "f" * 32
    def __init__(self, deployment_row=None, **project_changes):
        self.calls = []
        self.project = {
            "name": pages.PROJECT,
            "production_branch": "main",
            "canonical_deployment": deployment() if deployment_row is None else deployment_row,
        }
        self.project.update(project_changes)

    def request(self, method, path):
        self.calls.append((method, path))
        expected = f"/accounts/{self.account}/pages/projects/{pages.PROJECT}"
        if method != "GET" or path != expected:
            raise AssertionError("Unexpected Pages API operation")
        return 200, self.project


def run(runid=37):
    return {
        "id": runid,
        "repository": {"full_name": forward.OWNER},
        "path": ".github/workflows/staradvs-pages-staging.yml",
        "head_branch": "main",
        "head_sha": "b" * 40,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
    }


def artifact(sha=SHA, runid=37, **changes):
    value = {
        "id": 72,
        "name": "staradvs-staging-verified-" + sha,
        "workflow_run": {"id": runid},
        "expired": False,
        "size_in_bytes": 123,
    }
    value.update(changes)
    return value


class Reader:
    def __init__(self, runs=None, artifacts=None):
        self.runs = [run()] if runs is None else runs
        self.artifacts = [artifact()] if artifacts is None else artifacts
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if path == forward.RUNS_PATH:
            return {"workflow_runs": self.runs}
        if path == f"/repos/{forward.OWNER}/actions/runs/37/artifacts?per_page=100":
            return {"artifacts": self.artifacts}
        raise AssertionError("Unexpected history endpoint")


class BaselineTests(unittest.TestCase):
    def test_canonical_current_deployment_has_exact_owned_successful_main_source(self):
        cf = Cloudflare()
        with patch.object(forward, "verify_immutable_target", return_value=URL) as proof:
            result = forward.canonical_forward(cf, SHA)
        self.assertEqual(result, {
            "forward_deployment_id": PROJECT_ID,
            "forward_sha": SHA,
            "forward_immutable_url": URL,
        })
        proof.assert_called_once()
        self.assertEqual([method for method, _ in cf.calls], ["GET"])

    def test_reject_foreign_project_preview_dirty_fail_or_wrong_sha(self):
        variants = [
            Cloudflare(name="foreign"),
            Cloudflare(production_branch="dev"),
            Cloudflare(deployment_row=deployment("c" * 40)),
            Cloudflare(deployment_row=deployment(environment="preview")),
            Cloudflare(deployment_row=deployment(project_name="foreign")),
            Cloudflare(deployment_row=deployment(latest_stage={"status": "failure"})),
            Cloudflare(deployment_row=deployment(deployment_trigger={"metadata": {
                "branch": "main", "commit_hash": SHA, "commit_dirty": True,
            }})),
            Cloudflare(deployment_row={}),
        ]
        for cf in variants:
            with self.subTest(project=cf.project):
                with patch.object(forward, "verify_immutable_target") as proof:
                    with self.assertRaises(pages.AdmissionError):
                        forward.canonical_forward(cf, SHA)
                    proof.assert_not_called()
                self.assertTrue(all(method == "GET" for method, _ in cf.calls))

    def test_missing_or_expired_release_receipt_does_not_approve_forward(self):
        bad = [
            artifact(expired=True),
            artifact(name="staradvs-staging-verified-" + "c" * 40),
            artifact(workflow_run={"id": 80}),
            artifact(size_in_bytes=0),
        ]
        for a in bad:
            with self.subTest(artifact=a):
                with self.assertRaisesRegex(pages.AdmissionError, "lacks unexpired"):
                    forward.forward_release_receipt(Reader(artifacts=[a]), SHA)

    def test_trusted_main_successful_history_is_required(self):
        for change in [
            {"conclusion": "failure"},
            {"event": "pull_request"},
            {"repository": {"full_name": "foreign/repo"}},
            {"head_branch": "feature"},
        ]:
            with self.subTest(change=change):
                with self.assertRaisesRegex(pages.AdmissionError, "lacks unexpired"):
                    forward.forward_release_receipt(Reader(runs=[{**run(), **change}]), SHA)

    def test_actual_current_receipt_is_trusted_and_bound_to_release_run(self):
        reader = Reader()
        result = forward.forward_release_receipt(reader, SHA)
        self.assertEqual(result, {
            "forward_publish_run_id": 37,
            "forward_receipt_id": 72,
        })
        self.assertEqual(len(reader.calls), 2)
        self.assertEqual(reader.calls[0], forward.RUNS_PATH)


if __name__ == "__main__":
    unittest.main()
