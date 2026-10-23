import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_rollback_evidence as evidence
import staradvs_pages as pages

LIVE = "a" * 40
OLD = "b" * 40
SECOND = "c" * 40


def good_run(run_id=33):
    return {
        "id": run_id,
        "repository": {"full_name": evidence.OWNER},
        "path": evidence.WORKFLOW,
        "head_branch": "main",
        "head_sha": "d" * 40,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
    }


def receipt(sha=OLD, run_id=33, **overrides):
    value = {
        "id": 88,
        "name": "staradvs-staging-verified-" + sha,
        "expired": False,
        "size_in_bytes": 335,
        "workflow_run": {"id": run_id},
    }
    value.update(overrides)
    return value


def inventory(previous=None):
    return {
        "live_sha": LIVE,
        "potential_previous": previous if previous is not None else [
            {"source_sha": OLD, "deployment_id": "e233c23e-3b66-4184-8be2-7e32ea2d64a5",
             "created_on": "2026-10-23T10:00:00Z"}
        ],
    }


class FakeReader:
    def __init__(self, runs=None, artifacts=None):
        self.runs = runs if runs is not None else [good_run()]
        self.artifacts = artifacts if artifacts is not None else {33: [receipt()]}
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        if path == evidence.RUNS_PATH:
            return {"workflow_runs": self.runs}
        for rid, entries in self.artifacts.items():
            if path == f"/repos/{evidence.OWNER}/actions/runs/{rid}/artifacts?per_page=100":
                return {"artifacts": entries}
        raise AssertionError("Unexpected GitHub endpoint " + path)


class ReceiptAdmissionTests(unittest.TestCase):
    def test_valid_owned_github_release_receipt_correlates_with_pages_candidate(self):
        reader = FakeReader()
        result = evidence.corroborate(inventory(), reader)
        self.assertEqual(result["receipt_backed_previous"], [{
            **inventory()["potential_previous"][0],
            "infra_publish_run_id": 33,
            "verified_receipt_id": 88,
        }])
        self.assertEqual(len(reader.paths), 2)
        self.assertTrue(all(path.startswith("/repos/evilsysadmin/shadowops-infra/actions/")
                            for path in reader.paths))

    def test_only_completed_green_trusted_main_publisher_runs_count(self):
        invalid = [
            {"head_branch": "dev"}, {"conclusion": "failure"},
            {"status": "in_progress"}, {"path": ".github/workflows/evil.yml"},
            {"repository": {"full_name": "somebody/other"}},
            {"head_sha": "main"}, {"event": "pull_request"},
        ]
        for fields in invalid:
            with self.subTest(fields=fields):
                bad = {**good_run(), **fields}
                self.assertFalse(evidence.credible_run(bad))
                with self.assertRaisesRegex(pages.AdmissionError, "valid GitHub release receipt"):
                    evidence.corroborate(inventory(), FakeReader(runs=[bad]))

    def test_missing_expired_mismatched_or_zero_size_receipts_are_never_backed(self):
        invalid = [
            {"expired": True}, {"name": "staradvs-staging-verified-" + SECOND},
            {"workflow_run": {"id": 999}}, {"size_in_bytes": 0},
            {"name": "staradvs-staging-verified-" + OLD + "-fake"},
            {"id": 0},
        ]
        for fields in invalid:
            with self.subTest(fields=fields):
                bad = receipt(**fields)
                self.assertFalse(evidence.credible_receipt(bad, 33, OLD))
                with self.assertRaisesRegex(pages.AdmissionError, "valid GitHub release receipt"):
                    evidence.corroborate(inventory(), FakeReader(artifacts={33: [bad]}))

    def test_missing_or_foreign_candidates_block(self):
        for altered in (
            {"source_sha": LIVE},
            {"source_sha": "main"},
            {"source_sha": 123},
        ):
            bad = {**inventory()["potential_previous"][0], **altered}
            with self.assertRaisesRegex(pages.AdmissionError, "Untrusted rollback"):
                evidence.corroborate(inventory([bad]), FakeReader())

    def test_no_prior_candidate_means_no_fake_rollback_evidence(self):
        reader = FakeReader()
        result = evidence.corroborate(inventory([]), reader)
        self.assertEqual(result["receipt_backed_previous"], [])
        self.assertEqual(reader.paths, [evidence.RUNS_PATH])

    def test_github_client_is_get_only_and_allowlisted(self):
        reader = evidence.GitHubEvidence("test-token")
        with self.assertRaisesRegex(pages.AdmissionError, "Unexpected GitHub"):
            reader.get("/repos/evilsysadmin/star-adventures/actions/runs")
        with self.assertRaisesRegex(pages.AdmissionError, "Unexpected GitHub"):
            reader.get("/repos/evilsysadmin/shadowops-infra/actions/runs/33/dispatches")
        with self.assertRaisesRegex(pages.AdmissionError, "Missing GitHub"):
            evidence.GitHubEvidence("")


if __name__ == "__main__":
    unittest.main()
