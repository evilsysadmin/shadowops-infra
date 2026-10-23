import importlib.util
import pathlib
import unittest

path = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "staradvs_source_admission.py"
spec = importlib.util.spec_from_file_location("staradvs_source_admission", path)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
SHA = "a" * 40


class Reader:
    def __init__(self, current=SHA, run="success", missing=None,
                 job_status="completed", job_completed_at="2026-10-23T10:14:51Z"):
        self.current = current
        self.run = run
        self.missing = missing
        self.job_status = job_status
        self.job_completed_at = job_completed_at
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        if path.endswith("/commits/main"):
            return {"sha": self.current}
        if "/actions/workflows/" in path:
            return {"workflow_runs": [{
                "id": 987, "head_sha": SHA, "head_branch": "main",
                "event": "push", "status": "completed", "conclusion": self.run,
            }]}
        if path.endswith("/actions/runs/987/jobs?per_page=100"):
            names = app.NEEDED - ({self.missing} if self.missing else set())
            return {"jobs": [{"name": name, "status": self.job_status,
                              "conclusion": "success", "completed_at": self.job_completed_at}
                             for name in names]}
        raise AssertionError("Unexpected GitHub API request " + path)


class SourceAdmissionTests(unittest.TestCase):
    def test_source_ci_exact_sha_and_both_jobs_green(self):
        reader = Reader()
        self.assertEqual(app.admit(reader, SHA), 987)
        self.assertEqual(len(reader.paths), 3)
        self.assertTrue(all(path.startswith("/repos/evilsysadmin/star-adventures/") for path in reader.paths))

    def test_wrong_source_sha_refused_even_when_historic_ci_was_green(self):
        reader = Reader(current="b" * 40)
        with self.assertRaisesRegex(app.SourceAdmissionError, "not current"):
            app.admit(reader, SHA)
        self.assertEqual(len(reader.paths), 1)

    def test_pending_or_failed_ci_refused(self):
        for state in ("failure", "cancelled", None):
            with self.assertRaisesRegex(app.SourceAdmissionError, "not yet green"):
                app.admit(Reader(run=state), SHA)

    def test_missing_chrome_or_core_ci_refused(self):
        for name in app.NEEDED:
            with self.assertRaisesRegex(app.SourceAdmissionError, "not yet green"):
                app.admit(Reader(missing=name), SHA)

    def test_completed_green_run_admits_job_with_stale_in_progress_status(self):
        # Observed on source main run 39937715178: core job had a genuine
        # completed_at and success conclusion, but status still in_progress.
        reader = Reader(job_status="in_progress")
        self.assertEqual(app.admit(reader, SHA), 987)

    def test_status_disagreement_never_admits_unfinished_or_queued_job(self):
        for status, completed_at in (
            ("in_progress", None),
            ("queued", "2026-10-23T10:14:51Z"),
            ("completed", None),
        ):
            with self.subTest(status=status, completed_at=completed_at):
                with self.assertRaisesRegex(app.SourceAdmissionError, "not yet green"):
                    app.admit(Reader(job_status=status, job_completed_at=completed_at), SHA)

    def test_unsafe_sha_or_empty_credential_refused(self):
        for sha in ("main", "", "z" * 40, "a" * 39):
            with self.assertRaisesRegex(app.SourceAdmissionError, "full source SHA"):
                app.admit(Reader(), sha)
        with self.assertRaisesRegex(app.SourceAdmissionError, "required"):
            app.GithubReader("")


if __name__ == "__main__":
    unittest.main()
