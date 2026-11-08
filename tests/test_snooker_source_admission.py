import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_source_admission as admission


SHA = "a" * 40
REPO = admission.SOURCE
RUN_ID = 17
PREFIX = f"/repos/{REPO}"
RUNS = PREFIX + "/actions/workflows/ci.yml/runs?" + urlencode({
    "head_sha": SHA, "branch": "main", "event": "push", "per_page": 50})
JOBS = PREFIX + f"/actions/runs/{RUN_ID}/jobs?per_page=100"
ARTIFACTS = PREFIX + f"/actions/runs/{RUN_ID}/artifacts?per_page=100"


def fixtures():
    return {
        PREFIX + "/commits/main": {"sha": SHA},
        RUNS: {"workflow_runs": [{
            "id": RUN_ID, "head_sha": SHA, "head_branch": "main",
            "event": "push", "status": "completed", "conclusion": "success",
        }]},
        JOBS: {"jobs": [{
            "name": "verify", "status": "completed", "conclusion": "success",
            "completed_at": "2026-11-08T23:00:00Z",
            "steps": [{"name": name, "status": "completed", "conclusion": "success"}
                      for name in admission.REQUIRED_STEPS],
        }]},
        ARTIFACTS: {"artifacts": [{
            "id": 88, "name": admission.ARTIFACT, "expired": False,
            "size_in_bytes": 1024, "digest": "sha256:" + "b" * 64,
        }]},
    }


class FakeReader:
    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, path):
        if path not in self.mapping:
            raise AssertionError("Unexpected GitHub request: " + path)
        return self.mapping[path]


def make_zip(entries):
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_DEFLATED) as writer:
        for name, data in entries.items():
            writer.writestr(name, data)
    return memory.getvalue()


class SnookerAdmissionTests(unittest.TestCase):
    def test_admits_exact_green_push_artifact(self):
        self.assertEqual(admission.admit(FakeReader(fixtures()), SHA), {
            "source_sha": SHA, "run_id": RUN_ID, "artifact_id": 88,
            "artifact_digest": "sha256:" + "b" * 64,
        })

    def test_stale_main_fails_closed(self):
        mapping = fixtures()
        mapping[PREFIX + "/commits/main"] = {"sha": "c" * 40}
        with self.assertRaises(admission.AdmissionError):
            admission.admit(FakeReader(mapping), SHA)

    def test_pull_request_success_cannot_authorize_staging(self):
        mapping = fixtures()
        mapping[RUNS]["workflow_runs"][0]["event"] = "pull_request"
        with self.assertRaises(admission.AdmissionError):
            admission.admit(FakeReader(mapping), SHA)

    def test_browser_smoke_or_artifact_upload_skipped_is_rejected(self):
        for missing in ("Exercise desktop and mobile 3D browser",
                        "Attach Cloudflare Pages-ready dist (not a deployment)"):
            mapping = fixtures()
            mapping[JOBS]["jobs"][0]["steps"] = [
                s for s in mapping[JOBS]["jobs"][0]["steps"] if s["name"] != missing]
            with self.subTest(step=missing), self.assertRaises(admission.AdmissionError):
                admission.admit(FakeReader(mapping), SHA)

    def test_artifact_digest_expiry_and_uniqueness_are_mandatory(self):
        for change in ({"expired": True}, {"digest": "missing"}, {"size_in_bytes": 0}):
            mapping = fixtures()
            mapping[ARTIFACTS]["artifacts"][0].update(change)
            with self.subTest(change=change), self.assertRaises(admission.AdmissionError):
                admission.admit(FakeReader(mapping), SHA)
        mapping = fixtures()
        mapping[ARTIFACTS]["artifacts"].append(dict(mapping[ARTIFACTS]["artifacts"][0]))
        with self.assertRaises(admission.AdmissionError):
            admission.admit(FakeReader(mapping), SHA)

    def test_zip_uses_exact_digest_and_has_only_bounded_static_assets(self):
        binary = make_zip({"index.html": "<html></html>", "assets/game.js": "console.log(1)"})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.zip"
            path.write_bytes(binary)
            digest = "sha256:" + hashlib.sha256(binary).hexdigest()
            self.assertEqual(admission.verify_archive(path, digest)["files"], 2)
            with self.assertRaises(admission.AdmissionError):
                admission.verify_archive(path, "sha256:" + "0" * 64)

    def test_zip_rejects_traversal_worker_symlink_and_missing_js(self):
        for entries in (
            {"index.html": "x", "../escape.js": "x", "assets/game.js": "x"},
            {"index.html": "x", "_worker.js": "public bypass", "assets/game.js": "x"},
            {"index.html": "x", "assets/note.txt": "x"},
        ):
            binary = make_zip(entries)
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "artifact.zip"
                path.write_bytes(binary)
                with self.subTest(entries=entries), self.assertRaises(admission.AdmissionError):
                    admission.verify_archive(path, "sha256:" + hashlib.sha256(binary).hexdigest())


if __name__ == "__main__":
    unittest.main()
