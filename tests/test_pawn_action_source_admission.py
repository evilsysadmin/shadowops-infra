"""Offline acceptance and rejection tests for Pawn Action source admission."""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_source_admission as gate

SHA = "a" * 40

class Reader:
    def __init__(self):
        self.head = SHA
        self.run = {"id": 42, "head_sha": SHA, "head_branch": "main",
                    "event": "push", "status": "completed", "conclusion": "success"}
        self.job = {"name": gate.JOB, "status": "completed", "conclusion": "success",
                    "completed_at": "2026-11-03T10:00:00Z",
                    "steps": [{"name": x, "status": "completed", "conclusion": "success"}
                              for x in gate.STEPS]}
        self.artifacts = [
            {"name": name, "id": i + 1, "size_in_bytes": 12500,
             "expired": False, "digest": "sha256:" + chr(97 + i) * 64}
            for i, name in enumerate(gate.ARTIFACTS)]
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if path.endswith("/commits/main"):
            return {"sha": self.head}
        if "/actions/workflows/" in path and "/runs?" in path:
            return {"workflow_runs": [self.run]}
        if path.endswith("/jobs?per_page=100"):
            return {"jobs": [self.job]}
        if path.endswith("/artifacts?per_page=100"):
            return {"artifacts": self.artifacts}
        raise AssertionError(path)

def make_zip(files=None, symlink=False):
    files = files or {name: b"bytes" for name in gate.REQUIRED}
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as z:
        for name, raw in files.items():
            if symlink and name == "index.js":
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (0o120777 << 16)
                z.writestr(info, raw)
            else:
                z.writestr(name, raw)
    return data.getvalue()

class PawnAdmissionTests(unittest.TestCase):
    def test_success_is_exact_main_push_with_real_browser_and_two_artifacts(self):
        reader = Reader()
        receipt = gate.admit(reader, SHA)
        self.assertEqual((receipt["run_id"], receipt["artifact_id"]), (42, 1))
        self.assertEqual(receipt["source_sha"], SHA)
        self.assertEqual(len(reader.calls), 5)
        self.assertTrue(all(x.startswith("/repos/" + gate.REPO + "/") for x in reader.calls))

    def test_main_and_full_sha_are_mandatory(self):
        for bad in ("", "a" * 7, "A" * 40, "a" * 39, "bad"):
            with self.subTest(bad=bad), self.assertRaises(gate.AdmissionError):
                gate.admit(Reader(), bad)
        reader = Reader()
        reader.head = "b" * 40
        with self.assertRaises(gate.AdmissionError):
            gate.admit(reader, SHA)

    def test_wrong_event_or_incomplete_run_never_admitted(self):
        for fault in ("pr", "dispatch", "pending", "red", "branch", "head"):
            reader = Reader()
            if fault == "pr":
                reader.run["event"] = "pull_request"
            elif fault == "dispatch":
                reader.run["event"] = "workflow_dispatch"
            elif fault == "pending":
                reader.run["status"] = "in_progress"
            elif fault == "red":
                reader.run["conclusion"] = "failure"
            elif fault == "branch":
                reader.run["head_branch"] = "migration/standalone-godot"
            elif fault == "head":
                reader.run["head_sha"] = "b" * 40
            with self.subTest(fault=fault), self.assertRaises(gate.AdmissionError):
                gate.admit(reader, SHA)

    def test_browser_or_export_skipped_blocks_even_successful_job(self):
        for required_step in gate.STEPS:
            reader = Reader()
            for step in reader.job["steps"]:
                if step["name"] == required_step:
                    step["conclusion"] = "skipped"
            with self.subTest(step=required_step), self.assertRaises(gate.AdmissionError):
                gate.admit(reader, SHA)
        reader = Reader()
        reader.job["status"] = "in_progress"
        with self.assertRaises(gate.AdmissionError):
            gate.admit(reader, SHA)

    def test_missing_expired_duplicated_or_unauthenticated_artifacts_rejected(self):
        for fault in ("missing", "expired", "duplicate", "digest", "id", "size"):
            reader = Reader()
            artifact = reader.artifacts[0]
            if fault == "missing":
                reader.artifacts.remove(artifact)
            elif fault == "expired":
                artifact["expired"] = True
            elif fault == "duplicate":
                reader.artifacts.append(dict(artifact))
            elif fault == "digest":
                artifact["digest"] = "broken"
            elif fault == "id":
                artifact["id"] = 0
            else:
                artifact["size_in_bytes"] = -1
            with self.subTest(fault=fault), self.assertRaises(gate.AdmissionError):
                gate.admit(reader, SHA)

    def test_zip_exact_digest_and_godot_entries(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "web.zip"
            blob = make_zip()
            path.write_bytes(blob)
            digest = "sha256:" + hashlib.sha256(blob).hexdigest()
            self.assertEqual(gate.verify_archive(path, digest)["files"], 4)
            for bad in ("sha256:" + "0" * 64, "bad"):
                with self.assertRaises(gate.AdmissionError):
                    gate.verify_archive(path, bad)
            path.write_bytes(blob[:-4])
            with self.assertRaises(gate.AdmissionError):
                gate.verify_archive(path, "sha256:" + hashlib.sha256(blob[:-4]).hexdigest())

    def test_zip_path_traversal_missing_wasm_and_symlink_rejected(self):
        bad = [
            {"index.html": b"a", "index.js": b"b", "index.pck": b"c",
             "../index.wasm": b"evil"},
            {"index.html": b"a", "index.js": b"b", "index.pck": b"c",
             "other.png": b"no wasm"},
            {"index.html": b"a", "index.js": b"b", "index.pck": b"c",
             r"folder\index.wasm": b"evil"},
        ]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "web.zip"
            for entries in bad:
                blob = make_zip(entries)
                path.write_bytes(blob)
                with self.assertRaises(gate.AdmissionError):
                    gate.verify_archive(path, "sha256:" + hashlib.sha256(blob).hexdigest())
            blob = make_zip(symlink=True)
            path.write_bytes(blob)
            with self.assertRaises(gate.AdmissionError):
                gate.verify_archive(path, "sha256:" + hashlib.sha256(blob).hexdigest())

if __name__ == "__main__":
    unittest.main()
