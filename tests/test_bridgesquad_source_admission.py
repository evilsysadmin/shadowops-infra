import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bridgesquad_source_admission as source

SHA = "a" * 40
RUN = 19
ROOT = f"/repos/{source.SOURCE}"
MAIN = ROOT + "/commits/main"
RUNS = ROOT + "/actions/workflows/pages.yml/runs?" + urlencode({
    "head_sha": SHA, "branch": "main", "event": "push", "per_page": 50,
})
JOBS = ROOT + f"/actions/runs/{RUN}/jobs?per_page=100"
ARTIFACTS = ROOT + f"/actions/runs/{RUN}/artifacts?per_page=100"
HTML = b'<!doctype html><html lang="es"><head><title>Matthias Bridge Squad - ShadowOps</title></head><body>Bridge</body></html>'


def evidence():
    return {
        MAIN: {"sha": SHA},
        RUNS: {"workflow_runs": [{
            "id": RUN, "head_sha": SHA, "head_branch": "main", "event": "push",
            "status": "completed", "conclusion": "success",
            "head_repository": {"full_name": source.SOURCE},
        }]},
        JOBS: {"jobs": [{
            "name": name, "status": "completed", "conclusion": "success",
            "completed_at": "2026-11-17T20:00:00Z",
            "steps": [{"name": step, "status": "completed", "conclusion": "success"}
                      for step in required],
        } for name, required in source.JOBS.items()]},
        ARTIFACTS: {"artifacts": [{
            "id": 88, "name": source.ARTIFACT_PREFIX + SHA, "expired": False,
            "size_in_bytes": 17000, "digest": "sha256:" + "b" * 64,
            "workflow_run": {"id": RUN, "head_sha": SHA, "head_branch": "main"},
        }]},
    }


class Reader:
    def __init__(self, mapping):
        self.data = mapping
        self.main_reads = 0

    def get(self, path):
        if path not in self.data:
            raise AssertionError("Unexpected GitHub source path " + path)
        if path == MAIN:
            self.main_reads += 1
        return self.data[path]


def manifest():
    return {"schema": 1, "application": "matthias-bridge-squad",
            "environment": "production", "source_repository": source.SOURCE,
            "source_sha": SHA, "authentication": {
                "provider": "shadowops-id", "audience": "bridgesquad", "required": True,
            }, "files": {"index.html": {
                "sha256": hashlib.sha256(HTML).hexdigest(), "bytes": len(HTML),
            }}}


def archive(entries):
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return memory.getvalue()


def zipped(m=None, html=HTML):
    return archive([
        ("index.html", html),
        ("release.json", json.dumps(manifest() if m is None else m).encode()),
    ])


def verify_bytes(data, sha=SHA):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "candidate.zip"
        p.write_bytes(data)
        return source.verify_archive(p, "sha256:" + hashlib.sha256(data).hexdigest(), sha)


class BridgeSquadAdmissionTests(unittest.TestCase):
    def test_exact_source_main_green_push_and_unique_artifact(self):
        reader = Reader(evidence())
        result = source.admit(reader, SHA)
        self.assertEqual(reader.main_reads, 2)
        self.assertEqual(result["source_sha"], SHA)
        self.assertEqual(result["run_id"], RUN)
        self.assertEqual(result["artifact_id"], 88)
        self.assertEqual(result["artifact_name"], source.ARTIFACT_PREFIX + SHA)
        self.assertEqual(result["artifact_digest"], "sha256:" + "b"*64)

    def test_wrong_source_or_stale_main_is_denied(self):
        for change in ({"head_branch": "dev"}, {"event": "pull_request"},
                       {"head_sha": "c"*40}, {"conclusion": "failure"},
                       {"status": "in_progress"},
                       {"head_repository": {"full_name": "attacker/game"}}):
            data = evidence()
            data[RUNS]["workflow_runs"][0].update(change)
            with self.subTest(change=change), self.assertRaises(source.AdmissionError):
                source.admit(Reader(data), SHA)
        data = evidence()
        data[MAIN] = {"sha": "c"*40}
        with self.assertRaises(source.AdmissionError):
            source.admit(Reader(data), SHA)
        with self.assertRaises(source.AdmissionError):
            source.admit(Reader(evidence()), "../HEAD")

    def test_main_moves_during_admission(self):
        class MovingReader(Reader):
            def get(self, path):
                result = super().get(path)
                return {"sha": "c"*40} if path == MAIN and self.main_reads > 1 else result
        with self.assertRaises(source.AdmissionError):
            source.admit(MovingReader(evidence()), SHA)

    def test_skipped_job_or_required_step_and_duplicates_fail(self):
        for job_name in source.JOBS:
            data = evidence()
            next(j for j in data[JOBS]["jobs"] if j["name"] == job_name)["conclusion"] = "skipped"
            with self.subTest(job_name=job_name), self.assertRaises(source.AdmissionError):
                source.admit(Reader(data), SHA)
            data = evidence()
            data[JOBS]["jobs"] = [j for j in data[JOBS]["jobs"] if j["name"] != job_name]
            with self.assertRaises(source.AdmissionError):
                source.admit(Reader(data), SHA)
            data = evidence()
            target = next(j for j in data[JOBS]["jobs"] if j["name"] == job_name)
            target["steps"][0]["conclusion"] = "skipped"
            with self.assertRaises(source.AdmissionError):
                source.admit(Reader(data), SHA)
        for path, field in ((JOBS, "jobs"), (ARTIFACTS, "artifacts")):
            data = evidence()
            data[path][field].append(copy.deepcopy(data[path][field][0]))
            with self.subTest(path=path), self.assertRaises(source.AdmissionError):
                source.admit(Reader(data), SHA)

    def test_artifact_expiry_digest_identity_and_size_fail(self):
        for change in (
            {"expired": True}, {"digest": "bad"}, {"digest": "sha256:"+ "C"*64},
            {"size_in_bytes": 0}, {"size_in_bytes": 3_000_000},
            {"id": True}, {"name": "bridgesquad-private-release-"+"c"*40},
            {"workflow_run": {"id":RUN+1, "head_sha":SHA, "head_branch":"main"}},
            {"workflow_run": {"id":RUN, "head_sha":"c"*40, "head_branch":"main"}},
        ):
            data = evidence()
            data[ARTIFACTS]["artifacts"][0].update(change)
            with self.subTest(change=change), self.assertRaises(source.AdmissionError):
                source.admit(Reader(data), SHA)

    def test_exact_release_archive_and_html_digest(self):
        data = zipped()
        result = verify_bytes(data)
        self.assertEqual(result["html_sha256"], hashlib.sha256(HTML).hexdigest())
        self.assertEqual(result["html_bytes"], len(HTML))
        self.assertEqual(result["authentication"], "required")
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"release.zip";p.write_bytes(data)
            with self.assertRaises(source.AdmissionError):
                source.verify_archive(p, "sha256:"+"0"*64, SHA)

    def test_reject_cross_environment_wrong_audience_wrong_sha_and_manifest(self):
        for update in (
            {"environment":"staging"}, {"application":"snooker-of-matthias"},
            {"source_sha":"c"*40}, {"source_repository":"other/owner"},
            {"authentication":{"provider":"shadowops-id","audience":"snooker","required":True}},
            {"authentication":{"provider":"shadowops-id","audience":"bridgesquad","required":False}},
            {"files":{"index.html":{"sha256":"0"*64, "bytes":len(HTML)}}},
            {"files":{"index.html":{"sha256":hashlib.sha256(HTML).hexdigest(), "bytes":len(HTML)+1}}},
            {"files":{}}, {"schema": True}, {"extra":"forbidden"},
        ):
            m = manifest()
            m.update(update)
            with self.subTest(update=update), self.assertRaises(source.AdmissionError):
                verify_bytes(zipped(m))

    def test_extra_worker_duplicate_names_bad_json_and_traversal_fail(self):
        for entries in (
            [("index.html",HTML),("release.json",b'{"schema":1,"schema":1}')],
            [("index.html",HTML),("release.json",json.dumps(manifest())),("_worker.js", "bad")],
            [("index.html",HTML),("index.html",HTML)],
            [("index.html",HTML),("../escape",b"x")],
            [("index.html",HTML),("release.json",b"not json")],
        ):
            with self.subTest(entries=[x[0] for x in entries]), self.assertRaises(source.AdmissionError):
                verify_bytes(archive(entries))

    def test_unrelated_html_and_oversized_manifest_fail(self):
        for html in (b"bad", b"\xff"*200, b'<!doctype html><title>Other game</title>'):
            with self.subTest(html=html[:20]), self.assertRaises(source.AdmissionError):
                verify_bytes(zipped(html=html))
        with self.assertRaises(source.AdmissionError):
            verify_bytes(archive([("index.html",HTML),("release.json",b" "*10000)]))


if __name__ == "__main__":
    unittest.main()
