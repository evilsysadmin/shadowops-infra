#!/usr/bin/env python3
"""Read-only exact-SHA admission for Pawn Action staging; no Cloudflare writes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPO = "evilsysadmin/pawn-action"
WORKFLOW = "godot-web.yml"
JOB = "Godot · gates, gameplay, 4 stages and Web export"
STEPS = {"Export standalone Web build", "Capture real Pawn Action gameplay and mobile input in Chromium"}
ARTIFACTS = ("pawn-action-godot-web", "pawn-action-real-visual-evidence")
REQUIRED = {"index.html", "index.js", "index.wasm", "index.pck"}
SHA = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
MAX_ZIP = 128 * 1024**2
MAX_EXPANDED = 256 * 1024**2

class AdmissionError(ValueError):
    pass

class GithubReader:
    def __init__(self, token):
        if not token:
            raise AdmissionError("GH_TOKEN required for source CI evidence")
        self.token = token

    def get(self, path):
        if not path.startswith("/repos/" + REPO + "/") or ".." in path or "//" in path:
            raise AdmissionError("GitHub API path outside Pawn Action allowlist")
        request = urllib.request.Request(
            "https://api.github.com" + path,
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status != 200:
                    raise AdmissionError("Unexpected source API status")
                return json.loads(response.read(2_000_000))
        except (urllib.error.URLError, ValueError, UnicodeError) as exc:
            raise AdmissionError("Source CI evidence unavailable: " + type(exc).__name__) from None

def _main(reader):
    value = reader.get("/repos/" + REPO + "/commits/main")
    if not isinstance(value, dict) or not isinstance(value.get("sha"), str):
        raise AdmissionError("Cannot verify current Pawn Action main")
    return value["sha"]

def _select_artifact(artifacts, name):
    matching = [x for x in artifacts if isinstance(x, dict) and x.get("name") == name]
    if len(matching) != 1:
        raise AdmissionError("Exactly one source artifact required: " + name)
    item = matching[0]
    if (item.get("expired") is not False
            or type(item.get("id")) is not int or item["id"] <= 0
            or type(item.get("size_in_bytes")) is not int
            or not 0 < item["size_in_bytes"] <= MAX_ZIP
            or not isinstance(item.get("digest"), str)
            or not DIGEST.fullmatch(item["digest"])):
        raise AdmissionError("Source artifact is expired or lacks an authenticated digest: " + name)
    return item

def admit(reader, sha):
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise AdmissionError("Exact lowercase 40-hex source SHA required")
    if _main(reader) != sha:
        raise AdmissionError("Candidate is not current Pawn Action main")
    query = urllib.parse.urlencode({"head_sha": sha, "branch": "main", "event": "push", "per_page": 50})
    result = reader.get(f"/repos/{REPO}/actions/workflows/{WORKFLOW}/runs?" + query)
    runs = result.get("workflow_runs") if isinstance(result, dict) else None
    if not isinstance(runs, list):
        raise AdmissionError("Source workflow inventory malformed")
    for run in runs:
        if not (isinstance(run, dict) and run.get("head_sha") == sha
                and run.get("head_branch") == "main" and run.get("event") == "push"
                and run.get("status") == "completed" and run.get("conclusion") == "success"
                and type(run.get("id")) is int and run["id"] > 0):
            continue
        rid = run["id"]
        jobs_data = reader.get(f"/repos/{REPO}/actions/runs/{rid}/jobs?per_page=100")
        jobs = jobs_data.get("jobs") if isinstance(jobs_data, dict) else None
        if not isinstance(jobs, list) or len(jobs) != 1:
            raise AdmissionError("Expected one complete Godot CI job")
        job = jobs[0]
        if (not isinstance(job, dict) or job.get("name") != JOB
                or job.get("status") != "completed" or job.get("conclusion") != "success"
                or not job.get("completed_at")):
            raise AdmissionError("Godot CI job is incomplete")
        steps = job.get("steps")
        if not isinstance(steps, list):
            raise AdmissionError("Godot CI steps unavailable")
        passed = {s.get("name") for s in steps if isinstance(s, dict)
                  and s.get("status") == "completed" and s.get("conclusion") == "success"}
        if not STEPS.issubset(passed):
            raise AdmissionError("Chromium input/visual or Godot export was skipped on main")
        artifacts_data = reader.get(f"/repos/{REPO}/actions/runs/{rid}/artifacts?per_page=100")
        artifacts = artifacts_data.get("artifacts") if isinstance(artifacts_data, dict) else None
        if not isinstance(artifacts, list):
            raise AdmissionError("Source artifacts unavailable")
        web, visual = (_select_artifact(artifacts, name) for name in ARTIFACTS)
        if _main(reader) != sha:
            raise AdmissionError("Pawn Action main advanced during source admission")
        return {"source_sha": sha, "run_id": rid, "artifact_id": web["id"],
                "artifact_digest": web["digest"],
                "visual_artifact_id": visual["id"],
                "visual_artifact_digest": visual["digest"]}
    raise AdmissionError("No successful exact-main push with real Chromium Web gate")

def verify_archive(path: Path, digest: str):
    """Check the exact GitHub ZIP digest and every entry without extracting it."""
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise AdmissionError("GitHub artifact SHA256 digest required")
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_ZIP:
        raise AdmissionError("Web ZIP missing, empty or too large")
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != digest.split(":", 1)[1]:
        raise AdmissionError("Web archive differs from Actions SHA256")
    names = set()
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if not 4 <= len(entries) <= 128:
                raise AdmissionError("Web archive file-count bound violated")
            for entry in entries:
                name = entry.filename
                pure = PurePosixPath(name)
                if (entry.is_dir() or not pure.parts or name.startswith("/")
                        or "\\" in name or any(p in ("", ".", "..") for p in name.split("/"))
                        or stat.S_ISLNK(entry.external_attr >> 16)
                        or name in names or not 0 < entry.file_size <= MAX_EXPANDED):
                    raise AdmissionError("Unsafe/duplicate/empty Web archive path")
                names.add(name)
                total += entry.file_size
                if total > MAX_EXPANDED:
                    raise AdmissionError("Web archive expansion budget exceeded")
                with archive.open(entry) as stream:
                    for _ in iter(lambda: stream.read(1 << 20), b""):
                        pass
    except (OSError, EOFError, zipfile.BadZipFile) as exc:
        raise AdmissionError("Invalid ZIP or CRC: " + type(exc).__name__) from None
    if not REQUIRED.issubset(names):
        raise AdmissionError("Missing Godot HTML/JS/WASM/PCK files")
    return {"files": len(names), "bytes": total, "digest": digest}

def main():
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "check":
            result = admit(GithubReader(os.environ.get("GH_TOKEN", "")), sys.argv[2])
            print("PAWN_ACTION_SOURCE_ADMITTED " + json.dumps(result, sort_keys=True))
        elif len(sys.argv) == 4 and sys.argv[1] == "verify-archive":
            result = verify_archive(Path(sys.argv[2]), sys.argv[3])
            print("PAWN_ACTION_WEB_ARCHIVE_VERIFIED " + json.dumps(result, sort_keys=True))
        else:
            print("Usage: pawn_action_source_admission.py check <40-hex-sha> | verify-archive <zip> <sha256:digest>", file=sys.stderr)
            return 2
        return 0
    except AdmissionError as exc:
        print("PAWN_ACTION_SOURCE_BLOCKED " + str(exc), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
