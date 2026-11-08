#!/usr/bin/env python3
"""Exact-source admissibility for Snooker staging. Read-only, no Pages deploy."""
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

SOURCE = "evilsysadmin/snooker-of-matthias"
WORKFLOW = "ci.yml"
JOB = "verify"
REQUIRED_STEPS = {
    "Deterministic physics tests",
    "Production 3D build",
    "Exercise desktop and mobile 3D browser",
    "Attach Cloudflare Pages-ready dist (not a deployment)",
}
ARTIFACT = "snooker-web-dist"
SHA = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
MAX_ZIP = 30 * 1024 * 1024
MAX_UNPACKED = 50 * 1024 * 1024


class AdmissionError(ValueError):
    pass


class GithubReader:
    def __init__(self, token: str):
        if not token:
            raise AdmissionError("GH_TOKEN required for source evidence")
        self.token = token

    def get(self, path: str):
        if not path.startswith("/repos/" + SOURCE + "/") or ".." in path or "://" in path:
            raise AdmissionError("GitHub source path outside allowlist")
        request = urllib.request.Request(
            "https://api.github.com" + path,
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status != 200:
                    raise AdmissionError("Source API non-200")
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise AdmissionError("Source API response too large")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise AdmissionError("Source API response invalid")
                return result
        except (urllib.error.URLError, ValueError, UnicodeError) as exc:
            raise AdmissionError("Source CI evidence unavailable: " + type(exc).__name__) from None


def current_sha(reader) -> str:
    data = reader.get(f"/repos/{SOURCE}/commits/main")
    sha = data.get("sha") if isinstance(data, dict) else None
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise AdmissionError("Cannot establish current Snooker main")
    return sha


def admit(reader, expected_sha: str) -> dict:
    if not isinstance(expected_sha, str) or not SHA.fullmatch(expected_sha):
        raise AdmissionError("Exact lowercase 40-hex Snooker main SHA required")
    if current_sha(reader) != expected_sha:
        raise AdmissionError("Snooker source main has advanced or does not match")
    query = urllib.parse.urlencode({
        "head_sha": expected_sha, "branch": "main", "event": "push", "per_page": 50,
    })
    result = reader.get(f"/repos/{SOURCE}/actions/workflows/{WORKFLOW}/runs?" + query)
    runs = result.get("workflow_runs") if isinstance(result, dict) else None
    if not isinstance(runs, list):
        raise AdmissionError("Source CI run inventory unavailable")
    for run in runs:
        if not isinstance(run, dict) or any((
            run.get("head_sha") != expected_sha,
            run.get("head_branch") != "main",
            run.get("event") != "push",
            run.get("status") != "completed",
            run.get("conclusion") != "success",
        )):
            continue
        run_id = run.get("id")
        if type(run_id) is not int or run_id <= 0:
            raise AdmissionError("Source CI run ID invalid")
        jobs_result = reader.get(f"/repos/{SOURCE}/actions/runs/{run_id}/jobs?per_page=100")
        jobs = jobs_result.get("jobs") if isinstance(jobs_result, dict) else None
        if not isinstance(jobs, list):
            raise AdmissionError("Source CI job evidence missing")
        matches = [job for job in jobs if isinstance(job, dict) and job.get("name") == JOB]
        if len(matches) != 1:
            raise AdmissionError("Unique Snooker CI job required")
        job = matches[0]
        if (job.get("status") != "completed" or job.get("conclusion") != "success"
                or not job.get("completed_at")):
            raise AdmissionError("Source CI job not complete")
        steps = job.get("steps")
        if not isinstance(steps, list):
            raise AdmissionError("Source CI step evidence unavailable")
        passed = {step.get("name") for step in steps if isinstance(step, dict)
                  and step.get("status") == "completed"
                  and step.get("conclusion") == "success"}
        if not REQUIRED_STEPS.issubset(passed):
            raise AdmissionError("3D build / physics / Chromium / artifact step skipped")
        artifacts_result = reader.get(f"/repos/{SOURCE}/actions/runs/{run_id}/artifacts?per_page=100")
        artifacts = artifacts_result.get("artifacts") if isinstance(artifacts_result, dict) else None
        if not isinstance(artifacts, list):
            raise AdmissionError("Source artifacts unavailable")
        matches = [a for a in artifacts if isinstance(a, dict) and a.get("name") == ARTIFACT]
        if len(matches) != 1:
            raise AdmissionError("Unique Snooker dist artifact required")
        item = matches[0]
        if (item.get("expired") is not False
                or type(item.get("id")) is not int or item["id"] <= 0
                or type(item.get("size_in_bytes")) is not int
                or not 0 < item["size_in_bytes"] <= MAX_ZIP
                or not isinstance(item.get("digest"), str)
                or not DIGEST.fullmatch(item["digest"])):
            raise AdmissionError("Source artifact missing SHA256, expired or oversized")
        if current_sha(reader) != expected_sha:
            raise AdmissionError("Source main advanced during admission")
        return {
            "source_sha": expected_sha,
            "run_id": run_id,
            "artifact_id": item["id"],
            "artifact_digest": item["digest"],
        }
    raise AdmissionError("No green exact-main source CI push run")


def verify_archive(path: Path, digest: str) -> dict:
    if not DIGEST.fullmatch(digest):
        raise AdmissionError("Artifact SHA256 receipt required")
    if not path.is_file() or path.stat().st_size > MAX_ZIP:
        raise AdmissionError("Source artifact missing or oversized")
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest.removeprefix("sha256:"):
        raise AdmissionError("Source artifact ZIP digest mismatch")
    names = set()
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if not 2 <= len(infos) <= 300:
                raise AdmissionError("Unexpected Snooker distribution entry count")
            for item in infos:
                p = PurePosixPath(item.filename)
                if (item.is_dir() or p.is_absolute() or ".." in p.parts or
                        "\\" in item.filename or ":" in item.filename or
                        stat.S_ISLNK(item.external_attr >> 16) or
                        item.file_size > 25 * 1024 * 1024):
                    raise AdmissionError("Unsafe Snooker distribution entry")
                name = p.as_posix()
                if name in names or not (
                    name == "index.html"
                    or (len(p.parts) == 2 and p.parts[0] == "assets"
                        and p.suffix in {".js", ".css", ".svg", ".png", ".woff2"})
                ):
                    raise AdmissionError("Unexpected file in source distribution")
                names.add(name)
                total += item.file_size
                if total > MAX_UNPACKED:
                    raise AdmissionError("Expanded Snooker distribution over budget")
            if "index.html" not in names or not any(
                n.startswith("assets/") and n.endswith(".js") for n in names
            ):
                raise AdmissionError("Snooker distribution missing HTML or runtime JS")
            if archive.testzip() is not None:
                raise AdmissionError("Source artifact CRC mismatch")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        raise AdmissionError("Unreadable source distribution ZIP") from None
    return {"files": len(names), "unpacked_bytes": total}


def main():
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "check-current":
            reader = GithubReader(os.environ.get("GH_TOKEN", ""))
            proof = admit(reader, current_sha(reader))
            print("SNOOKER_SOURCE_ADMITTED " + " ".join(f"{k}={v}" for k, v in proof.items()))
        elif len(sys.argv) == 3 and sys.argv[1] == "check":
            proof = admit(GithubReader(os.environ.get("GH_TOKEN", "")), sys.argv[2])
            print("SNOOKER_SOURCE_ADMITTED " + " ".join(f"{k}={v}" for k, v in proof.items()))
        elif len(sys.argv) == 4 and sys.argv[1] == "verify-archive":
            proof = verify_archive(Path(sys.argv[2]), sys.argv[3])
            print("SNOOKER_DIST_ARCHIVE_VERIFIED " + " ".join(f"{k}={v}" for k, v in proof.items()))
        else:
            raise AdmissionError("Usage: check-current | check SHA | verify-archive ZIP sha256:DIGEST")
        return 0
    except AdmissionError as exc:
        print("SNOOKER_SOURCE_BLOCKED " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
