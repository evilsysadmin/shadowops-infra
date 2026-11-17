#!/usr/bin/env python3
"""Exact-source admissibility for Bridge Squad staging. Read-only, no Pages deploy."""
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

SOURCE = "evilsysadmin/matthias-bridge-squad"
WORKFLOW = "pages.yml"
JOBS = {
    "smoke": {
        "Test private release packaging contract (offline)",
        "Verify desktop, mobile and 12 levels",
    },
    "package-private-candidate": {
        "Verify source-pinned release package policy (offline)",
        "Build immutable private candidate for Infra admission",
        "Upload exact SHA-bound candidate; never deploy publicly",
    },
}
ARTIFACT_PREFIX = "bridgesquad-private-release-"
SHA = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
MAX_ZIP = 2_000_000
MAX_HTML = 2_000_000
MAX_MANIFEST = 8192


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
        raise AdmissionError("Cannot establish current Bridge Squad main")
    return sha


def admit(reader, expected_sha: str) -> dict:
    if not isinstance(expected_sha, str) or not SHA.fullmatch(expected_sha):
        raise AdmissionError("Exact lowercase 40-hex Bridge Squad main SHA required")
    if current_sha(reader) != expected_sha:
        raise AdmissionError("Bridge Squad source main has advanced or does not match")
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
            not isinstance(run.get("head_repository"), dict) or run["head_repository"].get("full_name") != SOURCE,
        )):
            continue
        run_id = run.get("id")
        if type(run_id) is not int or run_id <= 0:
            raise AdmissionError("Source CI run ID invalid")
        jobs_result = reader.get(f"/repos/{SOURCE}/actions/runs/{run_id}/jobs?per_page=100")
        jobs = jobs_result.get("jobs") if isinstance(jobs_result, dict) else None
        if not isinstance(jobs, list):
            raise AdmissionError("Source CI job evidence missing")
        for job_name, required in JOBS.items():
            matches = [job for job in jobs if isinstance(job, dict)
                       and job.get("name") == job_name]
            if len(matches) != 1:
                raise AdmissionError("Unique source job required: " + job_name)
            job = matches[0]
            if (job.get("status") != "completed" or job.get("conclusion") != "success"
                    or not job.get("completed_at")):
                raise AdmissionError("Source CI job not green")
            steps = job.get("steps")
            if not isinstance(steps, list):
                raise AdmissionError("Source CI step evidence unavailable")
            passed = {step.get("name") for step in steps if isinstance(step, dict)
                      and step.get("status") == "completed"
                      and step.get("conclusion") == "success"}
            if not required.issubset(passed):
                raise AdmissionError("Browser, package or artifact upload step skipped")
        artifacts_result = reader.get(f"/repos/{SOURCE}/actions/runs/{run_id}/artifacts?per_page=100")
        artifacts = artifacts_result.get("artifacts") if isinstance(artifacts_result, dict) else None
        if not isinstance(artifacts, list):
            raise AdmissionError("Source artifacts unavailable")
        matches = [a for a in artifacts if isinstance(a, dict) and a.get("name") == ARTIFACT_PREFIX + expected_sha]
        if len(matches) != 1:
            raise AdmissionError("Unique Bridge Squad dist artifact required")
        item = matches[0]
        if (item.get("expired") is not False
                or type(item.get("id")) is not int or item["id"] <= 0
                or type(item.get("size_in_bytes")) is not int
                or not 0 < item["size_in_bytes"] <= MAX_ZIP
                or not isinstance(item.get("digest"), str)
                or not DIGEST.fullmatch(item["digest"])
                or not isinstance(item.get("workflow_run"), dict)
                or item["workflow_run"].get("id") != run_id
                or item["workflow_run"].get("head_sha") != expected_sha
                or item["workflow_run"].get("head_branch") != "main"):
            raise AdmissionError("Source artifact missing SHA256, expired or oversized")
        if current_sha(reader) != expected_sha:
            raise AdmissionError("Source main advanced during admission")
        return {
            "source_sha": expected_sha,
            "run_id": run_id,
            "artifact_id": item["id"],
            "artifact_digest": item["digest"],
            "artifact_name": ARTIFACT_PREFIX + expected_sha,
        }
    raise AdmissionError("No green exact-main source CI push run")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionError("Duplicate release JSON field")
        result[key] = value
    return result


def verify_archive(path: Path, digest: str, source_sha: str) -> dict:
    """Read-only ZIP validation. Never extract an untrusted artifact."""
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        raise AdmissionError("Exact lowercase source SHA required")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise AdmissionError("Artifact SHA256 receipt required")
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_ZIP:
        raise AdmissionError("Source artifact missing, linked or oversized")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest.removeprefix("sha256:"):
        raise AdmissionError("Source artifact ZIP digest mismatch")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) != 2 or {i.filename for i in infos} != {"index.html", "release.json"}:
                raise AdmissionError("Expected exactly HTML and release manifest")
            for item in infos:
                if (item.is_dir() or item.flag_bits & 1 or
                        stat.S_ISLNK(item.external_attr >> 16) or
                        item.file_size > (MAX_HTML if item.filename == "index.html" else MAX_MANIFEST)):
                    raise AdmissionError("Unsafe source ZIP entry")
            html = archive.read("index.html")
            raw = archive.read("release.json")
            if archive.testzip() is not None:
                raise AdmissionError("Source ZIP CRC mismatch")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError):
        raise AdmissionError("Unreadable artifact ZIP") from None
    if not 64 <= len(html) <= MAX_HTML or not 0 < len(raw) <= MAX_MANIFEST:
        raise AdmissionError("Unexpected HTML or manifest size")
    try:
        title = html.decode("utf-8")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError, TypeError):
        raise AdmissionError("Source manifest or HTML invalid") from None
    if not title.lstrip().lower().startswith("<!doctype html>") or "<title>Matthias Bridge Squad" not in title:
        raise AdmissionError("Unexpected game HTML")
    auth = {"provider": "shadowops-id", "audience": "bridgesquad", "required": True}
    if (not isinstance(value, dict)
            or set(value) != {"schema", "application", "environment", "source_repository", "source_sha", "authentication", "files"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["application"] != "matthias-bridge-squad"
            or value["environment"] != "production"
            or value["source_repository"] != SOURCE
            or value["source_sha"] != source_sha or value["authentication"] != auth):
        raise AdmissionError("Wrong source, release identity or authentication policy")
    files = value["files"]
    entry = files.get("index.html") if isinstance(files, dict) else None
    if (not isinstance(files, dict) or set(files) != {"index.html"}
            or not isinstance(entry, dict) or set(entry) != {"sha256", "bytes"}
            or type(entry["bytes"]) is not int or entry["bytes"] != len(html)
            or entry["sha256"] != hashlib.sha256(html).hexdigest()):
        raise AdmissionError("HTML digest or release manifest mismatch")
    return {"source_sha": source_sha, "artifact_digest": digest, "html_sha256": entry["sha256"],
            "html_bytes": entry["bytes"], "files": 2, "authentication": "required"}


def main():
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "check-current":
            reader = GithubReader(os.environ.get("GH_TOKEN", ""))
            proof = admit(reader, current_sha(reader))
            print("BRIDGESQUAD_SOURCE_ADMITTED " + " ".join(f"{k}={v}" for k, v in proof.items()))
        elif len(sys.argv) == 3 and sys.argv[1] == "check":
            proof = admit(GithubReader(os.environ.get("GH_TOKEN", "")), sys.argv[2])
            print("BRIDGESQUAD_SOURCE_ADMITTED " + " ".join(f"{k}={v}" for k, v in proof.items()))
        elif len(sys.argv) == 5 and sys.argv[1] == "verify-archive":
            proof = verify_archive(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
            print("BRIDGESQUAD_DIST_ARCHIVE_VERIFIED " + " ".join(f"{k}={v}" for k, v in proof.items()))
        else:
            raise AdmissionError("Usage: check-current | check SHA | verify-archive ZIP sha256:DIGEST SHA")
        return 0
    except AdmissionError as exc:
        print("BRIDGESQUAD_SOURCE_BLOCKED " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
