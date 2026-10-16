#!/usr/bin/env python3
"""Check signed Chronicles web release readiness on the existing shared A1.

This command is CHECK-ONLY. It never pulls, starts or mutates containers,
Cloudflare, Chess Studio, Oracle resources or saved data.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Callable, Mapping

from shared_a1_host_guard import SharedHostError, verify_shared_a1_containers

SOURCE = "evilsysadmin/chronicles-of-matthias"
IMAGE = "ghcr.io/evilsysadmin/chronicles-web"
WORKFLOW = ".github/workflows/web-publish.yml"
SIGNER = SOURCE + "/" + WORKFLOW
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
SHA = re.compile(r"^[a-f0-9]{40}$")
PROVENANCE = "https://slsa.dev/provenance/v1"
EXPECTED_JOBS = {"web-image-policy", "publish-staging-web"}


class WebPreflightError(ValueError):
    pass


def github_read(path: str, token: str) -> dict:
    prefix = "/repos/" + SOURCE + "/"
    if (not path.startswith(prefix) or "://" in path or "%" in path
            or any(part in {".", ".."} for part in path.split("/"))):
        raise WebPreflightError("GitHub request outside the fixed source repository")
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = response.read(2_000_001)
    except (urllib.error.URLError, OSError) as exc:
        raise WebPreflightError("Source build evidence cannot be retrieved") from exc
    if len(data) > 2_000_000:
        raise WebPreflightError("GitHub evidence exceeds size limit")
    try:
        result = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise WebPreflightError("Source build evidence is invalid JSON") from exc
    if not isinstance(result, dict):
        raise WebPreflightError("Source build evidence has invalid shape")
    return result


def verify_source(sha: str, run_id: int, token: str, read: Callable = github_read) -> None:
    prefix = "/repos/" + SOURCE
    run = read(f"{prefix}/actions/runs/{run_id}", token)
    if any((
        run.get("head_sha") != sha,
        run.get("event") != "push",
        run.get("head_branch") != "main",
        run.get("path") != WORKFLOW,
        run.get("status") != "completed",
        run.get("conclusion") != "success",
        (run.get("repository") or {}).get("full_name") != SOURCE,
    )):
        raise WebPreflightError("Untrusted Chronicles web publish run")
    branch = read(f"{prefix}/branches/main", token)
    if branch.get("protected") is not True:
        raise WebPreflightError("Chronicles main is not protected")
    lineage = read(f"{prefix}/compare/{sha}...main", token)
    if lineage.get("status") not in {"ahead", "identical"} or lineage.get("behind_by") != 0:
        raise WebPreflightError("Candidate no longer belongs to source main")
    jobs = read(f"{prefix}/actions/runs/{run_id}/jobs?per_page=100", token)
    rows = jobs.get("jobs")
    if (not isinstance(rows, list) or not isinstance(jobs.get("total_count"), int)
            or len(rows) != jobs["total_count"] or len(rows) > 100):
        raise WebPreflightError("Source workflow jobs are incomplete")
    for name in EXPECTED_JOBS:
        matches = [item for item in rows if item.get("name") == name]
        if len(matches) != 1 or matches[0].get("status") != "completed" or matches[0].get("conclusion") != "success":
            raise WebPreflightError("Missing successful trusted web publication job")


def command(runner: Callable, args: list[str], env: Mapping[str, str], label: str) -> str:
    try:
        result = runner(args, text=True, capture_output=True, timeout=90, env=dict(env))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WebPreflightError(label + " unavailable") from exc
    if result.returncode != 0 or not isinstance(result.stdout, str):
        # Never log process stdout/stderr; it could contain credentials.
        raise WebPreflightError(label + " failed")
    if len(result.stdout) > 2_000_000:
        raise WebPreflightError(label + " output exceeds size limit")
    return result.stdout


def verified_provenance(stdout: str, digest: str) -> None:
    try:
        rows = json.loads(stdout)
    except ValueError as exc:
        raise WebPreflightError("Verified provenance is not JSON") from exc
    if not isinstance(rows, list) or not rows:
        raise WebPreflightError("No verified provenance")
    valid = any(
        isinstance(row, dict)
        and (row.get("verificationResult") or {}).get("statement", {}).get("predicateType") == PROVENANCE
        and any((subject.get("digest") or {}).get("sha256") == digest[7:]
                for subject in ((row.get("verificationResult") or {}).get("statement", {}).get("subject") or [])
                if isinstance(subject, dict))
        for row in rows
    )
    if not valid:
        raise WebPreflightError("Signature subject does not match the immutable digest")


def verify_manifest(stdout: str) -> None:
    try:
        data = json.loads(stdout)
    except ValueError as exc:
        raise WebPreflightError("Image manifest is not JSON") from exc
    manifests = data.get("manifests") if isinstance(data, dict) else None
    if not isinstance(manifests, list):
        raise WebPreflightError("Expected a multi-platform image manifest")
    for arch in ("amd64", "arm64"):
        matches = [row for row in manifests if isinstance(row, dict) and
                   isinstance(row.get("platform"), dict) and
                   row["platform"].get("os") == "linux" and row["platform"].get("architecture") == arch]
        if len(matches) != 1:
            raise WebPreflightError("Signed web image lacks a unique " + arch + " variant")


def verify_compose(stdout: str, digest: str) -> None:
    try:
        data = json.loads(stdout)
    except ValueError as exc:
        raise WebPreflightError("Compose configuration is not JSON") from exc
    if not isinstance(data, dict) or data.get("name") != "shadowops-chronicles-web-staging":
        raise WebPreflightError("Unexpected Compose project")
    services = data.get("services")
    if not isinstance(services, dict) or set(services) != {"chronicles-web"}:
        raise WebPreflightError("Web preflight cannot manage other services")
    web = services["chronicles-web"]
    if (web.get("image") != IMAGE + "@" + digest or web.get("platform") != "linux/arm64"
        or web.get("read_only") is not True or web.get("init") is not True
        or web.get("cap_drop") != ["ALL"] or web.get("user") != "101:101"
        or "no-new-privileges:true" not in web.get("security_opt", [])):
        raise WebPreflightError("Web image or container hardening is unexpected")
    ports = web.get("ports")
    if (not isinstance(ports, list) or len(ports) != 1
        or ports[0].get("host_ip") != "127.0.0.1"
        or str(ports[0].get("published")) != "18082" or ports[0].get("target") != 8080):
        raise WebPreflightError("Web origin must bind loopback 18082 only")
    if data.get("secrets") or web.get("privileged") or web.get("volumes"):
        raise WebPreflightError("Web origin contains unapproved privileges or mounts")


def check(*, sha: str, digest: str, run_id: int, env: Mapping[str, str],
          runner: Callable = subprocess.run, read: Callable = github_read,
          guard: Callable = verify_shared_a1_containers,
          architecture: str | None = None) -> str:
    if not SHA.fullmatch(sha) or not DIGEST.fullmatch(digest) or not isinstance(run_id, int) or run_id < 1:
        raise WebPreflightError("Invalid immutable release identity")
    if (architecture or platform.machine()).lower() not in {"arm64", "aarch64"}:
        raise WebPreflightError("Web staging preflight is restricted to the OCI ARM64 A1")
    if not env.get("GH_TOKEN"):
        raise WebPreflightError("Read-only source verification token is missing")
    if env.get("CHRONICLES_WEB_IMAGE_DIGEST") != digest:
        raise WebPreflightError("Compose digest and accredited digest must match")
    try:
        guard(runner)
    except SharedHostError as exc:
        raise WebPreflightError("Shared A1 Docker collision guard blocked staging") from exc
    verify_source(sha, run_id, env["GH_TOKEN"], read)
    attestation = command(runner, [
        "gh", "attestation", "verify", "oci://" + IMAGE + "@" + digest,
        "--repo", SOURCE, "--signer-workflow", SIGNER,
        "--source-digest", sha, "--source-ref", "refs/heads/main",
        "--predicate-type", PROVENANCE, "--format", "json",
    ], env, "Signed GHCR provenance verification")
    verified_provenance(attestation, digest)
    manifest = command(runner, [
        "docker", "buildx", "imagetools", "inspect", "--raw", IMAGE + "@" + digest,
    ], env, "Multiarch manifest validation")
    verify_manifest(manifest)
    compose = command(runner, [
        "docker", "compose", "-f", "compose.web.staging.yaml", "config", "--format", "json",
    ], env, "Independent web Compose rendering")
    verify_compose(compose, digest)
    return "CHRONICLES_WEB_A1_VERIFIED_PREFLIGHT_OK"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    args = parser.parse_args()
    try:
        result = check(sha=args.sha, digest=args.digest, run_id=args.run_id, env=os.environ)
    except WebPreflightError as exc:
        print("CHRONICLES_WEB_A1_PREFLIGHT_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
