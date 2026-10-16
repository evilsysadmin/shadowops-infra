#!/usr/bin/env python3
"""Read-only, signed web release admission on a trusted ShadowOps GitHub runner.

This step never authenticates to OCI and never modifies a host. Its job is
independent source/workflow/Sigstore validation BEFORE a privileged dispatch.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Callable, Mapping

from oci_web_staging_preflight import (
    IMAGE, SOURCE, SIGNER, PROVENANCE, SHA, DIGEST,
    WebPreflightError, github_read, verify_compose, verify_manifest,
    verify_source, verified_provenance,
)


def fixed_command(runner: Callable, args: list[str], env: Mapping[str, str], stage: str) -> str:
    if stage not in {"signature", "manifest", "compose"}:
        raise WebPreflightError("Unknown signed-release verification stage")
    try:
        result = runner(args, text=True, capture_output=True, timeout=90, env=dict(env))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WebPreflightError("Signed-release " + stage + " tool unavailable") from exc
    if result.returncode != 0 or not isinstance(result.stdout, str):
        raise WebPreflightError("Signed-release " + stage + " command failed")
    if len(result.stdout) > 2_000_000:
        raise WebPreflightError("Signed-release " + stage + " output too large")
    return result.stdout


def admit(sha: str, digest: str, run_id: int, *,
          env: Mapping[str, str],
          read: Callable = github_read,
          runner: Callable = subprocess.run) -> str:
    if (not SHA.fullmatch(sha) or not DIGEST.fullmatch(digest)
            or not isinstance(run_id, int) or run_id <= 0):
        raise WebPreflightError("Immutable source identity is invalid")
    token = env.get("GH_TOKEN", "")
    if not token:
        raise WebPreflightError("Read-only source verification token missing")
    if env.get("CHRONICLES_WEB_IMAGE_DIGEST") != digest:
        raise WebPreflightError("Expected digest differs from pinned Compose digest")
    verify_source(sha, run_id, token, read)
    checked = fixed_command(runner, [
        "gh", "attestation", "verify", "oci://" + IMAGE + "@" + digest,
        "--repo", SOURCE, "--signer-workflow", SIGNER,
        "--source-digest", sha, "--source-ref", "refs/heads/main",
        "--predicate-type", PROVENANCE, "--format", "json",
        "--bundle-from-oci",
    ], env, "signature")
    verified_provenance(checked, digest)
    manifest = fixed_command(runner, [
        "docker", "buildx", "imagetools", "inspect", "--raw", IMAGE + "@" + digest,
    ], env, "manifest")
    verify_manifest(manifest)
    composed = fixed_command(runner, [
        "docker", "compose", "-f", "compose.web.staging.yaml",
        "config", "--format", "json",
    ], env, "compose")
    verify_compose(composed, digest)
    return "CHRONICLES_WEB_SIGNED_A1_RELEASE_ADMITTED sha=" + sha + " digest=" + digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    args = parser.parse_args()
    try:
        print(admit(args.sha, args.digest, args.run_id, env=os.environ))
    except WebPreflightError as exc:
        print("CHRONICLES_WEB_SIGNED_ADMISSION_BLOCKED reason=" +
              str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
