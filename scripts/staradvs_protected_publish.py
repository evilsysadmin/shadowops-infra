#!/usr/bin/env python3
"""Narrow Star Adventures private Pages release admission (GET only).

The actual Cloudflare Pages write is a separate, protected manual workflow
step. Neither a green build nor a 302 redirect is a signed-in acceptance.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

import pages_access_readiness as access
import staradvs_access_challenge as challenge
import staradvs_access_quarantine as quarantine
import staradvs_identity_readiness as readiness
import staradvs_pages as pages
import staradvs_protected_bundle as bundle
import staradvs_source_admission as source

INFRA_REPO = "evilsysadmin/shadowops-infra"
SOURCE_REPO = "evilsysadmin/star-adventures"
WORKFLOW = ".github/workflows/staradvs-protected-candidate.yml"
NAME = "staradvs-protected-candidate-"
SHA = re.compile(r"[a-f0-9]{40}\Z")
RUN = re.compile(r"[1-9][0-9]{0,14}\Z")
ACCEPT = frozenset(("access-login-challenge-candidate",
                    "all-observed-guest-paths-denied"))


class ReleaseBlocked(Exception):
    pass


class GitHub:
    def __init__(self, token):
        if not token:
            raise ReleaseBlocked("GitHub read-only token unavailable")
        self.token = token

    def get(self, path):
        prefix = "/repos/" + INFRA_REPO + "/actions/runs/"
        if not path.startswith(prefix) or not re.fullmatch(
            r"/repos/evilsysadmin/shadowops-infra/actions/runs/[1-9][0-9]{0,14}(?:/artifacts\?per_page=100)?",
            path
        ):
            raise ReleaseBlocked("Unapproved GitHub endpoint")
        req = urllib.request.Request(
            "https://api.github.com" + path, headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                if response.status != 200:
                    raise ReleaseBlocked("GitHub artifact evidence unavailable")
                raw = response.read(1_000_001)
        except (urllib.error.URLError, OSError, TimeoutError):
            raise ReleaseBlocked("GitHub artifact API unavailable") from None
        if len(raw) > 1_000_000:
            raise ReleaseBlocked("Artifact metadata oversized")
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError):
            raise ReleaseBlocked("GitHub artifact response malformed") from None


def admit_candidate(reader, run_id, game_sha, infra_sha, *, game_reader):
    """Require successful trusted-main candidate and unique exact SHA artifact."""
    if (not isinstance(run_id, str) or not RUN.fullmatch(run_id) or
            not isinstance(game_sha, str) or not SHA.fullmatch(game_sha) or
            not isinstance(infra_sha, str) or not SHA.fullmatch(infra_sha)):
        raise ReleaseBlocked("Run, game SHA or Infra SHA invalid")
    # The separately pinned, current game main must have real CI evidence.
    source.admit(game_reader, game_sha)
    path = f"/repos/{INFRA_REPO}/actions/runs/{run_id}"
    run = reader.get(path)
    if not isinstance(run, dict) or (
        run.get("id") != int(run_id) or
        run.get("status") != "completed" or
        run.get("conclusion") != "success" or
        run.get("event") not in ("push", "workflow_dispatch") or
        run.get("head_branch") != "main" or
        run.get("head_sha") != infra_sha or
        not isinstance(run.get("repository"), dict) or
        run["repository"].get("full_name") != INFRA_REPO or
        not isinstance(run.get("path"), str) or
        run["path"].split("@", 1)[0] != WORKFLOW
    ):
        raise ReleaseBlocked("Candidate is not exact successful Infra-main workflow")
    data = reader.get(path + "/artifacts?per_page=100")
    if not isinstance(data, dict) or not isinstance(data.get("artifacts"), list):
        raise ReleaseBlocked("Candidate artifacts unavailable")
    wanted = NAME + game_sha
    artifacts = data["artifacts"]
    # No permissive pagination or duplicate artifact selection.
    if (type(data.get("total_count")) is not int or
            data["total_count"] != len(artifacts) or
            len(artifacts) != 1):
        raise ReleaseBlocked("Candidate artifact inventory ambiguous")
    artifact = artifacts[0]
    if (not isinstance(artifact, dict) or
            artifact.get("name") != wanted or artifact.get("expired") is not False or
            type(artifact.get("id")) is not int or artifact["id"] < 1 or
            type(artifact.get("size_in_bytes")) is not int or
            not 1024 <= artifact["size_in_bytes"] <= 200_000_000 or
            not isinstance(artifact.get("workflow_run"), dict) or
            artifact["workflow_run"].get("id") != int(run_id) or
            artifact["workflow_run"].get("head_sha") != infra_sha):
        raise ReleaseBlocked("Artifact unavailable, expired or not from the admitted run")
    return wanted


def verify_posture(pages_client, access_client):
    """Independently enforce all pre-mutation constraints, no cookie/token reuse."""
    if pages_client.account != access_client.account:
        raise ReleaseBlocked("Cloudflare account mismatch")
    if bundle.policy_status() != "pending-identity":
        raise ReleaseBlocked("Unreviewed public publisher activation")
    report = readiness.collect(pages_client, access_client=access_client)
    if (report.get("pages_project") != "owned" or
            report.get("identity_login") != "audience-recognized" or
            report.get("pages_private_policy") != "configured" or
            report.get("pages_app_proof") != "bound" or
            report.get("cloudflare_access") != "restricted-policy-candidate" or
            report.get("historical_enumeration_status") != "reported-total-observed"):
        raise ReleaseBlocked("Identity, Pages or Access guard not provisioned")
    scopes = report.get("cloudflare_access_scopes")
    if not isinstance(scopes, dict) or set(scopes) != set(readiness.ACCESS_SCOPES) or any(
        state != "restricted-policy-candidate" for state in scopes.values()
    ):
        raise ReleaseBlocked("Access policy inventory incomplete or overlapping")
    if report.get("historical_aliases_exposed") != 0:
        raise ReleaseBlocked("Previously published anonymous content still visible")
    # The second independent Cloudflare Pages history pass is mandatory:
    # no trust in just a count or a 302 Location.
    evidence = challenge.collect(pages_client, report)
    verdict = quarantine.judge_guest_quarantine(report, evidence)
    if verdict not in ACCEPT:
        raise ReleaseBlocked("Historical/current guest quarantine not verified")
    # Return only sanitized proof; never the historical aliases, Access team,
    # Cloudflare account, operator emails, Vault material or session data.
    return {
        "verdict": verdict,
        "deployment_total": report["historical_deployments_reported_total"],
        "aliases_checked": evidence["historical"]["hosts"],
        "aliases_challenged": evidence["historical"]["challenged"],
        "aliases_denied": evidence["historical"]["denied"],
        "can_activate": False,
        "signed_in_e2e": "not-performed",
    }


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("admit", "preflight", "postflight"))
    parser.add_argument("--run-id", default="")
    parser.add_argument("--game-sha", default="")
    parser.add_argument("--infra-sha", default="")
    args = parser.parse_args(argv)
    try:
        if args.operation == "admit":
            result = admit_candidate(
                GitHub(os.environ.get("GH_TOKEN", "")),
                args.run_id, args.game_sha, args.infra_sha,
                game_reader=source.GithubReader(os.environ.get("GH_TOKEN", "")),
            )
            print("STARADVS_PROTECTED_CANDIDATE_ADMITTED name=" + result)
            return 0
        if args.run_id or args.game_sha or args.infra_sha:
            raise ReleaseBlocked("Provider posture cannot be overridden by inputs")
        pages_client = pages.CloudflareClient(os.environ)
        access_client = access.AccessClient(os.environ)
        state = verify_posture(pages_client, access_client)
        print(json.dumps({
            "operation": args.operation, "project": pages.PROJECT, **state,
        }, sort_keys=True))
        print("STARADVS_PROTECTED_" + args.operation.upper() +
              "_GUEST_CANDIDATE authenticated-E2E-still-required")
        return 0
    except Exception as exc:
        # Never reveal Cloudflare, OCI Vault, Github API response or URL bodies.
        print("STARADVS_PROTECTED_RELEASE_BLOCKED kind=" + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
