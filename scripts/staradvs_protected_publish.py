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

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID
import staradvs_identity_readiness as readiness
import staradvs_pages as pages
import staradvs_protected_bundle as bundle
import staradvs_infra_revision as revision
import staradvs_source_admission as source

INFRA_REPO = "evilsysadmin/shadowops-infra"
SOURCE_REPO = "evilsysadmin/star-adventures"
WORKFLOW = ".github/workflows/staradvs-protected-candidate.yml"
NAME = "staradvs-protected-candidate-"
SHA = re.compile(r"[a-f0-9]{40}\Z")
RUN = re.compile(r"[1-9][0-9]{0,14}\Z")


class ReleaseBlocked(Exception):
    pass


class GitHub:
    def __init__(self, token):
        if not token:
            raise ReleaseBlocked("GitHub read-only token unavailable")
        self.token = token

    def get(self, path):
        actions = re.fullmatch(
            r"/repos/evilsysadmin/shadowops-infra/actions/runs/[1-9][0-9]{0,14}(?:/artifacts\?per_page=100)?",
            path
        )
        trees = re.fullmatch(
            r"/repos/evilsysadmin/shadowops-infra/git/trees/[a-f0-9]{40}\?recursive=1",
            path
        )
        if not path.startswith("/repos/" + INFRA_REPO + "/") or not (actions or trees):
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
                raw = response.read(6_000_001 if trees else 1_000_001)
        except (urllib.error.URLError, OSError, TimeoutError):
            raise ReleaseBlocked("GitHub artifact API unavailable") from None
        if len(raw) > (6_000_000 if trees else 1_000_000):
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
        not isinstance(run.get("head_sha"), str) or
        not SHA.fullmatch(run["head_sha"]) or
        not isinstance(run.get("repository"), dict) or
        run["repository"].get("full_name") != INFRA_REPO or
        not isinstance(run.get("path"), str) or
        run["path"].split("@", 1)[0] != WORKFLOW
    ):
        raise ReleaseBlocked("Candidate is not exact successful Infra-main workflow")
    # A Chronicles/Football-only Infra merge cannot invalidate identical
    # Star Adventures release policy. Independently compare immutable git
    # blob IDs of every staging-relevant path, not commit dates or names.
    # Truncated trees, deleted files, changed code/Workers/workflows, or an
    # unrecognized provider response all fail closed.
    pinned = run["head_sha"]
    if pinned != infra_sha:
        try:
            stable, changed = revision.compare(
                pinned, infra_sha,
                lambda sha: reader.get(
                    f"/repos/{INFRA_REPO}/git/trees/{sha}?recursive=1"
                ),
            )
        except revision.RevisionError:
            raise ReleaseBlocked("Protected Infra revision evidence unavailable") from None
        if not stable:
            raise ReleaseBlocked("Staging-owned Infra paths changed")
    data = reader.get(path + "/artifacts?per_page=100")
    if not isinstance(data, dict) or not isinstance(data.get("artifacts"), list):
        raise ReleaseBlocked("Candidate artifacts unavailable")
    wanted = NAME + game_sha
    artifacts = data["artifacts"]
    # No permissive pagination, cross-run artifact or duplicate selection.
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
            artifact["workflow_run"].get("head_sha") != pinned):
        raise ReleaseBlocked("Artifact unavailable, expired or not from the admitted run")
    return wanted


def owned_project(client):
    if bundle.policy_status() != "pending-identity":
        raise ReleaseBlocked("public-publisher-not-frozen")
    _, owner = pages.inspect(client)
    if owner != {"dns": "owned", "domain": "owned", "project": "owned"}:
        raise ReleaseBlocked("pages-ownership")
    status, project = client.request("GET", f"/accounts/{client.account}/pages/projects/{pages.PROJECT}")
    if status != 200 or not isinstance(project, dict) or project.get("subdomain") != pages.TARGET:
        raise ReleaseBlocked("pages-project")
    policy, proof = readiness.pages_posture(project)
    if policy != "configured":
        raise ReleaseBlocked("pages-fail-closed-policy-not-configured")
    if proof != "bound":
        raise ReleaseBlocked("staradvs-identity-proof-not-bound")
    return project


def checked_id(value):
    try:
        if str(UUID(value)) == value:
            return value
    except (TypeError, ValueError, AttributeError):
        pass
    raise ReleaseBlocked("invalid-deployment-id")


def checked_host(value):
    if not isinstance(value, str):
        raise ReleaseBlocked("invalid-deployment-url")
    parsed = urlsplit(value)
    host = parsed.hostname
    if (parsed.scheme != "https" or parsed.netloc != host or
            parsed.path not in ("", "/") or parsed.query or parsed.fragment or
            not host or not (host in (pages.HOST, pages.TARGET) or
            re.fullmatch(r"[a-z0-9-]+\." + re.escape(pages.TARGET), host))):
        raise ReleaseBlocked("foreign-deployment-url")
    return host


def inventory(client):
    path = f"/accounts/{client.account}/pages/projects/{pages.PROJECT}/deployments"
    rows = {}
    total = None
    for number in range(1, readiness.MAX_HISTORY_PAGES + 1):
        status, batch, meta = client.request_with_info(path + (f"?page={number}" if number > 1 else ""))
        if (status != 200 or not isinstance(batch, list) or not isinstance(meta, dict) or
                type(meta.get("total_count")) is not int or
                type(meta.get("page")) is not int or meta["page"] != number or
                type(meta.get("count")) is not int or meta["count"] != len(batch) or
                type(meta.get("per_page")) is not int or meta["per_page"] < len(batch)):
            raise ReleaseBlocked("history-pagination-unverified")
        if total is None:
            total = meta["total_count"]
        if total != meta["total_count"] or not 1 <= total <= readiness.MAX_HISTORY_ALIASES or not batch:
            raise ReleaseBlocked("history-total-invalid")
        for row in batch:
            if not isinstance(row, dict) or row.get("project_name") not in (None, pages.PROJECT):
                raise ReleaseBlocked("foreign-deployment")
            key = checked_id(row.get("id"))
            host = checked_host(row.get("url"))
            aliases = row.get("aliases") or []
            if (key in rows or host in (pages.HOST, pages.TARGET) or
                    not isinstance(aliases, list) or any(host == x["host"] for x in rows.values())):
                raise ReleaseBlocked("duplicate-or-nonimmutable-deployment")
            rows[key] = {"host": host, "aliases": sorted(set(checked_host(x) for x in aliases))}
        if len(rows) == total:
            return rows
        if len(rows) > total:
            break
    raise ReleaseBlocked("history-incomplete")


def verify_posture(client):
    project = owned_project(client)
    code, body = readiness.read_public(readiness.ISSUER + "/login?app=staradvs")
    if code != 200 or b"https://staging.staradvs.shadowops.dpdns.org/?shadowops=central" not in body:
        raise ReleaseBlocked("staradvs-identity-audience-not-live")
    rows = inventory(client)
    current = checked_id((project.get("canonical_deployment") or {}).get("id"))
    if current not in rows:
        raise ReleaseBlocked("canonical-not-in-inventory")
    return rows


def active_deployment(client, sha, snapshot):
    project = owned_project(client)
    canonical = project.get("canonical_deployment") or {}
    latest = project.get("latest_deployment") or {}
    key = checked_id(canonical.get("id"))
    metadata = (canonical.get("deployment_trigger") or {}).get("metadata") or {}
    if (key in snapshot or latest.get("id") != key or
            canonical.get("environment") != "production" or
            (canonical.get("latest_stage") or {}).get("status") != "success" or
            metadata.get("commit_hash") != sha or metadata.get("branch") != "main" or
            metadata.get("commit_dirty") is not False):
        raise ReleaseBlocked("new-protected-canonical-not-verified")
    host = checked_host(canonical.get("url"))
    if host in (pages.HOST, pages.TARGET):
        raise ReleaseBlocked("canonical-immutable-host-unverified")
    return key, host


def require_denial(canonical, aliases, probe=readiness.read_public):
    checks = [(pages.HOST, path, method, 401) for path in readiness.ROUTES for method in readiness.METHODS]
    checks += [(host, path, method, 404) for host in sorted(set(aliases) | {pages.TARGET, canonical} - {pages.HOST})
               if host != pages.HOST for path in readiness.ROUTES for method in readiness.METHODS]
    with ThreadPoolExecutor(max_workers=24) as pool:
        results = list(pool.map(lambda x: probe("https://" + x[0] + x[1], x[2])[0] == x[3], checks))
    if not all(results):
        raise ReleaseBlocked("guest-denial-incomplete")


def validate_snapshot(snapshot):
    if not isinstance(snapshot, dict) or not 1 <= len(snapshot) <= readiness.MAX_HISTORY_ALIASES:
        raise ReleaseBlocked("invalid-cutover-snapshot")
    for key, row in snapshot.items():
        checked_id(key)
        if not isinstance(row, dict) or set(row) != {"host", "aliases"} or not isinstance(row["aliases"], list):
            raise ReleaseBlocked("invalid-cutover-snapshot")
        for host in [row["host"], *row["aliases"]]:
            if checked_host("https://" + host) != host:
                raise ReleaseBlocked("invalid-cutover-host")
        if row["host"] in (pages.HOST, pages.TARGET):
            raise ReleaseBlocked("invalid-cutover-host")
    return snapshot


def retire_legacy(client, sha, snapshot):
    """Only explicitly approved staging history, after a new protected canonical is live."""
    validate_snapshot(snapshot)
    key, host = active_deployment(client, sha, snapshot)
    require_denial(host, [])
    rows = inventory(client)
    if key not in rows or set(rows) - set(snapshot) != {key}:
        raise ReleaseBlocked("history-changed-after-publish")
    for old_id in sorted(set(rows) - {key}):
        # Pages moves branch aliases when a new canonical deployment is
        # published. The deployment ID and immutable deployment URL must stay
        # the same; alias metadata may change as routing moves to the new
        # protected canonical. Preserve both observations for postflight.
        if rows[old_id]["host"] != snapshot[old_id]["host"]:
            raise ReleaseBlocked("historical-deployment-changed")
        snapshot[old_id]["aliases"] = sorted(set(snapshot[old_id]["aliases"]) |
                                               set(rows[old_id]["aliases"]))
    for old_id in sorted(set(rows) - {key}):
        if active_deployment(client, sha, snapshot) != (key, host):
            raise ReleaseBlocked("canonical-changed-during-retirement")
        status, _ = client.request("DELETE",
            f"/accounts/{client.account}/pages/projects/{pages.PROJECT}/deployments/{old_id}?force=true")
        if status != 200:
            raise ReleaseBlocked("historical-deletion-not-confirmed")
    return len(rows) - 1


def verify_postflight(client, sha, snapshot):
    validate_snapshot(snapshot)
    key, host = active_deployment(client, sha, snapshot)
    rows = inventory(client)
    if set(rows) != {key}:
        raise ReleaseBlocked("legacy-deployments-remain")
    old_hosts = {h for row in snapshot.values() for h in [row["host"], *row["aliases"]]}
    old_hosts.update(rows[key]["aliases"])
    require_denial(host, old_hosts)
    return {"verdict": "shadowops-id-guest-denial-observed", "retired_aliases_checked": len(old_hosts - {pages.HOST}),
            "can_activate": False, "signed_in_e2e": "not-performed"}


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("admit", "preflight", "retire", "postflight"))
    parser.add_argument("--run-id", default="")
    parser.add_argument("--game-sha", default="")
    parser.add_argument("--infra-sha", default="")
    parser.add_argument("--inventory-file", type=Path)
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
        if args.run_id or args.infra_sha:
            raise ReleaseBlocked("unexpected-provider-input")
        client = pages.CloudflareClient(os.environ)
        if args.operation == "preflight":
            if args.game_sha:
                raise ReleaseBlocked("unexpected-preflight-sha")
            snapshot = verify_posture(client)
            if args.inventory_file:
                args.inventory_file.write_text(json.dumps(snapshot, sort_keys=True))
            state = {"legacy_deployments": len(snapshot), "can_activate": False,
                     "verdict": "ready-for-protected-replacement-and-retirement"}
        else:
            if not args.inventory_file or not SHA.fullmatch(args.game_sha):
                raise ReleaseBlocked("missing-cutover-snapshot-or-sha")
            snapshot = validate_snapshot(json.loads(args.inventory_file.read_text()))
            if args.operation == "retire":
                if os.environ.get("STARADVS_RETIRE_CONFIRM") != "STARADVS_PUBLISH_AND_RETIRE_OLD_DEPLOYMENTS":
                    raise ReleaseBlocked("retirement-not-approved")
                state = {"retired": retire_legacy(client, args.game_sha, snapshot), "can_activate": False}
                args.inventory_file.write_text(json.dumps(snapshot, sort_keys=True))
            else:
                state = verify_postflight(client, args.game_sha, snapshot)
        print(json.dumps({"operation": args.operation, "project": pages.PROJECT, **state}, sort_keys=True))
        return 0
    except Exception as exc:
        # Never reveal Cloudflare, OCI Vault, Github API response or URL bodies.
        print("STARADVS_PROTECTED_RELEASE_BLOCKED kind=" + type(exc).__name__ +
              (" reason=" + str(exc) if type(exc) is ReleaseBlocked else ""), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
