#!/usr/bin/env python3
"""One-time Bridge Squad Pages bootstrap: GET-only pre/postflight and guest-denial proof.

This module never mutates Cloudflare. The separate protected workflow owns the
single Wrangler direct upload and must never attach DNS or a custom domain.
"""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.parse
import urllib.request

import bridgesquad_pages_readiness as readiness
import bridgesquad_source_admission as source

PATHS = ("/", "/index.html", "/release.json", "/_worker.js",
         "/_shadowops/session.js", "/api/bridgesquad/session")
METHODS = ("GET", "HEAD", "POST")


class BootstrapBlocked(ValueError):
    pass


def _project(client, *, require_empty: bool) -> dict:
    inventory = readiness.inspect(client)
    if inventory != {
        "project": "present", "domain": "absent", "dns": "absent",
        "identity_gate": "not-verified", "deployment": "not-verified",
    }:
        raise BootstrapBlocked("Dedicated project must have no domain or DNS")
    path = "/accounts/" + client.account + "/pages/projects/" + readiness.PROJECT
    project = client.get(path)
    if not isinstance(project, dict) or project.get("name") != readiness.PROJECT:
        raise BootstrapBlocked("Unknown Pages project")
    if project.get("production_branch") != "main" or project.get("source"):
        raise BootstrapBlocked("Only Infra-owned Direct Upload project allowed")
    alias = project.get("subdomain")
    if not isinstance(alias, str) or not readiness.ALIAS_PATTERN.fullmatch(alias):
        raise BootstrapBlocked("Unknown Pages project alias")
    if set(project.get("domains") or []) - {alias}:
        raise BootstrapBlocked("Unexpected Pages custom domain")
    configs = project.get("deployment_configs")
    if not isinstance(configs, dict):
        raise BootstrapBlocked("Unknown Pages configuration")
    for mode in ("production", "preview"):
        cfg = configs.get(mode)
        if (not isinstance(cfg, dict) or cfg.get("fail_open") is not False
                or "global_fetch_strictly_public" not in (cfg.get("compatibility_flags") or [])
                or "global_fetch_private_origin" in (cfg.get("compatibility_flags") or [])):
            raise BootstrapBlocked("Pages Functions must fail closed")
        if cfg.get("env_vars"):
            # This bootstrap never borrows a staging Identity proof.
            raise BootstrapBlocked("Unexpected preexisting Identity/env bindings")
    if require_empty:
        if project.get("latest_deployment") is not None or project.get("canonical_deployment") is not None:
            raise BootstrapBlocked("One-time bootstrap refuses to overwrite existing deployments")
    return project


def _hosts(project: dict) -> tuple[str, ...]:
    alias = project["subdomain"]
    hosts = {alias}
    for key in ("latest_deployment", "canonical_deployment"):
        value = project.get(key)
        if value is None:
            continue
        if not isinstance(value, dict):
            raise BootstrapBlocked("Pages deployment metadata invalid")
        url = value.get("url")
        if not isinstance(url, str) or not url:
            raise BootstrapBlocked("Pages deployment alias missing")
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.username or parsed.password
                or parsed.port is not None or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment
                or not (parsed.hostname == alias or parsed.hostname.endswith("." + alias))):
            raise BootstrapBlocked("Foreign immutable Pages deployment alias")
        hosts.add(parsed.hostname)
    return tuple(sorted(hosts))


def _canonical(project: dict, sha: str) -> None:
    if not source.SHA.fullmatch(sha):
        raise BootstrapBlocked("Exact game SHA required")
    deployment = project.get("canonical_deployment")
    if not isinstance(deployment, dict):
        raise BootstrapBlocked("Pages canonical deployment missing")
    trigger = deployment.get("deployment_trigger")
    meta = trigger.get("metadata") if isinstance(trigger, dict) else None
    latest = deployment.get("latest_stage")
    if (deployment.get("environment") != "production"
            or deployment.get("is_skipped") is not False
            or not isinstance(latest, dict) or latest.get("status") != "success"
            or not isinstance(trigger, dict) or trigger.get("type") != "ad_hoc"
            or not isinstance(meta, dict) or meta.get("branch") != "main"
            or meta.get("commit_dirty") is not False or meta.get("commit_hash") != sha):
        raise BootstrapBlocked("Canonical deployment is not exact audited game source")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def guest_status(url: str, method: str = "GET") -> int:
    """Observe HTTP status only. No response bodies, cookies or secrets logged."""
    req = urllib.request.Request(
        url, method=method, headers={"User-Agent": "ShadowOps-BridgeSquad-GuestAudit/1.0"},
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(req, timeout=12) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, TimeoutError):
        raise BootstrapBlocked("Pages alias HTTPS unavailable") from None


def preflight(client) -> dict:
    project = _project(client, require_empty=True)
    return {"project": readiness.PROJECT, "alias": project["subdomain"], "status": "empty-private"}


def postflight(client, expected_sha: str, status=guest_status) -> dict:
    project = _project(client, require_empty=False)
    _canonical(project, expected_sha)
    hosts = _hosts(project)
    if len(hosts) < 1:
        raise BootstrapBlocked("No verified Pages alias")
    for host in hosts:
        for path in PATHS:
            if status("https://" + host + path, "GET") != 404:
                raise BootstrapBlocked("Pages alias permits unauthenticated GET")
        for path in ("/", "/index.html", "/release.json"):
            if status("https://" + host + path, "HEAD") != 404:
                raise BootstrapBlocked("Pages alias permits unauthenticated HEAD")
        if status("https://" + host + "/api/bridgesquad/session", "POST") != 404:
            raise BootstrapBlocked("Pages alias permits unauthenticated POST")
    return {"project": readiness.PROJECT, "aliases": len(hosts),
            "anonymous_access": "denied", "source_sha": expected_sha,
            "domain": "absent", "dns": "absent", "identity": "not-provisioned"}


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3) or argv[1] not in ("preflight", "postflight"):
        print("Usage: bridgesquad_alias_bootstrap.py preflight|postflight SOURCE_SHA", file=sys.stderr)
        return 2
    if (argv[1] == "preflight" and len(argv) != 2) or (argv[1] == "postflight" and len(argv) != 3):
        return 2
    try:
        client = readiness.CloudflareClient(os.environ)
        result = preflight(client) if argv[1] == "preflight" else postflight(client, argv[2])
    except (OSError, ValueError, readiness.InventoryError) as exc:
        print("BRIDGESQUAD_ALIAS_BOOTSTRAP_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1
    prefix = "BRIDGESQUAD_ALIAS_PREFLIGHT" if argv[1] == "preflight" else "BRIDGESQUAD_ALIAS_DENIAL_VERIFIED"
    print(prefix + " " + " ".join(k + "=" + str(v) for k, v in result.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
