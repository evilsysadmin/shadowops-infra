#!/usr/bin/env python3
"""GET-only evidence for Star Adventures ShadowOps ID staging cutover.

Never provisions Identity, reads a service proof, writes Cloudflare, or
treats anonymous denial as proof of authenticated gameplay.
"""
from __future__ import annotations

import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

import staradvs_pages as pages

ISSUER = "https://id-staging.shadowops.dpdns.org"
CONSUMER = "staradvs"
BINDING = "SHADOWOPS_STARADVS_SERVICE_CREDENTIAL"
EXPECTED_ALIAS = re.compile(r"staradvs-staging(?:-[a-z0-9]+)?\.pages\.dev\Z")
ROUTES = ("/", "/index.html", "/bridge", "/release.json")
METHODS = ("GET", "HEAD")


class CutoverBlocked(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_public(url: str, method: str = "GET") -> tuple[int, bytes]:
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": "ShadowOps-StarAdvs-Cutover-Audit/1.0",
        "Cache-Control": "no-cache", "Accept": "text/html,application/json",
    })
    handler = urllib.request.HTTPSHandler(context=ssl.create_default_context())
    try:
        with urllib.request.build_opener(handler, NoRedirect()).open(req, timeout=10) as res:
            return res.status, res.read(65537)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(65537)
        finally:
            exc.close()
    except (urllib.error.URLError, OSError, TimeoutError):
        return 0, b""


def alias_hosts(project: dict) -> list[str]:
    alias = project.get("subdomain")
    if not isinstance(alias, str) or not EXPECTED_ALIAS.fullmatch(alias):
        raise CutoverBlocked("Pages project alias is unrecognized")
    hosts = {alias}
    for key in ("latest_deployment", "canonical_deployment"):
        deployment = project.get(key)
        if deployment is None:
            continue
        if not isinstance(deployment, dict):
            raise CutoverBlocked("Pages deployment metadata invalid")
        url = deployment.get("url")
        if not isinstance(url, str) or not url:
            raise CutoverBlocked("Pages deployment URL missing")
        try:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port
        except ValueError:
            raise CutoverBlocked("Invalid Pages deployment URL") from None
        if (parsed.scheme != "https" or parsed.username or parsed.password or
                port is not None or parsed.path not in ("", "/") or
                parsed.query or parsed.fragment or
                not parsed.hostname or
                not (parsed.hostname == alias or parsed.hostname.endswith("." + alias))):
            raise CutoverBlocked("Foreign Pages deployment alias")
        hosts.add(parsed.hostname)
    return sorted(hosts)


def pages_posture(project: dict) -> tuple[str, str]:
    if (project.get("name") != pages.PROJECT or project.get("production_branch") != "main" or
            project.get("source")):
        raise CutoverBlocked("Unexpected Pages project owner/branch")
    domains = project.get("domains") or []
    alias = project.get("subdomain")
    if not isinstance(domains, list) or any(
        not isinstance(d, str) or d not in {pages.HOST, alias} for d in domains
    ):
        raise CutoverBlocked("Unexpected Pages custom domains")
    configs = project.get("deployment_configs") or {}
    if not isinstance(configs, dict):
        raise CutoverBlocked("Malformed Pages deployment policy")
    protected = all(
        isinstance(configs.get(mode), dict) and
        configs[mode].get("fail_open") is False and
        isinstance(configs[mode].get("compatibility_flags"), list) and
        "global_fetch_strictly_public" in configs[mode]["compatibility_flags"]
        for mode in ("production", "preview")
    )
    vars_ = (configs.get("production") or {}).get("env_vars") or {}
    if not isinstance(vars_, dict):
        raise CutoverBlocked("Malformed Pages binding metadata")
    binding = vars_.get(BINDING)
    proof = (set(vars_) == {BINDING} and isinstance(binding, dict) and
             binding.get("type") == "secret_text")
    return ("configured" if protected else "not-configured",
            "bound" if proof else "not-bound")


def collect(client, probe=read_public) -> dict:
    # The existing ownership inspector makes GET-only calls.
    zone, owner = pages.inspect(client)
    del zone
    report = {
        "application": CONSUMER, "environment": "staging",
        "identity_login": "not-verified",
        "pages_project": owner["project"],
        "pages_private_policy": "not-verified",
        "pages_app_proof": "not-verified",
        "canonical_guest": "not-verified",
        "pages_alias_guest": "not-verified",
        "signed_in_e2e": "not-performed",
        "can_activate": False,
    }
    status, project = client.request(
        "GET", f"/accounts/{client.account}/pages/projects/{pages.PROJECT}")
    if status not in (200, 404):
        raise CutoverBlocked("Pages inventory unavailable")
    if status == 200:
        if not isinstance(project, dict):
            raise CutoverBlocked("Malformed Pages project")
        report["pages_private_policy"], report["pages_app_proof"] = pages_posture(project)
        aliases = alias_hosts(project)
    else:
        aliases = []

    code, body = probe(ISSUER + "/login?app=staradvs", "GET")
    if (code == 200 and 0 < len(body) <= 65536 and
            b"https://staging.staradvs.shadowops.dpdns.org/?shadowops=central" in body):
        report["identity_login"] = "audience-recognized"
    else:
        report["identity_login"] = "unavailable-or-not-provisioned"

    canonical = [
        probe("https://" + pages.HOST + path, method)[0]
        for path in ROUTES for method in METHODS
    ]
    if all(code == 401 for code in canonical):
        report["canonical_guest"] = "denied-401"
    elif any(code in (200, 206) for code in canonical):
        report["canonical_guest"] = "anonymous-content-observed"
    else:
        report["canonical_guest"] = "unverified-or-unavailable"

    if aliases:
        observed = [
            probe("https://" + host + path, method)[0]
            for host in aliases for path in ("/", "/index.html", "/release.json")
            for method in METHODS
        ]
        if all(code == 404 for code in observed):
            report["pages_alias_guest"] = "denied-404"
        elif any(code in (200, 206) for code in observed):
            report["pages_alias_guest"] = "anonymous-content-observed"
        else:
            report["pages_alias_guest"] = "unverified-or-unavailable"

    # These conditions only admit a *subsequent real signed-in E2E*. Never an
    # automatic DNS/Pages/Identity cutover or production rollout.
    report["next_gate_ready"] = all((
        owner == {"dns": "owned", "project": "owned", "domain": "owned"},
        report["identity_login"] == "audience-recognized",
        report["pages_private_policy"] == "configured",
        report["pages_app_proof"] == "bound",
        report["canonical_guest"] == "denied-401",
        report["pages_alias_guest"] == "denied-404",
    ))
    return report


def main(argv: list[str]) -> int:
    if argv != ["inspect"]:
        print("Usage: staradvs_identity_readiness.py inspect", file=sys.stderr)
        return 64
    try:
        report = collect(pages.CloudflareClient(__import__("os").environ))
    except Exception as exc:
        # No service secret, Cloudflare value or HTTP response content in logs.
        print("STARADVS_IDENTITY_READINESS_BLOCKED kind=" + type(exc).__name__,
              file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["next_gate_ready"] else 10


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
