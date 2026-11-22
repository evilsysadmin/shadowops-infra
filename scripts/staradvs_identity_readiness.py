#!/usr/bin/env python3
"""GET-only evidence for Star Adventures ShadowOps ID staging cutover.

Never provisions Identity, reads a service proof, writes Cloudflare, or
treats anonymous denial as proof of authenticated gameplay.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
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



def historical_alias_hosts(client, project: dict, *, max_hosts: int = 64) -> tuple[list[str], int]:
    """Probe the *observed* first Pages history page. Never certify full history.

    Cloudflare's live API has returned HTTP 400 for explicit page/per_page
    parameters on multiple owned projects; the bare GET is independently
    exercised by the shared games history audit. The current Cloudflare client
    strips result_info, so a successful response is always a PARTIAL sample,
    including an empty one. No caller can infer complete coverage from it.
    """
    alias = project["subdomain"]
    path = f"/accounts/{client.account}/pages/projects/{pages.PROJECT}/deployments"
    status, deployments = client.request("GET", path)
    if status != 200 or not isinstance(deployments, list) or len(deployments) > 100:
        raise CutoverBlocked("Pages historical deployment sample unavailable")
    hosts: set[str] = set()
    for deployment in deployments:
        if not isinstance(deployment, dict) or deployment.get("project_name") not in (None, pages.PROJECT):
            raise CutoverBlocked("Foreign or malformed Pages deployment")
        aliases = deployment.get("aliases") or []
        if not isinstance(aliases, list) or any(not isinstance(x, str) for x in aliases):
            raise CutoverBlocked("Malformed historical alias list")
        for value in [deployment.get("url"), *aliases]:
            if not isinstance(value, str) or not value:
                raise CutoverBlocked("Pages history missing URL")
            try:
                parsed = urllib.parse.urlsplit(value)
                port = parsed.port
            except ValueError:
                raise CutoverBlocked("Malformed historical deployment URL") from None
            host = parsed.hostname
            if (parsed.scheme != "https" or parsed.username or parsed.password or
                    port is not None or parsed.path not in ("", "/") or
                    parsed.query or parsed.fragment or not host or
                    not (host == alias or host.endswith("." + alias) or
                         host == pages.HOST)):
                raise CutoverBlocked("Foreign historical Pages alias")
            if host != pages.HOST:  # Canonical host is checked separately.
                hosts.add(host)
            if len(hosts) > max_hosts:
                raise CutoverBlocked("Pages alias sample exceeds bounded probe capacity")
    return sorted(hosts), len(deployments)


def history_guest_status(hosts: list[str], probe=read_public) -> str:
    """Require anonymous GET denial on both root and immutable release URL."""
    if not hosts:
        return "not-verified"
    checks = [("https://" + host + path, "GET")
              for host in hosts for path in ("/", "/release.json")]
    # Keep the total audit bounded even when many old links are unreachable.
    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(lambda check: probe(*check)[0], checks))
    if all(code == 404 for code in codes):
        return "denied-404"
    if any(code in (200, 206) for code in codes):
        return "anonymous-content-observed"
    return "unverified-or-unavailable"


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
        "pages_historical_guest": "not-verified",
        "historical_inventory_complete": False,
        "historical_deployments_scanned": 0,
        "historical_aliases_scanned": 0,
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
        try:
            history, count = historical_alias_hosts(client, project)
            report["historical_deployments_scanned"] = count
            report["historical_aliases_scanned"] = len(history)
        except pages.AdmissionError:
            # The provider can reject even the bare GET. Pending means neither
            # missing permission nor complete/empty history can be inferred.
            # Never expose provider bodies or downgrade malformed URL errors.
            history = []
            report["pages_historical_guest"] = "inventory-unavailable"
    else:
        aliases = []
        history = []

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

    if history:
        status = history_guest_status(history, probe)
        # A 404 from sampled hosts is useful evidence, NOT full coverage.
        report["pages_historical_guest"] = (
            "sample-denied-404" if status == "denied-404" else status
        )

    # These conditions only admit a *subsequent real signed-in E2E*. Never an
    # automatic DNS/Pages/Identity cutover or production rollout.
    report["next_gate_ready"] = all((
        owner == {"dns": "owned", "project": "owned", "domain": "owned"},
        report["identity_login"] == "audience-recognized",
        report["pages_private_policy"] == "configured",
        report["pages_app_proof"] == "bound",
        report["canonical_guest"] == "denied-401",
        report["pages_alias_guest"] == "denied-404",
        report["historical_inventory_complete"] is True,
        report["pages_historical_guest"] == "denied-404",
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
