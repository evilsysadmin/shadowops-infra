#!/usr/bin/env python3
"""GET-only evidence for Star Adventures ShadowOps ID staging cutover.

Never provisions Identity, reads a service proof, writes Cloudflare, or
treats anonymous denial as proof of authenticated gameplay.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

import staradvs_pages as pages
import pages_access_readiness as access

ISSUER = "https://id-staging.shadowops.dpdns.org"
CONSUMER = "staradvs"
BINDING = "SHADOWOPS_STARADVS_SERVICE_CREDENTIAL"
EXPECTED_ALIAS = re.compile(r"staradvs-staging(?:-[a-z0-9]+)?\.pages\.dev\Z")
ROUTES = ("/", "/index.html", "/bridge", "/release.json")
METHODS = ("GET", "HEAD")
ACCESS_SCOPES = ("main", "immutable", "custom_companion")
MAX_HISTORY_PAGES = 8
MAX_HISTORY_ALIASES = 192


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



def historical_alias_hosts(client, project: dict, *, max_hosts: int = 64,
                           page: int = 1) -> tuple[list[str], int, int | None]:
    """Read one bounded Pages history page. Never certify full history.

    Cloudflare's live API has returned HTTP 400 for explicit page/per_page
    parameters on multiple owned projects; the bare GET is independently
    exercised by the shared games history audit. Record provider result_info
    only as a count hint, not proof of complete history (even on empty samples).
    """
    if type(page) is not int or page < 1 or page > MAX_HISTORY_PAGES:
        raise CutoverBlocked("Unapproved Pages history probe page")
    alias = project["subdomain"]
    path = f"/accounts/{client.account}/pages/projects/{pages.PROJECT}/deployments"
    # The bare first page and page=2 alone were proven against Cloudflare;
    # keep per_page out of requests (that combination returned HTTP 400).
    if page > 1:
        path += f"?page={page}"
    status, deployments, metadata = client.request_with_info(path)
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
    total = None
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise CutoverBlocked("Malformed Pages pagination metadata")
        if "total_count" in metadata:
            total = metadata["total_count"]
            if (type(total) is not int or total < len(deployments) or
                    type(metadata.get("page")) is not int or metadata["page"] != page or
                    type(metadata.get("count")) is not int or metadata["count"] != len(deployments) or
                    type(metadata.get("per_page")) is not int or
                    metadata["per_page"] < len(deployments)):
                raise CutoverBlocked("Contradictory Pages pagination metadata")
    return sorted(hosts), len(deployments), total


def history_guest_assessment(hosts: list[str], probe=read_public) -> tuple[str, dict]:
    """Aggregate per-host guest results without disclosing historical URLs."""
    counts = {"exposed": 0, "denied": 0, "unverified": 0}
    if not hosts:
        return "not-verified", counts
    checks = [("https://" + host + path, "GET")
              for host in hosts for path in ("/", "/release.json")]
    with ThreadPoolExecutor(max_workers=12) as pool:
        codes = list(pool.map(lambda check: probe(*check)[0], checks))
    for index in range(0, len(codes), 2):
        pair = codes[index:index + 2]
        if any(code in (200, 206) for code in pair):
            counts["exposed"] += 1
        elif all(code == 404 for code in pair):
            counts["denied"] += 1
        else:
            # Includes network failures, redirects, and inconsistent denial.
            counts["unverified"] += 1
    state = (
        "anonymous-content-observed" if counts["exposed"] else
        "denied-404" if counts["denied"] == len(hosts) else
        "unverified-or-unavailable"
    )
    return state, counts


def history_guest_status(hosts: list[str], probe=read_public) -> str:
    """Backwards-compatible status facade for the historical probe."""
    return history_guest_assessment(hosts, probe)[0]


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


def collect(client, probe=read_public, *, access_client=None) -> dict:
    # The existing ownership inspector makes GET-only calls.
    zone, owner = pages.inspect(client)
    del zone
    report = {
        "application": CONSUMER, "environment": "staging",
        "identity_login": "not-verified",
        "pages_project": owner["project"],
        "pages_private_policy": "not-verified",
        "pages_app_proof": "not-verified",
        "cloudflare_access": "not-verified",
        "cloudflare_access_scopes": {k: "not-verified" for k in ACCESS_SCOPES},
        "canonical_guest": "not-verified",
        "pages_alias_guest": "not-verified",
        "pages_historical_guest": "not-verified",
        "historical_inventory_complete": False,
        "historical_deployments_scanned": 0,
        "historical_pages_scanned": 0,
        "historical_enumeration_status": "not-attempted",
        "historical_deployments_reported_total": None,
        "historical_page2_status": "not-requested",
        "historical_page2_deployments_indexed": 0,
        "historical_page2_aliases_indexed": 0,
        "historical_aliases_scanned": 0,
        "historical_aliases_exposed": 0,
        "historical_aliases_denied": 0,
        "historical_aliases_unverified": 0,
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
            history, count, total = historical_alias_hosts(client, project)
            report["historical_deployments_reported_total"] = total
            report["historical_deployments_scanned"] = count
            report["historical_aliases_scanned"] = len(history)
            # Query only this verified, owned Pages project. Keep the first
            # successful page even when later pages fail; never print hosts.
            seen = set(history)
            signatures = {tuple(history)}
            pages_seen = 1
            scanned = count
            report["historical_pages_scanned"] = 1
            report["historical_enumeration_status"] = "partial-or-unverified"
            if total is not None and total > count:
                for page_number in range(2, MAX_HISTORY_PAGES + 1):
                    try:
                        hosts, n, reported = historical_alias_hosts(
                            client, project, max_hosts=MAX_HISTORY_ALIASES,
                            page=page_number
                        )
                    except pages.AdmissionError:
                        if page_number == 2:
                            report["historical_page2_status"] = "provider-unavailable"
                        report["historical_enumeration_status"] = "provider-unavailable"
                        break
                    if page_number == 2:
                        report["historical_page2_deployments_indexed"] = n
                        report["historical_page2_aliases_indexed"] = len(hosts)
                    signature = tuple(hosts)
                    problem = (
                        "total-drift-or-unknown" if reported != total else
                        "unexpected-empty" if n == 0 else
                        "count-inconsistent" if n > total - scanned else
                        "repeated-first-page" if signature in signatures else
                        "alias-cap-exceeded" if len(seen | set(hosts)) > MAX_HISTORY_ALIASES else
                        None
                    )
                    if problem:
                        if page_number == 2:
                            report["historical_page2_status"] = problem
                        report["historical_enumeration_status"] = problem
                        break
                    if page_number == 2:
                        report["historical_page2_status"] = "distinct-page-observed"
                    signatures.add(signature)
                    seen.update(hosts)
                    scanned += n
                    pages_seen += 1
                    report["historical_pages_scanned"] = pages_seen
                    report["historical_deployments_scanned"] = scanned
                    report["historical_aliases_scanned"] = len(seen)
                    if scanned == total:
                        report["historical_enumeration_status"] = "reported-total-observed"
                        break
                else:
                    report["historical_enumeration_status"] = "page-limit-reached"
            history = sorted(seen)
            # Deliberate safety invariant: matching provider total is NOT
            # proof that unlisted historical URLs or Access policies are safe.
            # The future activation gate requires independent confirmation.
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
        status, counts = history_guest_assessment(history, probe)
        report["historical_aliases_exposed"] = counts["exposed"]
        report["historical_aliases_denied"] = counts["denied"]
        report["historical_aliases_unverified"] = counts["unverified"]
        # A 404 from sampled hosts is useful evidence, NOT full coverage.
        report["pages_historical_guest"] = (
            "sample-denied-404" if status == "denied-404" else status
        )

    # Independent Access read-only token, never Pages write token.
    # Inspect only Star Adventures policy details, retaining account-wide
    # application overlap detection so a foreign policy cannot hide a bypass.
    if access_client is not None:
        try:
            access_report = access.inspect(access_client, project_filter=pages.PROJECT)
        except access.ReadinessError:
            report["cloudflare_access"] = "inventory-unavailable"
        else:
            scopes = access_report["projects"][0]["application_scopes"]
            report["cloudflare_access_scopes"] = scopes
            report["cloudflare_access"] = (
                "restricted-policy-candidate"
                if all(scopes[name] == "restricted-policy-candidate" for name in ACCESS_SCOPES)
                else "remediation-required"
            )

    # These conditions only admit a *subsequent real signed-in E2E*. Never an
    # automatic DNS/Pages/Identity cutover or production rollout.
    report["next_gate_ready"] = all((
        owner == {"dns": "owned", "project": "owned", "domain": "owned"},
        report["identity_login"] == "audience-recognized",
        report["pages_private_policy"] == "configured",
        report["pages_app_proof"] == "bound",
        report["cloudflare_access"] == "restricted-policy-candidate",
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
        # Missing Access-read credential cannot turn metadata into a green gate.
        try:
            access_client = access.AccessClient(os.environ)
        except access.ReadinessError:
            access_client = None
        report = collect(pages.CloudflareClient(os.environ),
                         access_client=access_client)
        if access_client is None:
            report["cloudflare_access"] = "read-token-unconfigured"
    except Exception as exc:
        # No service secret, Cloudflare value or HTTP response content in logs.
        print("STARADVS_IDENTITY_READINESS_BLOCKED kind=" + type(exc).__name__,
              file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["next_gate_ready"] else 10


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
