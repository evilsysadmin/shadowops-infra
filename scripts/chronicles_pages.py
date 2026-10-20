#!/usr/bin/env python3
"""ShadowOps-owned convergence for the standalone Chronicles staging Pages hostname.

Matthias central control plane. Credential values never reach output.
This fixed-domain reconciler refuses to overwrite any existing record not already ours.\nDo not call mutating operations until pages_owner_admission.py has verified the\nsource repository's legacy publisher is retired.
"""
from __future__ import annotations

import json
import re
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ZONE = "shadowops.dpdns.org"
# Each environment owns its own Pages project, hostname and DNS record.
ENVIRONMENTS = {
    "staging": ("chronicles-staging", "staging.chronicles.shadowops.dpdns.org"),
    "production": ("chronicles-production", "chronicles.shadowops.dpdns.org"),
}
ENVIRONMENT = os.environ.get("CHRONICLES_PAGES_ENV", "staging").strip() or "staging"
if ENVIRONMENT not in ENVIRONMENTS:
    raise SystemExit("CHRONICLES_PAGES_ENV must be staging or production")
PROJECT, HOST = ENVIRONMENTS[ENVIRONMENT]
TARGET = PROJECT + ".pages.dev"


def require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required secret {name}")
    return value


def request(method: str, path: str, payload: dict | None = None) -> tuple[int, object]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        API + path,
        method=method,
        data=data,
        headers={
            "Authorization": "Bearer " + require("CLOUDFLARE_API_TOKEN"),
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    # Never echo the response body: it may contain unexpected private metadata.
    try:
        body = json.loads(raw) if raw else {}
    except (ValueError, UnicodeError):
        raise RuntimeError(f"Cloudflare {method} failed to return JSON (HTTP {status})") from None
    if status not in (200, 201, 404) or (
        status != 404 and (not isinstance(body, dict) or body.get("success") is False)
    ):
        raise RuntimeError(f"Cloudflare {method} endpoint rejected request (HTTP {status})")
    return status, body.get("result") if isinstance(body, dict) else None


def account_path() -> str:
    return "/accounts/" + require("CLOUDFLARE_ACCOUNT_ID")


def project_path() -> str:
    return account_path() + "/pages/projects/" + PROJECT


def preflight() -> None:
    """Read-only early ownership gate; never hijack existing host DNS or Pages."""
    query = urllib.parse.urlencode({"name": ZONE, "account.id": require("CLOUDFLARE_ACCOUNT_ID")})
    status, zones = request("GET", "/zones?" + query)
    if status != 200 or not isinstance(zones, list):
        raise RuntimeError("Cannot inspect the Cloudflare zone")
    selected = [z for z in zones if isinstance(z, dict) and z.get("name") == ZONE]
    if len(selected) != 1 or not selected[0].get("id"):
        raise RuntimeError("Expected exactly one Cloudflare zone")
    zone = str(selected[0]["id"])
    status, rows = request("GET", "/zones/" + zone + "/dns_records?" +
                           urllib.parse.urlencode({"name": HOST}))
    if status != 200 or not isinstance(rows, list):
        raise RuntimeError("Cannot inspect Chronicles DNS")
    records = [r for r in rows if isinstance(r, dict) and r.get("name") == HOST]
    if len(records) > 1:
        raise RuntimeError("Ambiguous Chronicles DNS: multiple records")
    if records:
        item = records[0]
        if (item.get("type") != "CNAME" or item.get("proxied") is not True
                or str(item.get("content", "")).rstrip(".") != TARGET):
            raise RuntimeError("Existing Chronicles DNS belongs to a different origin")

    status, project = request("GET", project_path())
    if status == 200:
        if (not isinstance(project, dict) or project.get("name") != PROJECT
                or project.get("production_branch") != "main"):
            raise RuntimeError("Existing Pages project is not Chronicles " + ENVIRONMENT)
        domain_status, domain = request("GET", domain_path())
        if domain_status == 200:
            if (not isinstance(domain, dict) or domain.get("name") != HOST
                    or domain.get("status") in {"blocked", "deactivated", "error"}):
                raise RuntimeError("Existing Pages domain does not belong to Chronicles")
        elif domain_status != 404:
            raise RuntimeError("Cannot inspect Pages custom domain")
    elif status != 404:
        raise RuntimeError("Cannot inspect Pages project")
    print("CHRONICLES_PAGES_HOSTNAME_PRECHECK_OK " + HOST)


def ensure_project() -> None:
    status, obj = request("GET", project_path())
    if status == 404:
        status, obj = request("POST", account_path() + "/pages/projects", {
            "name": PROJECT, "production_branch": "main",
        })
        if status not in (200, 201):
            raise RuntimeError("Cloudflare failed to create dedicated Pages project")
    if not isinstance(obj, dict) or obj.get("name") != PROJECT:
        raise RuntimeError("Unexpected Pages project identity")
    if obj.get("production_branch") != "main":
        raise RuntimeError("Pages project branch differs from main: refuse to modify")
    print("Chronicles Pages project ownership OK")


def domain_path() -> str:
    return project_path() + "/domains/" + urllib.parse.quote(HOST, safe="")


def ensure_domain() -> None:
    status, obj = request("GET", domain_path())
    if status == 404:
        status, obj = request("POST", project_path() + "/domains", {"name": HOST})
        if status not in (200, 201):
            raise RuntimeError("Could not create isolated Chronicles Pages domain")
    if not isinstance(obj, dict) or obj.get("name") != HOST:
        raise RuntimeError("Pages custom domain mismatch")
    if obj.get("status") in {"blocked", "deactivated", "error"}:
        raise RuntimeError("Pages custom domain is blocked/errored")
    ensure_dns()
    print("Chronicles Pages custom domain and DNS ownership OK")


def ensure_dns() -> None:
    query = urllib.parse.urlencode({"name": ZONE, "account.id": require("CLOUDFLARE_ACCOUNT_ID")})
    status, zones = request("GET", "/zones?" + query)
    if status != 200 or not isinstance(zones, list):
        raise RuntimeError("Unable to inspect Cloudflare zone")
    selected = [z for z in zones if isinstance(z, dict) and z.get("name") == ZONE]
    if len(selected) != 1 or not selected[0].get("id"):
        raise RuntimeError("Expected exactly one matching Cloudflare zone")
    zone = str(selected[0]["id"])
    dns_path = "/zones/" + zone + "/dns_records"
    status, records = request("GET", dns_path + "?" + urllib.parse.urlencode({"name": HOST}))
    if status != 200 or not isinstance(records, list):
        raise RuntimeError("Unable to inspect target hostname DNS")
    records = [row for row in records if isinstance(row, dict) and row.get("name") == HOST]
    if len(records) > 1:
        raise RuntimeError("Ambiguous Chronicles hostname DNS: refuse to change")
    if records:
        row = records[0]
        if (row.get("type") != "CNAME"
                or str(row.get("content", "")).rstrip(".") != TARGET
                or row.get("proxied") is not True):
            raise RuntimeError("Chronicles hostname already owned by different DNS target")
        return
    status, _ = request("POST", dns_path, {
        "type": "CNAME", "name": HOST, "content": TARGET,
        "proxied": True, "ttl": 1,
        "comment": "Chronicles " + ENVIRONMENT + " Pages (managed by shadowops-infra)",
    })
    if status not in (200, 201):
        raise RuntimeError("Unable to create dedicated Chronicles DNS CNAME")


def probe_https() -> str:
    """Diagnose only the public page; never log raw TLS, DNS, HTTP or page data."""
    try:
        # Exercise the public browser path rather than urllib's default
        # User-Agent, which can be singled out by anti-bot policies. No
        # authentication/cookies, redirects disabled by marker verification,
        # no exceptions to TLS certificate validation.
        browser_request = urllib.request.Request(
            "https://" + HOST + "/",
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml",
            },
        )
        with urllib.request.urlopen(browser_request, timeout=10) as response:
            page = response.read(200000).decode("utf-8")
            if response.status != 200:
                return "http_status"
            if 'Chronicles of Matthias' not in page or '<div id="root"></div>' not in page:
                return "unexpected_content"
            return "ok"
    except urllib.error.HTTPError as exc:
        # The presence of Cloudflare's challenge marker is safe to report;
        # do not expose the response headers, body, or origin details.
        if exc.code == 403 and exc.headers and (
            str(exc.headers.get("cf-mitigated", "")).lower() == "challenge"
        ):
            return "http_403_challenge"
        # HTTP status is non-sensitive, unlike the response body or headers.
        # Separate a 403 policy denial from Pages origin 522/525 or 404.
        if isinstance(exc.code, int) and 400 <= exc.code <= 599:
            return "http_" + str(exc.code)
        return "http_error"
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLError):
            return "tls_error"
        if isinstance(exc.reason, socket.gaierror):
            return "dns_error"
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            return "timeout"
        return "connection_error"
    except (UnicodeError, TimeoutError, socket.timeout):
        return "invalid_response"



# Only exact, same-origin assets for the real independent exploration preview.
# Source SHA is still admitted by ShadowOps before publication.
EXPLORATION_ASSETS = (
    ("map", "/game/crypt-map.js", b"export const CRYPT_MAP"),
    ("rules", "/game/exploration-core.js", b"export function explorationStep"),
    ("viewport", "/game/exploration-preview.js", b"mountExplorationPreview"),
    ("forge", "/game/party-preview.js", b"mountPartyForge"),
)


def probe_exploration_assets() -> str:
    """Reject 200 HTML fallbacks and missing JS without printing response data."""
    for name, path, marker in EXPLORATION_ASSETS:
        browser_request = urllib.request.Request(
            "https://" + HOST + path,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
                ),
                "Accept": "text/javascript,application/javascript,*/*",
            },
        )
        try:
            with urllib.request.urlopen(browser_request, timeout=10) as response:
                mime = str(response.headers.get("Content-Type", "")).lower()
                if response.status != 200 or "javascript" not in mime:
                    return name + "_response"
                if marker not in response.read(300000):
                    return name + "_content"
        except urllib.error.HTTPError as exc:
            status = exc.code if isinstance(exc.code, int) and 400 <= exc.code <= 599 else None
            return name + ("_http_" + str(status) if status else "_http_error")
        except (urllib.error.URLError, TimeoutError, socket.timeout, UnicodeError):
            return name + "_unavailable"
    return "ok"



def probe_react_preview(
    path: str = "/react/",
    assets: bytes = b"/react/assets/",
    manifest_path: str | None = "/react/manifest.webmanifest",
) -> str:
    """Prove the isolated built React entry, JS and CSS on the public HTTPS host.

    Never follow an asset outside the expected /react/assets/ path, and never
    return provider response bodies, redirects or headers in CI diagnostics.
    """
    def get_public(path: str, accept: str):
        req = urllib.request.Request(
            "https://" + HOST + path,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
                ),
                "Accept": accept,
            },
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status != 200 or response.geturl() != req.full_url:
                return "", b""
            return str(response.headers.get("Content-Type", "")).lower(), response.read(500000)

    try:
        html_type, html = get_public(path, "text/html,application/xhtml+xml")
        if "text/html" not in html_type or not (
            b'<div id="root"></div>' in html
            and b'Chronicles of Matthias' in html
        ):
            return "html_missing"
        asset = re.escape(assets) + rb'[A-Za-z0-9._-]+'
        # Entry points only: the module script and the stylesheet. Vite also
        # emits <link rel="modulepreload"> for vendor chunks; those are not
        # entries and must not make the reference ambiguous.
        entries = {
            "js": set(re.findall(rb'<script\b[^>]*\bsrc="(' + asset + rb'\.js)"', html)),
            "css": set(re.findall(rb'<link\b[^>]*\brel="stylesheet"[^>]*\bhref="(' + asset + rb'\.css)"', html)),
        }
        for extension in ("js", "css"):
            urls = sorted(path.decode("ascii") for path in entries[extension])
            if len(urls) != 1:
                return extension + "_reference"
            mime, content = get_public(urls[0],
                "text/javascript,application/javascript,*/*" if extension == "js" else "text/css,*/*")
            if extension == "js" and "javascript" not in mime:
                return "js_mime"
            if extension == "css" and "text/css" not in mime:
                return "css_mime"
            if len(content) < 128 or content.lstrip().lower().startswith(b"<"):
                return extension + "_content"
        if manifest_path is None:
            return "ok"
        # Installed standalone Chronicles must advertise landscape. The
        # ordinary Brave tab still requires a user gesture and browser API.
        _, manifest_bytes = get_public(
            manifest_path, "application/manifest+json,application/json,*/*"
        )
        try:
            manifest = json.loads(manifest_bytes)
        except (ValueError, UnicodeDecodeError):
            return "manifest_content"
        if not isinstance(manifest, dict) or (
            manifest.get("orientation") != "landscape"
            or manifest.get("display") != "standalone"
            or manifest.get("start_url") != "./"
        ):
            return "manifest_content"
    except urllib.error.HTTPError as exc:
        return "http_" + str(exc.code) if isinstance(exc.code, int) and 400 <= exc.code <= 599 else "http_error"
    except (urllib.error.URLError, TimeoutError, socket.timeout, UnicodeError, ValueError):
        return "unavailable"
    return "ok"


def safe_domain_state(value: object) -> str:
    """Allowlisted Cloudflare state only: never print untrusted API payloads."""
    return value if isinstance(value, str) and value in {
        "active", "pending", "initializing", "verifying",
        "pending_validation", "pending_issuance", "pending_deployment",
    } else "unknown"


def verify(timeout_seconds: int = 120) -> None:
    # Domain activation and certificate issuance may take much longer than a
    # CI job. Fail closed with actionable status rather than burning ten minutes
    # and emitting a generic timeout. Never disable TLS verification.
    deadline = time.monotonic() + timeout_seconds
    last_state, last_probe = "unknown", "not_checked"
    while time.monotonic() < deadline:
        status, obj = request("GET", domain_path())
        if status != 200 or not isinstance(obj, dict):
            raise RuntimeError("Unable to check Pages custom domain")
        state = obj.get("status")
        if state in {"blocked", "deactivated", "error"}:
            raise RuntimeError("Pages domain activation failed")
        last_state = safe_domain_state(state)
        # Probe even when Pages is pending: a single missing custom certificate
        # otherwise hides behind ten minutes of silent status polling.
        last_probe = probe_https()
        # New Pages custom domains may report 'pending' after their HTTPS
        # endpoint is already functional. For production, accept that lag
        # ONLY if verified HTTPS and the complete same-origin game pass below;
        # the workflow separately verifies the exact public release SHA.
        serving = state == "active" or (ENVIRONMENT == "production" and state == "pending")
        if serving and last_probe == "ok":
            # The root serves the verbatim Chess Studio game build (Vite):
            # exactly one entry JS and one CSS under /assets/, same origin.
            home_result = probe_react_preview(path="/", assets=b"/assets/", manifest_path=None)
            if home_result == "ok":
                print("CHRONICLES_PAGES_" + ENVIRONMENT.upper() + "_HTTPS_OK " + HOST)
                print("CHRONICLES_PAGES_HOME_GAME_OK " + HOST)
                return
            last_probe = "home_" + home_result
        time.sleep(5)
    reason = (
        "Pages custom domain HTTPS did not converge"
        + " (domain_status=" + last_state + ", https_probe=" + last_probe + ")"
    )
    if last_probe == "tls_error":
        reason += (
            "; confirm a valid edge certificate for this deeper-level hostname"
            " (Universal SSL alone covers only one level in full-zone setup)"
        )
    raise RuntimeError(reason)


def self_test() -> None:
    assert HOST.endswith("." + ZONE)
    assert TARGET == f"chronicles-{ENVIRONMENT}.pages.dev"
    assert ENVIRONMENTS["production"][1] == "chronicles." + ZONE
    assert ENVIRONMENTS["staging"][0] != ENVIRONMENTS["production"][0]
    assert PROJECT != "chess-studio-staging"
    assert HOST != "staging.chess-studio.shadowops.dpdns.org"
    assert "chess-studio" not in PROJECT
    # Mismatched DNS records MUST NOT be overwritten:
    from unittest.mock import patch
    os.environ.setdefault("CLOUDFLARE_ACCOUNT_ID", "test-account")
    def fake_request(method, path, payload=None):
        if path.startswith("/zones?"):
            return 200, [{"name": ZONE, "id": "test-zone"}]
        if "/dns_records?" in path:
            return 200, [{"name": HOST, "type": "CNAME", "content": "other.pages.dev", "proxied": True}]
        raise AssertionError(f"Unexpected DNS write {method}")
    with patch(__name__ + ".request", side_effect=fake_request):
        try:
            ensure_dns()
        except RuntimeError as exc:
            assert "already owned" in str(exc)
        else:
            raise AssertionError("Existing unrelated DNS route was overwritten")
    print("Chronicles Pages ownership self-test OK")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("preflight", "project", "domain", "verify", "self-test"))
    args = parser.parse_args()
    try:
        {"preflight": preflight, "project": ensure_project, "domain": ensure_domain,
         "verify": verify, "self-test": self_test}[args.operation]()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
