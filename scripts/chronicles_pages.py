#!/usr/bin/env python3
"""ShadowOps-owned convergence for the standalone Chronicles staging Pages hostname.

Matthias central control plane. Credential values never reach output.
This fixed-domain reconciler refuses to overwrite any existing record not already ours.\nDo not call mutating operations until pages_owner_admission.py has verified the\nsource repository's legacy publisher is retired.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ZONE = "shadowops.dpdns.org"
PROJECT = "chronicles-staging"
HOST = "staging.chronicles.shadowops.dpdns.org"
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
            raise RuntimeError("Existing Pages project is not Chronicles staging")
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
        "comment": "Chronicles standalone staging Pages (not Chess Studio)",
    })
    if status not in (200, 201):
        raise RuntimeError("Unable to create dedicated staging DNS CNAME")


def verify() -> None:
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        status, obj = request("GET", domain_path())
        if status != 200 or not isinstance(obj, dict):
            raise RuntimeError("Unable to check Pages custom domain")
        state = obj.get("status")
        if state in {"blocked", "deactivated", "error"}:
            raise RuntimeError("Pages domain activation failed")
        if state == "active":
            try:
                with urllib.request.urlopen("https://" + HOST + "/", timeout=15) as response:
                    page = response.read(200000).decode("utf-8")
                    if response.status == 200 and (
                        "CHRONICLES OF MATTHIAS" in page
                        and "todavía no es el juego" in page
                    ):
                        print("CHRONICLES_PAGES_STAGING_HTTPS_OK " + HOST)
                        return
            except (urllib.error.URLError, UnicodeError):
                pass
        time.sleep(5)
    raise RuntimeError("Pages custom domain HTTPS did not converge")


def self_test() -> None:
    assert HOST.endswith("." + ZONE)
    assert TARGET == "chronicles-staging.pages.dev"
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
