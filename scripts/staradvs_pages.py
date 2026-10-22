#!/usr/bin/env python3
"""Dedicated Star Adventures *staging* Cloudflare Pages owner; refuses foreign assets.

Mutations require a separate trusted-main workflow admission. This module never
touches the Chess Studio tunnel, Chronicles Pages projects or production DNS.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ZONE = "shadowops.dpdns.org"
HOST = "staging.staradvs.shadowops.dpdns.org"
PROJECT = "staradvs-staging"
TARGET = PROJECT + ".pages.dev"
BASE = "https://" + HOST
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
BAD_DOMAIN_STATUSES = {"blocked", "deactivated", "error"}


class AdmissionError(Exception):
    pass


def required(env: dict[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise AdmissionError("Required Cloudflare credential missing: " + name)
    return value


class CloudflareClient:
    def __init__(self, env: dict[str, str]):
        self.token = required(env, "CLOUDFLARE_API_TOKEN")
        self.account = required(env, "CLOUDFLARE_ACCOUNT_ID")
        if not re.fullmatch(r"[0-9a-fA-F]{32}", self.account):
            raise AdmissionError("Malformed Cloudflare account ID")

    def request(self, method: str, path: str, data: dict | None = None):
        if not path.startswith("/") or ".." in path or "://" in path:
            raise AdmissionError("Unsafe Cloudflare endpoint")
        body = None if data is None else json.dumps(data).encode("utf-8")
        request = urllib.request.Request(
            API + path, method=method, data=body,
            headers={"Authorization": "Bearer " + self.token,
                     "Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                status, content = response.status, response.read(2_000_000)
        except urllib.error.HTTPError as exc:
            status, content = exc.code, exc.read(2_000_000)
        if status == 404:
            return status, None
        if status not in (200, 201):
            raise AdmissionError(f"Cloudflare {method} failed (HTTP {status})")
        try:
            payload = json.loads(content)
        except (ValueError, UnicodeError):
            raise AdmissionError("Malformed Cloudflare response") from None
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise AdmissionError("Cloudflare denied operation")
        return status, payload.get("result")


def paths(account: str, zone: str) -> dict[str, str]:
    project = f"/accounts/{account}/pages/projects/{PROJECT}"
    return {
        "project": project,
        "projects": f"/accounts/{account}/pages/projects",
        "domain": project + "/domains/" + urllib.parse.quote(HOST, safe=""),
        "domains": project + "/domains",
        "dns": f"/zones/{zone}/dns_records",
    }


def inspect(client) -> tuple[str, dict[str, str]]:
    if not HOST.endswith("." + ZONE):
        raise AdmissionError("Staging host outside managed zone")
    query = urllib.parse.urlencode({"name": ZONE, "account.id": client.account})
    _, zones = client.request("GET", "/zones?" + query)
    matching = [z for z in zones if isinstance(z, dict) and z.get("name") == ZONE] if isinstance(zones, list) else []
    if len(matching) != 1 or not matching[0].get("id"):
        raise AdmissionError("Cloudflare zone missing or ambiguous")
    zone = str(matching[0]["id"])
    p = paths(client.account, zone)
    _, existing = client.request("GET", p["dns"] + "?" + urllib.parse.urlencode({"name": HOST, "per_page": "100"}))
    if not isinstance(existing, list):
        raise AdmissionError("Cloudflare DNS inventory invalid")
    records = [r for r in existing if isinstance(r, dict) and r.get("name") == HOST]
    if len(records) > 1:
        raise AdmissionError("Multiple DNS owners for Star Adventures staging")
    if records:
        row = records[0]
        if row.get("type") != "CNAME" or row.get("proxied") is not True or str(row.get("content", "")).rstrip(".") != TARGET:
            raise AdmissionError("Star Adventures staging DNS is owned by another target")
    pstatus, project = client.request("GET", p["project"])
    if pstatus == 200:
        if not isinstance(project, dict) or project.get("name") != PROJECT or project.get("production_branch") != "main":
            raise AdmissionError("Existing Pages project is not Star Adventures staging")
        dstatus, domain = client.request("GET", p["domain"])
        if dstatus == 200:
            if not isinstance(domain, dict) or domain.get("name") != HOST or domain.get("status") in BAD_DOMAIN_STATUSES:
                raise AdmissionError("Existing Pages custom domain mismatches")
        elif dstatus != 404:
            raise AdmissionError("Pages domain lookup failed")
    elif pstatus != 404:
        raise AdmissionError("Pages project lookup failed")
    return zone, {
        "dns": "owned" if records else "absent",
        "project": "owned" if pstatus == 200 else "absent",
        "domain": "owned" if pstatus == 200 and dstatus == 200 else "absent",
    }


def ensure_project(client) -> None:
    zone, _ = inspect(client)
    p = paths(client.account, zone)
    status, project = client.request("GET", p["project"])
    if status == 404:
        _, project = client.request("POST", p["projects"], {"name": PROJECT, "production_branch": "main"})
    if not isinstance(project, dict) or project.get("name") != PROJECT or project.get("production_branch") != "main":
        raise AdmissionError("Pages project reconciliation did not confirm owner")


def ensure_domain(client) -> None:
    zone, _ = inspect(client)
    p = paths(client.account, zone)
    status, project = client.request("GET", p["project"])
    if status != 200 or not isinstance(project, dict) or project.get("name") != PROJECT:
        raise AdmissionError("Dedicated Pages project not found")
    dstatus, domain = client.request("GET", p["domain"])
    if dstatus == 404:
        _, domain = client.request("POST", p["domains"], {"name": HOST})
    if not isinstance(domain, dict) or domain.get("name") != HOST or domain.get("status") in BAD_DOMAIN_STATUSES:
        raise AdmissionError("Dedicated Pages domain not verified")
    # Cloudflare Pages may automatically create the same-zone DNS CNAME.
    _, rows = client.request("GET", p["dns"] + "?" + urllib.parse.urlencode({"name": HOST}))
    if not isinstance(rows, list):
        raise AdmissionError("DNS ownership cannot be rechecked")
    records = [r for r in rows if isinstance(r, dict) and r.get("name") == HOST]
    if not records:
        client.request("POST", p["dns"], {
            "name": HOST, "type": "CNAME", "content": TARGET, "proxied": True, "ttl": 1,
            "comment": "Star Adventures staging Pages (shadowops-infra owner)",
        })
    elif len(records) != 1 or records[0].get("type") != "CNAME" or records[0].get("proxied") is not True or str(records[0].get("content", "")).rstrip(".") != TARGET:
        raise AdmissionError("Refused to replace foreign/ambiguous DNS")
    # An API POST/200 is not evidence that public TLS works.
    inspect(client)


def public_check(expected_sha: str) -> None:
    if not SHA_PATTERN.fullmatch(expected_sha):
        raise AdmissionError("Invalid expected immutable source SHA")
    # urllib verifies TLS certificates by default; no -k/insecure workaround.
    for path, kind in [("/", "html"), ("/release.json", "release")]:
        req = urllib.request.Request(BASE + path, headers={
            "User-Agent": "Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36",
            "Accept": "text/html,application/json,*/*",
            "Cache-Control": "no-cache",
        })
        try:
            with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as response:
                if response.status != 200:
                    raise AdmissionError("Public staging HTTP status is not 200")
                content = response.read(700_000)
                content_type = response.headers.get("Content-Type", "").lower()
        except (urllib.error.URLError, TimeoutError) as exc:
            raise AdmissionError("Public staging HTTPS/DNS/TLS not ready (" + type(exc).__name__ + ")") from None
        if kind == "html":
            if "text/html" not in content_type or b"Star Adventures" not in content or b'id="root"' not in content:
                raise AdmissionError("Public staging root is not the expected Star Adventures game")
            match = re.search(rb'<script[^>]+src="(/assets/[^"]+\.js)"', content)
            if not match:
                raise AdmissionError("Published index lacks Vite JS entrypoint")
            asset = match.group(1).decode("ascii")
            with urllib.request.urlopen(BASE + asset, timeout=15, context=ssl.create_default_context()) as response:
                if response.status != 200 or "javascript" not in response.headers.get("Content-Type", "").lower() or not response.read(64):
                    raise AdmissionError("Published JS is missing or an HTML SPA fallback")
        else:
            if "json" not in content_type:
                raise AdmissionError("Public release manifest has wrong MIME type")
            try:
                obj = json.loads(content)
            except (ValueError, UnicodeDecodeError):
                raise AdmissionError("Public release manifest not JSON") from None
            if not isinstance(obj, dict) or obj.get("build") != expected_sha or obj.get("environment") != "staging":
                raise AdmissionError("Public staging does not serve expected source SHA")
    print("STARADVS_STAGING_HTTPS_SHA_OK " + expected_sha)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("self-test", "preflight", "project", "domain", "verify"))
    parser.add_argument("--sha", default="")
    args = parser.parse_args()
    try:
        if args.operation == "self-test":
            assert HOST == "staging.staradvs.shadowops.dpdns.org" and PROJECT == "staradvs-staging"
            print("STARADVS_PAGES_CONTRACT_OK")
        elif args.operation == "verify":
            public_check(args.sha)
        else:
            client = CloudflareClient(os.environ)
            if args.operation == "preflight":
                _, found = inspect(client)
                print("STARADVS_STAGING_OWNERSHIP_OK " + json.dumps(found, sort_keys=True))
            elif args.operation == "project":
                ensure_project(client)
                print("STARADVS_STAGING_PAGES_PROJECT_OK")
            else:
                ensure_domain(client)
                print("STARADVS_STAGING_DNS_CONFIGURED")
        return 0
    except AdmissionError as exc:
        print("STARADVS_STAGING_BLOCKED " + str(exc), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
