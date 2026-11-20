#!/usr/bin/env python3
"""Bridge Squad quarantine DNS cutover.

The Pages Worker is ALREADY deployed and deliberately has NO production Identity
service proof. Claiming the canonical hostname here MUST NOT unlock game assets.
Only the exact Pages custom-domain and proxied CNAME writes are possible.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

import bridgesquad_alias_bootstrap as bootstrap
import bridgesquad_pages_readiness as readiness
import bridgesquad_pages_provision as provision
import bridgesquad_source_admission as source

HOST = readiness.HOST
DOMAIN_PATH = "/domains/" + urllib.parse.quote(HOST, safe="")
CHECK_PATHS = ("/", "/index.html", "/release.json",
               "/api/bridgesquad/session", "/_worker.js")
PROOF_PATH = "/api/bridgesquad/session"
PROOF_KEY = "SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL"


class QuarantineError(ValueError):
    pass


class Client(readiness.CloudflareClient):
    """Exactly two scoped POST operations, never a Pages upload or secret edit."""
    def write(self, method: str, path: str, value: dict, *, zone: str) -> dict:
        root = "/accounts/" + self.account + "/pages/projects/" + readiness.PROJECT
        is_domain = method == "POST" and path == root + "/domains" and value == {"name": HOST}
        is_dns = (method == "POST" and path == "/zones/" + zone + "/dns_records"
                  and value == {"type": "CNAME", "name": HOST,
                                "content": readiness.PROJECT + ".pages.dev",
                                "proxied": True, "ttl": 1})
        if not is_domain and not is_dns:
            raise QuarantineError("Noncanonical Cloudflare mutation denied")
        # Same safe status-only Cloudflare error contract as Pages provisioning.
        raw = json.dumps(value, separators=(",", ":")).encode()
        req = urllib.request.Request(
            readiness.API + path, method="POST", data=raw,
            headers={"Authorization": "Bearer " + self._token,
                     "Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as res:
                status, data = res.status, res.read(2_000_001)
        except urllib.error.HTTPError as error:
            status, data = error.code, error.read(2_000_001)
        except urllib.error.URLError:
            raise QuarantineError("Cloudflare write unavailable") from None
        if status not in (200, 201) or len(data) > 2_000_000:
            code = provision.safe_provider_code(data)
            raise QuarantineError("Cloudflare mutation denied HTTP " + str(status)
                                  + (" API " + code if code else ""))
        try:
            response = json.loads(data)
        except (ValueError, UnicodeError):
            raise QuarantineError("Invalid Cloudflare response") from None
        if not isinstance(response, dict) or response.get("success") is not True \
                or not isinstance(response.get("result"), dict):
            raise QuarantineError("Cloudflare mutation unconfirmed")
        return response["result"]


def _safe_env_vars(mode: str, settings: dict, *, allow_bound: bool) -> bool:
    variables = settings.get("env_vars")
    if variables is None:
        variables = {}
    if not isinstance(variables, dict):
        return False
    if not variables:
        return True
    # A single encrypted proof is permitted only AFTER an operator cutover,
    # NEVER for the preview environment nor the DNS attach workflow.
    return (mode == "production" and allow_bound and set(variables) == {PROOF_KEY}
            and isinstance(variables[PROOF_KEY], dict)
            and variables[PROOF_KEY].get("type") == "secret_text")


def project(client, *, allow_bound: bool = False) -> tuple[dict, tuple[str, ...], str]:
    inv = readiness.inspect(client)
    if inv["project"] != "present" or inv["domain"] != inv["dns"]:
        # Partial cutovers must be resumed only by attach(), not accepted
        # as a live readiness receipt.
        if inv["domain"] != "present" or inv["dns"] != "absent":
            raise QuarantineError("Pages ownership or DNS inconsistent")
    path = "/accounts/" + client.account + "/pages/projects/" + readiness.PROJECT
    cfg = client.get(path)
    if not isinstance(cfg, dict) or cfg.get("name") != readiness.PROJECT \
            or cfg.get("production_branch") != "main" or cfg.get("source") \
            or not isinstance(cfg.get("subdomain"), str) \
            or not readiness.ALIAS_PATTERN.fullmatch(cfg["subdomain"]):
        raise QuarantineError("Missing exact owner-only Pages deployment")
    if cfg["subdomain"] != readiness.PROJECT + ".pages.dev":
        raise QuarantineError("Unexpected mutable project alias")
    if set(cfg.get("domains") or []) - {HOST, cfg["subdomain"]}:
        raise QuarantineError("Unexpected Pages custom domain")
    for mode in ("production", "preview"):
        settings = (cfg.get("deployment_configs") or {}).get(mode)
        if (not isinstance(settings, dict) or settings.get("fail_open") is not False
                or "global_fetch_strictly_public" not in (settings.get("compatibility_flags") or [])
                or "global_fetch_private_origin" in (settings.get("compatibility_flags") or [])
                or not _safe_env_vars(mode, settings, allow_bound=allow_bound)):
            raise QuarantineError("Identity proof must remain unbound in quarantine")
    canonical = cfg.get("canonical_deployment")
    trigger = canonical.get("deployment_trigger") if isinstance(canonical, dict) else None
    meta = trigger.get("metadata") if isinstance(trigger, dict) else None
    sha = meta.get("commit_hash") if isinstance(meta, dict) else None
    if not isinstance(sha, str) or not source.SHA.fullmatch(sha):
        raise QuarantineError("No exact canonical game SHA")
    bootstrap._canonical(cfg, sha)
    hosts = bootstrap._hosts(cfg)
    if len(hosts) < 2:
        raise QuarantineError("Immutable Pages alias not visible")
    return cfg, hosts, sha


def prove_aliases(hosts: tuple[str, ...], guest=bootstrap.guest_status) -> None:
    for host in hosts:
        for path in bootstrap.PATHS:
            if guest("https://" + host + path, "GET") != 404:
                raise QuarantineError("Unprotected Pages GET alias")
        for path in ("/", "/index.html", "/release.json"):
            if guest("https://" + host + path, "HEAD") != 404:
                raise QuarantineError("Unprotected Pages HEAD alias")
        if guest("https://" + host + PROOF_PATH, "POST") != 404:
            raise QuarantineError("Unprotected Pages POST alias")


def _zone_id(client) -> str:
    query = urllib.parse.urlencode({"name": readiness.ZONE, "account.id": client.account})
    zones = client.get("/zones?" + query)
    if not isinstance(zones, list):
        raise QuarantineError("Missing managed DNS zone")
    matches = [item for item in zones if isinstance(item, dict)
               and item.get("name") == readiness.ZONE and isinstance(item.get("id"), str)]
    if len(matches) != 1 or not matches[0]["id"]:
        raise QuarantineError("Ambiguous DNS zone ownership")
    return matches[0]["id"]


def _domain_path(client) -> str:
    return "/accounts/" + client.account + "/pages/projects/" + readiness.PROJECT + DOMAIN_PATH


def _dns_path(zone: str) -> str:
    return "/zones/" + urllib.parse.quote(zone, safe="") + "/dns_records"


def _existing_dns(client, zone: str) -> bool:
    path = _dns_path(zone) + "?" + urllib.parse.urlencode({"name": HOST, "per_page": 100})
    records = client.get(path)
    if not isinstance(records, list) or len(records) > 1:
        raise QuarantineError("DNS ownership ambiguous")
    if not records:
        return False
    rec = records[0]
    if not isinstance(rec, dict) or rec.get("name") != HOST \
            or rec.get("type") != "CNAME" or rec.get("proxied") is not True \
            or str(rec.get("content", "")).rstrip(".") != readiness.PROJECT + ".pages.dev":
        raise QuarantineError("Foreign DNS record: refusing takeover")
    return True


def attach(client, *, guest=bootstrap.guest_status) -> dict:
    # No application service secret: the canonical game stays closed to guests.
    cfg, hosts, sha = project(client)
    prove_aliases(hosts, guest)
    zone = _zone_id(client)
    domain = client.get(_domain_path(client))
    dns_exists = _existing_dns(client, zone)
    if dns_exists and domain is None:
        raise QuarantineError("Orphan DNS, cannot adopt")
    if domain is not None and (not isinstance(domain, dict) or domain.get("name") != HOST):
        raise QuarantineError("Foreign Pages custom domain")
    if domain is None:
        result = client.write("POST", _domain_path(client).rsplit("/domains/", 1)[0] + "/domains",
                              {"name": HOST}, zone=zone)
        if result.get("name") != HOST:
            raise QuarantineError("Pages domain was not assigned to Bridge Squad")
    # Re-read the domain before any DNS mutation; partial provider responses
    # are never treated as successful ownership claims.
    confirmed = client.get(_domain_path(client))
    if not isinstance(confirmed, dict) or confirmed.get("name") != HOST:
        raise QuarantineError("Cannot confirm Pages domain ownership")
    if not dns_exists:
        client.write("POST", _dns_path(zone), {
            "type": "CNAME", "name": HOST,
            "content": readiness.PROJECT + ".pages.dev", "proxied": True, "ttl": 1,
        }, zone=zone)
    state = readiness.inspect(client)
    if state["project"] != "present" or state["domain"] != "present" or state["dns"] != "present":
        raise QuarantineError("Cloudflare domain/DNS read-after-write incomplete")
    return {"host": HOST, "dns": "owned", "domain": "owned", "game": "locked",
            "source_sha": sha}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def https_probe(path: str, method="GET") -> tuple[int, dict, bytes]:
    if path not in CHECK_PATHS or method not in ("GET", "HEAD"):
        raise QuarantineError("Unsafe quarantine probe route")
    req = urllib.request.Request("https://" + HOST + path, method=method,
        headers={"User-Agent": "ShadowOps-BridgeSquad-Quarantine/1.0",
                 "Accept": "text/html, application/json"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=12) as res:
            return res.status, dict(res.headers), res.read(16385)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read(16385)
    except (urllib.error.URLError, TimeoutError, OSError):
        raise QuarantineError("Canonical HTTPS not yet reachable") from None


def audit(client, *, guest=bootstrap.guest_status, web=https_probe, allow_bound=False) -> dict:
    state = readiness.inspect(client)
    if state["project"] != "present" or state["domain"] != "present" or state["dns"] != "present":
        raise QuarantineError("Pages host is not configured yet")
    cfg, hosts, sha = project(client, allow_bound=allow_bound)
    prove_aliases(hosts, guest)
    # The real Cloudflare proxy and TLS certificate must resolve on the exact
    # canonical hostname; never accept a Pages alias or proxy redirect.
    try:
        if not socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM):
            raise QuarantineError("No DNS addresses for canonical host")
    except socket.gaierror:
        raise QuarantineError("DNS not yet propagated") from None
    for path in CHECK_PATHS:
        status, headers, body = web(path, "GET")
        if len(body) > 16384:
            raise QuarantineError("Unexpectedly large quarantine response")
        if path in ("/", "/index.html"):
            if status != 401 or b"Tu cuenta ShadowOps ID" not in body \
                    or b"Bridge Squad" not in body \
                    or b"matthias-bridge-squad" in body.lower() \
                    or b"<canvas" in body.lower() \
                    or "text/html" not in str(headers.get("Content-Type", "")).lower() \
                    or "default-src 'none'" not in str(headers.get("Content-Security-Policy", "")):
                raise QuarantineError("Canonical origin is not an auth-only login shell")
        else:
            if status != 401 or body != b'{"error":"authentication_required"}' \
                    or "application/json" not in str(headers.get("Content-Type", "")).lower():
                raise QuarantineError("Canonical origin leaked a protected game asset")
        if headers.get("Set-Cookie") or headers.get("set-cookie") \
                or headers.get("Location") or headers.get("location"):
            raise QuarantineError("Unexpected cookie or redirect on guest response")
    for path in ("/", "/index.html", "/release.json"):
        status, headers, body = web(path, "HEAD")
        if status != 401:
            raise QuarantineError("Guest HEAD must be blocked")
    return {"host": HOST, "https": "401-login-shell",
            "assets": "denied", "aliases": str(len(hosts)),
            "dns": "present", "domain": "present",
            "production_identity": (
                "proof-bound-unverified"
                if (cfg["deployment_configs"]["production"].get("env_vars") or {})
                else "not-provisioned"
            ), "source_sha": sha}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("preflight", "attach", "audit"):
        print("Usage: bridgesquad_dns_quarantine.py preflight|attach|audit", file=sys.stderr)
        return 2
    try:
        client = Client(os.environ)
        if argv[1] == "preflight":
            _, hosts, sha = project(client)
            prove_aliases(hosts)
            result = {"host": HOST, "aliases": str(len(hosts)), "source_sha": sha}
        elif argv[1] == "attach":
            result = attach(client)
        else:
            result = audit(client)
    except (OSError, ValueError, readiness.InventoryError) as exc:
        print("BRIDGESQUAD_QUARANTINE_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1
    print("BRIDGESQUAD_QUARANTINE_" + argv[1].upper() + " " +
          " ".join(f"{k}={v}" for k, v in result.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
