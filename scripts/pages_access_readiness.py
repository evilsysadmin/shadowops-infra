#!/usr/bin/env python3
"""Inspect Cloudflare Access for historical Pages bypasses; GET only, no writes.

Access on Pages previews does NOT cover the base <project>.pages.dev host.
This tool demands separate exact root, wildcard, and companion custom-domain
destinations before calling an environment ready for *further testing*.

App metadata or an Access sign-in redirect alone cannot establish that all
historical URLs are protected or that ShadowOps ID gameplay still works.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID

API = "https://api.cloudflare.com/client/v4"
HOSTS = {
    "chronicles-staging": "staging.chronicles.shadowops.dpdns.org",
    "chronicles-production": "chronicles.shadowops.dpdns.org",
    "staradvs-staging": "staging.staradvs.shadowops.dpdns.org",
}
UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
ACCOUNT_PATTERN = re.compile(r"[0-9a-fA-F]{32}\Z")
VALID_ACTIONS = {"allow", "deny"}
# A narrow allow rule must name an individual operator, not a domain,
# network range, Everyone, arbitrary Access group or all-service-token match.
EXACT_OPERATOR_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")
MAX_APPS = 100
MAX_POLICIES = 100


class ReadinessError(Exception):
    pass


class AccessClient:
    """Independent Access: Apps and Policies Read token; no Pages write token."""
    def __init__(self, env):
        account = env.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        token = env.get("CLOUDFLARE_ACCESS_READ_TOKEN", "").strip()
        if not ACCOUNT_PATTERN.fullmatch(account) or not token:
            raise ReadinessError("Access read-only account/token not configured")
        self.account = account
        self._token = token

    def get(self, path):
        if not isinstance(path, str) or not path.startswith("/accounts/" + self.account + "/access/apps"):
            raise ReadinessError("Access endpoint outside approved account")
        if any(v in path for v in ("?", "..", "//", "#")) or not re.fullmatch(
            r"/accounts/[0-9a-fA-F]{32}/access/apps(?:/[0-9a-f-]{36}/policies)?", path
        ):
            raise ReadinessError("Access endpoint not allowlisted")
        req = urllib.request.Request(API + path, method="GET", headers={
            "Authorization": "Bearer " + self._token,
            "Accept": "application/json",
            "User-Agent": "ShadowOps-Pages-Access-Readiness/1.0",
        })
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                NoRedirect())
            with opener.open(req, timeout=15) as res:
                raw, status = res.read(1_000_001), res.status
        except urllib.error.HTTPError as exc:
            exc.close()
            raise ReadinessError("Access inventory rejected: HTTP " + str(exc.code)) from None
        except (OSError, urllib.error.URLError, TimeoutError):
            raise ReadinessError("Access API unavailable") from None
        if status != 200 or len(raw) > 1_000_000:
            raise ReadinessError("Access inventory response not bounded HTTP 200")
        try:
            obj = json.loads(raw)
        except (UnicodeError, ValueError):
            raise ReadinessError("Access response invalid JSON") from None
        if not isinstance(obj, dict) or obj.get("success") is not True:
            raise ReadinessError("Access returned no approved inventory")
        return obj


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_apps(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("result"), list):
        raise ReadinessError("Access applications missing")
    apps = payload["result"]
    info = payload.get("result_info")
    if len(apps) > MAX_APPS:
        raise ReadinessError("Access app inventory too large")
    if not isinstance(info, dict):
        raise ReadinessError("Access pagination not independently verified")
    # Never treat a possibly truncated first page as a complete Access census.
    if (type(info.get("total_pages")) is not int or info["total_pages"] != 1
            or type(info.get("count")) is not int or info["count"] != len(apps)
            or type(info.get("total_count")) is not int or info["total_count"] != len(apps)):
        raise ReadinessError("Access applications inventory partial")
    return apps


def normalized_destination(value):
    if not isinstance(value, str) or not value or len(value) > 255:
        return None
    if value.startswith("https://"):
        value = value[len("https://"):]
    # The app must cover the entire hostname, never a specific page/path.
    if "/" in value or "?" in value or "#" in value or ":" in value:
        return None
    return value.lower() if value == value.lower() else None


def app_destinations(app):
    if not isinstance(app, dict) or app.get("type") != "self_hosted":
        return set(), False
    destinations = app.get("destinations")
    if destinations is not None:
        if not isinstance(destinations, list) or not destinations:
            return set(), False
        domains = set()
        for entry in destinations:
            if (not isinstance(entry, dict) or entry.get("type", "public") != "public"
                    or entry.get("overrides")):
                return set(), False
            name = normalized_destination(entry.get("uri"))
            if name is None:
                return set(), False
            domains.add(name)
        # Do not share one Access session/policy between multiple games,
        # environments or canonical/preview surfaces.
        return domains, len(domains) == 1
    # Legacy Access applications represent hostname scopes differently.
    domains = set()
    legacy = app.get("self_hosted_domains")
    if legacy:
        if not isinstance(legacy, list):
            return set(), False
        for entry in legacy:
            if not isinstance(entry, dict):
                return set(), False
            name = normalized_destination(entry.get("domain"))
            if name is None:
                return set(), False
            domains.add(name)
    else:
        name = normalized_destination(app.get("domain"))
        if name:
            domains.add(name)
    # Deprecation fallback must obey the same exact one-host boundary.
    return domains, len(domains) == 1


def raw_access_scope_overlap(app, expected):
    """Conservatively detect a potentially overlapping Access destination.

    This check is separate from app_destinations(): that strict parser
    intentionally rejects an entire app if one destination is malformed.
    Ignoring such an app would leave a false green for another Access app
    protecting the same hostname.
    """
    if not isinstance(app, dict):
        return False
    values = [app.get("domain")]
    for key, field in (("destinations", "uri"),
                       ("self_hosted_domains", "domain")):
        entries = app.get(key)
        if not isinstance(entries, list):
            continue
        for item in entries:
            values.append(item.get(field) if isinstance(item, dict) else item)
    witness = expected.replace("*.", "sample.", 1)
    for value in values:
        if not isinstance(value, str):
            continue
        host = value.strip().lower()
        if host.startswith("https://"):
            host = host[len("https://"):]
        host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if (host == expected or host == witness or
                (expected.startswith("*.") and host.endswith(expected[1:])) or
                (host.startswith("*.") and (
                    witness.endswith(host[1:]) or
                    (expected.startswith("*.") and expected[1:].endswith(host[1:]))))):
            return True
    return False


def policy_review(payload):
    if not isinstance(payload, dict):
        return "not-verified"
    rows = payload.get("result")
    page = payload.get("result_info")
    if (not isinstance(rows, list) or len(rows) > MAX_POLICIES
            or not isinstance(page, dict)
            or type(page.get("total_pages")) is not int
            or page["total_pages"] != 1
            or type(page.get("total_count")) is not int
            or page["total_count"] != len(rows)
            or type(page.get("count")) is not int
            or page["count"] != len(rows)):
        return "not-verified"
    if not rows:
        # All-deny is possible, but do not label an unconfigured Access
        # application ready for real authorized previews.
        return "not-verified"
    has_restricted_allow = False
    for policy in rows:
        if not isinstance(policy, dict):
            return "not-verified"
        action = policy.get("decision", policy.get("action"))
        if action not in VALID_ACTIONS:
            return "review-required"
        if action == "allow":
            include = policy.get("include")
            if not isinstance(include, list) or not include:
                return "review-required"
            # Cloudflare Access Include rules are ORed. One broad rule
            # (Everyone, email_domain, IP range, group, service token...)
            # broadens the whole allow, even alongside an exact email.
            # Accept only individual explicitly named operator addresses.
            for rule in include:
                if not isinstance(rule, dict) or set(rule) != {"email"}:
                    return "review-required"
                email = rule["email"]
                if (not isinstance(email, dict) or set(email) != {"email"}
                        or not isinstance(email["email"], str)
                        or len(email["email"]) > 254
                        or EXACT_OPERATOR_EMAIL.fullmatch(email["email"]) is None):
                    return "review-required"
            has_restricted_allow = True
    # Deny-only policy can be safe but is not proof that an authorized
    # operator can sign in and complete the subsequent gameplay E2E.
    return "restricted-policy-candidate" if has_restricted_allow else "review-required"


def inspect(client, *, project_filter=None):
    """Check Access for all games or one allowlisted project; no writes."""
    if project_filter is not None and project_filter not in HOSTS:
        raise ReadinessError("Access project is not allowlisted")
    apps = parse_apps(client.get("/accounts/" + client.account + "/access/apps"))
    project_rows = []
    for project, custom in HOSTS.items():
        if project_filter is not None and project != project_filter:
            continue
        wanted = {
            "main": project + ".pages.dev",
            "immutable": "*." + project + ".pages.dev",
            "custom_companion": custom,
        }
        matches = {k: [] for k in wanted}
        conflicts = {k: 0 for k in wanted}
        for app in apps:
            domains, safe = app_destinations(app)
            for k, domain in wanted.items():
                if raw_access_scope_overlap(app, domain) and (
                        not safe or domains != {domain}):
                    conflicts[k] += 1
                if safe and domains == {domain}:
                    matches[k].append(app)
        status = {}
        for scope, candidates in matches.items():
            if conflicts[scope]:
                status[scope] = "ambiguous"
                continue
            if len(candidates) != 1:
                status[scope] = "missing" if not candidates else "ambiguous"
                continue
            app = candidates[0]
            raw_id = app.get("id")
            try:
                app_id = str(UUID(raw_id))
            except (TypeError, ValueError, AttributeError):
                status[scope] = "unverified"
                continue
            if raw_id != app_id or not UUID_PATTERN.fullmatch(app_id):
                status[scope] = "unverified"
                continue
            pol = client.get(f"/accounts/{client.account}/access/apps/{app_id}/policies")
            status[scope] = policy_review(pol)
        project_rows.append({
            "project": project, "environment": "production" if project == "chronicles-production" else "staging",
            "application_scopes": status,
            "source_of_truth": "cloudflare-access-apps-and-policies-get",
            "guest_http_probe": "not-performed",
            "shadowops_id_e2e": "not-performed",
        })
    all_planned = all(all(v == "restricted-policy-candidate" for v in row["application_scopes"].values()) for row in project_rows)
    return {
        "state": "CONFIGURED_FOR_GUEST_TEST" if all_planned else "ACCESS_REMEDIATION_REQUIRED",
        "projects": project_rows,
        "can_activate": False,
        "claim_all_games_protected": False,
        "note": "Only metadata: live guest denial, Pages history, custom login, signed-in ShadowOps ID E2E still required",
    }


def main(argv):
    if argv != ["inspect"]:
        print("Usage: pages_access_readiness.py inspect", file=sys.stderr)
        return 64
    try:
        report = inspect(AccessClient(os.environ))
    except Exception as exc:
        # All Access/Cloudflare responses can contain confidential fields;
        # never print exception text, app IDs, policy rules or tokens.
        print("PAGES_ACCESS_READINESS_BLOCKED kind=" + type(exc).__name__, file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["state"] == "CONFIGURED_FOR_GUEST_TEST" else 10


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
