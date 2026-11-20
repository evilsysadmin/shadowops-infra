#!/usr/bin/env python3
"""Operator-only Cloudflare Access pilot for Chronicles STAGING immutable previews.

No DNS, Pages deployment, production, custom-domain, Identity or other game
mutations. This creates at most one app with one exact-email Allow policy.
A restricted Access preview is not proof of complete ShadowOps ID protection.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

from pages_access_readiness import (
    AccessClient, ReadinessError, app_destinations, parse_apps, policy_review,
    EXACT_OPERATOR_EMAIL,
)
from staradvs_pages import CloudflareClient

PROJECT = "chronicles-staging"
CUSTOM = "staging.chronicles.shadowops.dpdns.org"
WILDCARD = "*." + PROJECT + ".pages.dev"
APP_NAME = "ShadowOps Chronicles staging immutable preview lockdown"
POLICY_NAME = "Chronicles staging named operator"
APP_PATH = "/access/apps"
MAX_RESPONSE = 1_000_000


class CutoverError(Exception):
    pass


class AccessWriter(AccessClient):
    def __init__(self, env):
        scoped = dict(env)
        # Dedicated and independently permissioned Apps and Policies Write.
        # Do not allow implicit fallback to Pages or read-only API tokens.
        scoped["CLOUDFLARE_ACCESS_READ_TOKEN"] = env.get("CLOUDFLARE_ACCESS_WRITE_TOKEN", "")
        super().__init__(scoped)

    def create_app(self, body):
        path = f"/accounts/{self.account}{APP_PATH}"
        if not isinstance(body, dict) or body != app_payload(self._operator_email):
            raise CutoverError("Access payload deviates from the fixed staging contract")
        req = urllib.request.Request(
            "https://api.cloudflare.com/client/v4" + path,
            method="POST",
            data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
            headers={"Authorization": "Bearer " + self._token,
                     "Content-Type": "application/json",
                     "Accept": "application/json",
                     "User-Agent": "ShadowOps-Chronicles-Staging-Access-Operator/1.0"},
        )
        try:
            handler = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                NoRedirect())
            with handler.open(req, timeout=20) as res:
                raw, code = res.read(MAX_RESPONSE + 1), res.status
        except urllib.error.HTTPError:
            # A write may have succeeded before a transient API failure.
            # Retrying must start with a fresh full GET inventory, not a
            # blind second POST. Never log provider error bodies or token.
            raise CutoverError("Access create returned a provider error; inspect before retry") from None
        except (OSError, TimeoutError, urllib.error.URLError):
            raise CutoverError("Access create state uncertain; inspect before retry") from None
        if code not in (200, 201) or len(raw) > MAX_RESPONSE:
            raise CutoverError("Access create response not accepted")
        try:
            response = json.loads(raw)
        except (ValueError, UnicodeError):
            raise CutoverError("Access create response invalid") from None
        if not isinstance(response, dict) or response.get("success") is not True:
            raise CutoverError("Access create result not confirmed")
        return response


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def app_payload(email):
    if (not isinstance(email, str) or len(email) > 254
            or EXACT_OPERATOR_EMAIL.fullmatch(email) is None):
        raise CutoverError("Operator email is missing or invalid")
    return {
        "type": "self_hosted",
        "name": APP_NAME,
        "domain": WILDCARD,
        "app_launcher_visible": False,
        "session_duration": "1h",
        "policies": [{
            "name": POLICY_NAME,
            "decision": "allow",
            "include": [{"email": {"email": email}}],
            "precedence": 1,
        }],
    }


def exact_pages_owner(client):
    path = f"/accounts/{client.account}/pages/projects/{PROJECT}"
    status, project = client.request("GET", path)
    if status != 200 or not isinstance(project, dict):
        raise CutoverError("Chronicles staging Pages project not readable")
    expected_alias = PROJECT + ".pages.dev"
    if (project.get("name") != PROJECT or
            project.get("production_branch") != "main" or project.get("source") or
            project.get("subdomain") != expected_alias):
        raise CutoverError("Chronicles staging Pages project ownership mismatch")
    domains = project.get("domains") or []
    if (not isinstance(domains, list) or
            any(not isinstance(d, str) or d not in {CUSTOM, expected_alias}
                for d in domains)):
        raise CutoverError("Unexpected Pages domain")
    return True


def plan(access, pages, email):
    app_payload(email)  # Reject missing/invalid operator identity before touching provider.
    exact_pages_owner(pages)
    inventory = parse_apps(access.get(f"/accounts/{access.account}{APP_PATH}"))
    matching = []
    for app in inventory:
        domains, valid = app_destinations(app)
        if WILDCARD in domains and not valid:
            raise CutoverError("Conflicting multi-host/invalid Access application")
        if WILDCARD in domains:
            matching.append(app)
    if len(matching) > 1:
        raise CutoverError("Multiple overlapping Access applications")
    if not matching:
        return "needs-operator-creation"
    app = matching[0]
    from uuid import UUID
    try:
        app_id = str(UUID(app["id"]))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise CutoverError("Existing application identifier invalid") from None
    if app_id != app.get("id") or app.get("name") != APP_NAME:
        raise CutoverError("Foreign Access application owns staging previews")
    policies = access.get(f"/accounts/{access.account}/access/apps/{app_id}/policies")
    if policy_review(policies) != "restricted-policy-candidate":
        raise CutoverError("Existing Access policy not operator-restricted")
    rows = policies.get("result")
    if (not isinstance(rows, list) or len(rows) != 1
            or rows[0].get("decision", rows[0].get("action")) != "allow"
            or rows[0].get("include") != [{"email": {"email": email}}]):
        raise CutoverError("Existing Access policy does not match exact operator")
    return "already-configured"


def apply(access, pages, email):
    mode = plan(access, pages, email)
    if mode == "already-configured":
        return mode
    if mode != "needs-operator-creation":
        raise CutoverError("Access application state cannot be applied")
    # Exactly one mutating request. The operator workflow is gated by
    # repository/main, staging environment, confirmation and concurrency.
    access._operator_email = email
    access.create_app(app_payload(email))
    # Never claim live protection based on a successful POST alone.
    return "created-pending-guest-probe"


def main(argv):
    if argv not in (["plan"], ["apply"]):
        print("Usage: chronicles_staging_access_preview.py plan|apply", file=sys.stderr)
        return 64
    try:
        env = os.environ
        email = env.get("CLOUDFLARE_ACCESS_OPERATOR_EMAIL", "").strip()
        access = AccessWriter(env)
        pages = CloudflareClient(env)
        status = plan(access, pages, email) if argv == ["plan"] else apply(access, pages, email)
        print("CHRONICLES_STAGING_ACCESS_PREVIEW state=" + status +
              " project=" + PROJECT +
              " custom_domain_untouched=true production_untouched=true" +
              " base_pages_alias_untouched=true can_claim_protected=false")
        return 0 if status == "already-configured" else 10 if argv == ["plan"] else 0
    except Exception as exc:
        # In particular, never log operator email, policy JSON, Access
        # application IDs, provider responses, or any Cloudflare token.
        print("CHRONICLES_STAGING_ACCESS_PREVIEW_BLOCKED kind=" + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
