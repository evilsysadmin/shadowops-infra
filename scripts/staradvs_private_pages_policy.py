#!/usr/bin/env python3
"""Protect only the existing Star Adventures staging Pages project policy.

Read-only plan is the default; the reviewed manual workflow alone may apply.
This config is NOT a substitute for deploying the Identity Worker and proof.
"""
from __future__ import annotations

import json
import os
import sys

import staradvs_pages as pages

KEY = "SHADOWOPS_STARADVS_SERVICE_CREDENTIAL"
GOOD = "global_fetch_strictly_public"
BAD = "global_fetch_private_origin"
MODES = ("production", "preview")


class PrivatePolicyError(Exception):
    pass


def project_path(client) -> str:
    return f"/accounts/{client.account}/pages/projects/{pages.PROJECT}"


def get_owned_project(client) -> dict:
    _, ownership = pages.inspect(client)
    if ownership != {"dns": "owned", "project": "owned", "domain": "owned"}:
        raise PrivatePolicyError("Existing Star Adventures staging ownership incomplete")
    status, project = client.request("GET", project_path(client))
    if status != 200 or not isinstance(project, dict):
        raise PrivatePolicyError("Staging Pages project absent")
    if (project.get("name") != pages.PROJECT or project.get("production_branch") != "main"
            or project.get("source")):
        raise PrivatePolicyError("Foreign Pages project or source branch")
    alias = project.get("subdomain")
    if not isinstance(alias, str) or alias != pages.TARGET:
        raise PrivatePolicyError("Unexpected Pages project alias")
    domains = project.get("domains") or []
    if (not isinstance(domains, list) or
            any(not isinstance(x, str) or x not in {pages.HOST, alias} for x in domains)):
        raise PrivatePolicyError("Foreign Pages custom domain")
    return project


def preflight(client) -> dict:
    project = get_owned_project(client)
    configs = project.get("deployment_configs") or {}
    if not isinstance(configs, dict):
        raise PrivatePolicyError("Unexpected Pages configuration")
    patch = {}
    already_private = True
    bindings = {}
    for mode in MODES:
        original = configs.get(mode) or {}
        if not isinstance(original, dict):
            raise PrivatePolicyError("Malformed Pages environment")
        flags = original.get("compatibility_flags") or []
        if not isinstance(flags, list) or any(not isinstance(x, str) for x in flags):
            raise PrivatePolicyError("Invalid Pages compatibility flags")
        if BAD in flags:
            raise PrivatePolicyError("Cannot route IdP through private Cloudflare origin")
        env = original.get("env_vars") or {}
        if not isinstance(env, dict) or set(env) - ({KEY} if mode == "production" else set()):
            raise PrivatePolicyError("Unexpected Pages environment bindings")
        if any(not isinstance(value, dict) for value in env.values()):
            raise PrivatePolicyError("Malformed Pages binding")
        if KEY in env and env[KEY].get("type") != "secret_text":
            raise PrivatePolicyError("Plaintext/invalid Star Adventures service binding")
        bindings[mode] = sorted((key, value.get("type")) for key, value in env.items())
        needed = sorted(set(flags) | {GOOD})
        patch[mode] = {"fail_open": False, "compatibility_flags": needed}
        if original.get("fail_open") is not False or flags != needed:
            already_private = False
    return {
        "patch": {"deployment_configs": patch},
        "already_private": already_private,
        "bindings": bindings,
    }


def apply(client) -> str:
    before = preflight(client)
    if before["already_private"]:
        return "already-private"
    status, _ = client.request("PATCH", project_path(client), before["patch"])
    if status != 200:
        raise PrivatePolicyError("Cloudflare rejected exact Pages security patch")
    after = preflight(client)
    if not after["already_private"] or after["bindings"] != before["bindings"]:
        raise PrivatePolicyError("Pages security policy/bindings not preserved after patch")
    return "updated-private"


CONFIRM = "STARADVS_PRIVATE_PAGES_POLICY"


def validate_dispatch_intent(operation: str, confirmation: str) -> str:
    """Fail invalid manual requests before loading Cloudflare credentials."""
    if operation == "plan":
        if confirmation:
            raise PrivatePolicyError("Read-only plan must not carry apply confirmation")
        return "plan"
    if operation == "apply":
        if confirmation != CONFIRM:
            raise PrivatePolicyError("Exact protected apply confirmation required")
        return "apply"
    raise PrivatePolicyError("Unrecognized private Pages policy operation")


def main(argv: list[str]) -> int:
    if argv == ["validate-intent"]:
        try:
            validate_dispatch_intent(
                os.environ.get("STARADVS_POLICY_OPERATION", ""),
                os.environ.get("STARADVS_POLICY_CONFIRM", ""),
            )
        except PrivatePolicyError:
            print("STARADVS_PRIVATE_PAGES_OPERATOR_INTENT_BLOCKED", file=sys.stderr)
            return 64
        print("STARADVS_PRIVATE_PAGES_OPERATOR_INTENT_VALIDATED no-cloudflare-operation")
        return 0
    if argv not in (["plan"], ["apply"]):
        print("Usage: staradvs_private_pages_policy.py plan|apply", file=sys.stderr)
        return 64
    try:
        client = pages.CloudflareClient(os.environ)
        if argv == ["plan"]:
            preview = preflight(client)
            status = "already-private" if preview["already_private"] else "needs-fail-closed-policy"
        else:
            # GitHub workflow performs exact protected-main/operator approval
            # checks. This CLI does NOT read credentials from input arguments.
            status = apply(client)
        print("STARADVS_PAGES_PRIVATE_POLICY status=" + status +
              " project=" + pages.PROJECT + " cloudflare_values_logged=false")
        return 0
    except Exception as exc:
        # Never print project API response, env var values or token material.
        print("STARADVS_PAGES_PRIVATE_POLICY_BLOCKED kind=" + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
