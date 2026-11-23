#!/usr/bin/env python3
"""Bind Star Adventures' *own* staging Identity proof to *one* Pages project.

GET-only plan by default; manual protected staging workflow owns PATCH.
No game code, preview deployment, response or command line carries the secret.
"""
from __future__ import annotations

import os
import re
import sys

import staradvs_pages as pages

KEY = "SHADOWOPS_STARADVS_SERVICE_CREDENTIAL"
PROOF = re.compile(r"soc1_[A-Za-z0-9_-]{43}\Z")
GOOD = "global_fetch_strictly_public"


class BindingError(Exception):
    pass


def project_path(client):
    return f"/accounts/{client.account}/pages/projects/{pages.PROJECT}"


def posture(client):
    _, owner = pages.inspect(client)
    if owner != {"project": "owned", "domain": "owned", "dns": "owned"}:
        raise BindingError("Dedicated Star Adventures resource ownership is incomplete")
    status, project = client.request("GET", project_path(client))
    if status != 200 or not isinstance(project, dict):
        raise BindingError("Star Adventures Pages project missing")
    if (project.get("name") != pages.PROJECT or
            project.get("production_branch") != "main" or project.get("source") or
            project.get("subdomain") != pages.TARGET):
        raise BindingError("Foreign project/branch/Pages alias")
    domains = project.get("domains") or []
    if not isinstance(domains, list) or any(
        not isinstance(value, str) or value not in {pages.HOST, pages.TARGET}
        for value in domains
    ):
        raise BindingError("Unexpected Pages domain")
    configs = project.get("deployment_configs") or {}
    if not isinstance(configs, dict):
        raise BindingError("Malformed Pages deployment policies")
    current_binding = False
    for mode in ("production", "preview"):
        cfg = configs.get(mode)
        if not isinstance(cfg, dict) or cfg.get("fail_open") is not False:
            raise BindingError("Both Pages deployment modes must be fail-closed")
        flags = cfg.get("compatibility_flags")
        if (not isinstance(flags, list) or any(not isinstance(f, str) for f in flags)
                or GOOD not in flags or "global_fetch_private_origin" in flags):
            raise BindingError("Pages runtime does not have strict public origin routing")
        vars_ = cfg.get("env_vars") or {}
        if not isinstance(vars_, dict) or (
            set(vars_) - ({KEY} if mode == "production" else set())
        ):
            raise BindingError("Unexpected Pages environment bindings")
        if mode == "production" and KEY in vars_:
            if not isinstance(vars_[KEY], dict) or vars_[KEY].get("type") != "secret_text":
                raise BindingError("Service proof binding must be a secret_text")
            current_binding = True
    return "named-binding-present-not-value-verified" if current_binding else "binding-missing"


def vault_proof(sdk, env):
    """Use the exact existing operator Vault bundle; never create a new key."""
    from identity_staging_provision import load_existing
    from chronicles_api_provision import resolve_vault
    from oci_control_plane import config_from_env, resolve_existing_host
    config = config_from_env(sdk, env)
    compartment, _ = resolve_existing_host(sdk, config)
    vault, _, _ = resolve_vault(sdk, config, compartment)
    bundle = load_existing(sdk, config, vault, compartment)
    credential = (bundle or {}).get("consumers", {}).get("staradvs")
    if not isinstance(credential, str) or not PROOF.fullmatch(credential):
        raise BindingError("Dedicated Star Adventures consumer has not been provisioned")
    return credential


def bind(client, credential):
    if not isinstance(credential, str) or not PROOF.fullmatch(credential):
        raise BindingError("Malformed Star Adventures service proof")
    # No environment flags or arbitrary foreign project may be written to
    # make a missing Identity policy pass.
    posture(client)
    status, _ = client.request("PATCH", project_path(client), {
        "deployment_configs": {
            "production": {
                "env_vars": {KEY: {"type": "secret_text", "value": credential}}
            }
        }
    })
    if status != 200:
        raise BindingError("Cloudflare Pages app-only proof binding rejected")
    if posture(client) != "named-binding-present-not-value-verified":
        raise BindingError("Cloudflare did not report the isolated secret binding")
    return "bound-by-name-type-only"


CONFIRM = "STARADVS_BIND_ISOLATED_IDENTITY"


def validate_dispatch_intent(operation, confirmation):
    """Validate binding operator intent without Cloudflare or OCI access."""
    if operation == "plan":
        if confirmation:
            raise BindingError("Read-only binding plan cannot include confirmation")
        return operation
    if operation == "bind":
        if confirmation != CONFIRM:
            raise BindingError("Exact isolated binding confirmation is mandatory")
        return operation
    raise BindingError("Unknown binding operation")


def main(argv):
    if argv == ["validate-intent"]:
        try:
            validate_dispatch_intent(
                os.environ.get("STARADVS_BIND_OPERATION", ""),
                os.environ.get("STARADVS_BIND_CONFIRM", ""),
            )
        except BindingError:
            print("STARADVS_BINDING_OPERATOR_INTENT_BLOCKED", file=sys.stderr)
            return 64
        print("STARADVS_BINDING_OPERATOR_INTENT_VALIDATED no-provider-operation")
        return 0
    if argv == ["bind"] and os.environ.get("STARADVS_BIND_CONFIRM", "") != CONFIRM:
        # Defense in depth: a direct CLI invocation must not silently bind
        # a secret merely because OCI/Cloudflare credentials happen to exist.
        print("STARADVS_BINDING_OPERATOR_INTENT_BLOCKED", file=sys.stderr)
        return 64
    if argv not in (["plan"], ["bind"]):
        print("Usage: staradvs_identity_binding.py plan|bind", file=sys.stderr)
        return 64
    try:
        client = pages.CloudflareClient(os.environ)
        if argv == ["plan"]:
            state = posture(client)
        else:
            # Secret never appears in CLI arguments, logs, GitHub artifacts or
            # browser; OCI operator bundle is a separate protected backend.
            import oci
            proof = vault_proof(oci, os.environ)
            state = bind(client, proof)
        print("STARADVS_IDENTITY_BINDING state=" + state +
              " project=" + pages.PROJECT + " source=operator-vault value_logged=false")
        return 0
    except Exception as exc:
        # Never echo provider, OCI, Vault, or HTTP SDK exception messages.
        print("STARADVS_IDENTITY_BINDING_BLOCKED kind=" + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
