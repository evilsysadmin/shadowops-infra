#!/usr/bin/env python3
"""Snooker staging Pages handoff. Only trusted Infra manual workflow may call writes."""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

import snooker_pages_readiness as readiness
import snooker_source_admission as admission
from snooker_pages_provision import Client, ProvisionError

ISSUER = "https://id-staging.shadowops.dpdns.org"
HOST = readiness.HOST
ALIAS = "snooker-staging.pages.dev"
KEY = "SHADOWOPS_SNOOKER_SERVICE_CREDENTIAL"
PROOF = re.compile(r"soc1_[A-Za-z0-9_-]{43}\Z")

class BindingBlocked(ProvisionError):
    """A fixed, secret-free Pages binding failure stage."""
    STAGES = {
        "preflight-project", "preflight-production-vars", "preflight-preview-vars",
        "patch-rejected", "patch-http-400", "patch-http-401", "patch-http-403",
        "patch-http-404", "patch-http-409", "patch-http-422", "patch-http-429",
        "patch-http-500", "patch-http-502", "patch-http-503",
        "postpatch-policy", "postpatch-binding",
    }

    def __init__(self, stage, provider_code=None):
        if stage not in self.STAGES:
            raise ValueError("Invalid binding failure stage")
        if (provider_code is not None and
                (not isinstance(provider_code, str)
                 or not re.fullmatch(r"[1-9][0-9]{0,8}", provider_code))):
            raise ValueError("Invalid bounded provider code")
        super().__init__("Snooker Pages secret binding blocked")
        self.stage = stage
        self.provider_code = provider_code


class ReleaseAlignmentBlocked(ProvisionError):
    """Bounded, nonsecret canonical Pages production mismatch."""
    STAGES = frozenset({"canonical-missing", "canonical-invalid", "source-mismatch"})

    def __init__(self, stage, deployed_sha=None):
        if stage not in self.STAGES or (deployed_sha is not None and
                not re.fullmatch(r"[a-f0-9]{40}", deployed_sha)):
            raise ValueError("Invalid canonical deployment diagnostic")
        super().__init__("Canonical Pages release does not match admitted source")
        self.stage = stage
        self.deployed_sha = deployed_sha


class GuestDenialBlocked(ProvisionError):
    """Only public HTTP status and a fixed path category may leave CI."""
    STAGES = frozenset({
        "alias-root", "alias-release", "custom-root", "custom-asset", "custom-release"
    })

    def __init__(self, stage, observed):
        if stage not in self.STAGES or not re.fullmatch(r"[1-5][0-9]{2}|unavailable|invalid", observed):
            raise ValueError("Invalid guest-denial diagnostic")
        super().__init__("Guest-denial check blocked")
        self.stage = stage
        self.observed = observed


def project_path(client):
    return f"/accounts/{client.account}/pages/projects/{readiness.PROJECT}"

def require_private(client):
    status = readiness.inspect(client)
    if status["project"] != "present":
        raise ProvisionError("Snooker Pages project missing")
    project = client.get(project_path(client))
    if not isinstance(project, dict) or not readiness.ALIAS_PATTERN.fullmatch(
            str(project.get("subdomain", ""))):
        raise ProvisionError("Unknown Snooker Pages alias")
    configs = project.get("deployment_configs") or {}
    for mode in ("production", "preview"):
        config = configs.get(mode) or {}
        if config.get("fail_open") is not False or "global_fetch_strictly_public" not in (
                config.get("compatibility_flags") or []):
            raise ProvisionError("Pages Functions may fail open")
    return project

def issuer_ready(reader=None):
    url = ISSUER + "/login?app=snooker"
    if reader is None:
        def reader(address):
            req = urllib.request.Request(
                address, headers={"User-Agent": "ShadowOps-Snooker-Staging/1.0"})
            with urllib.request.urlopen(req, timeout=12) as response:
                if response.status != 200:
                    raise ProvisionError("Identity login is not active")
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise ProvisionError("Identity response exceeds bound")
                return raw
    try:
        raw = reader(url)
    except (OSError, urllib.error.URLError):
        raise ProvisionError("Identity endpoint unavailable") from None
    if not isinstance(raw, bytes) or (
        b"https://staging.snooker.shadowops.dpdns.org/?shadowops=central" not in raw
    ):
        raise ProvisionError("Deployed Identity does not recognize Snooker audience")

def current_proof():
    # Existing dedicated OCI Vault custody. Never print or export its full bundle.
    import oci
    from identity_staging_provision import load_existing
    from chronicles_api_provision import resolve_vault
    from oci_control_plane import config_from_env, resolve_existing_host
    config = config_from_env(oci, os.environ)
    compartment, _ = resolve_existing_host(oci, config)
    vault, _, _ = resolve_vault(oci, config, compartment)
    bundle = load_existing(oci, config, vault, compartment)
    proof = (bundle or {}).get("consumers", {}).get("snooker")
    if not isinstance(proof, str) or not PROOF.fullmatch(proof):
        raise ProvisionError("Snooker Identity has not been explicitly provisioned")
    return proof

def bind(client, proof):
    if not isinstance(proof, str) or not PROOF.fullmatch(proof):
        raise ProvisionError("Invalid independent Snooker service proof")
    try:
        project = require_private(client)
    except (readiness.InventoryError, ProvisionError):
        raise BindingBlocked("preflight-project") from None
    for mode in ("production", "preview"):
        vars_ = (project.get("deployment_configs") or {}).get(mode, {}).get("env_vars") or {}
        if not isinstance(vars_, dict) or set(vars_) - ({KEY} if mode == "production" else set()):
            raise BindingBlocked("preflight-" + mode + "-vars")
    path = project_path(client)
    # The project already passed require_private() for production AND preview.
    # Cloudflare's PATCH supports partial deployment_config changes; do not
    # re-send unrelated compatibility flags or policy fields with a secret.
    # The post-patch require_private() below must prove both modes unchanged.
    try:
        client.write("PATCH", path, {"deployment_configs": {"production": {
            "env_vars": {KEY: {"type": "secret_text", "value": proof}},
        }}})
    except (readiness.InventoryError, ProvisionError) as exc:
        # Cloudflare's response body may contain private material. Only a
        # known numeric HTTP status from our own fixed Client error may pass.
        match = re.fullmatch(
            r"Cloudflare write rejected \(HTTP ([0-9]{3})\)(?: API ([1-9][0-9]{0,8}))?",
            str(exc))
        status = match.group(1) if match else None
        code = match.group(2) if match else None
        stage = "patch-http-" + status if status in {
            "400", "401", "403", "404", "409", "422", "429", "500", "502", "503"
        } else "patch-rejected"
        raise BindingBlocked(stage, code) from None
    try:
        updated = require_private(client)
    except (readiness.InventoryError, ProvisionError):
        raise BindingBlocked("postpatch-policy") from None
    vars_ = (updated.get("deployment_configs") or {}).get("production", {}).get("env_vars") or {}
    if (not isinstance(vars_, dict) or set(vars_) != {KEY}
            or not isinstance(vars_[KEY], dict)
            or vars_[KEY].get("type") != "secret_text"):
        raise BindingBlocked("postpatch-binding")
    return {"identity": "bound", "value_logged": "false"}

def probe(url):
    req = urllib.request.Request(url, headers={"User-Agent": "ShadowOps-Snooker-Smoke/1.0",
                                               "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except urllib.error.URLError:
        raise ProvisionError("Snooker staging HTTPS unavailable") from None

def actual_alias_hosts(project):
    alias = project["subdomain"]
    hosts = {alias}
    found_deployment = False
    for field in ("latest_deployment", "canonical_deployment"):
        deployment = project.get(field)
        if deployment is None:
            continue
        if not isinstance(deployment, dict):
            raise ProvisionError("Invalid Pages deployment metadata")
        url = deployment.get("url")
        if not isinstance(url, str) or not url:
            continue
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.username or parsed.password or
                parsed.port is not None or parsed.path not in ("", "/") or
                parsed.query or parsed.fragment or
                not (parsed.hostname == alias or parsed.hostname.endswith("." + alias))):
            raise ProvisionError("Unexpected Pages deployment alias")
        hosts.add(parsed.hostname)
        found_deployment = True
    if not found_deployment:
        raise ProvisionError("No confirmed deployed Pages Worker")
    return sorted(hosts)


def attach_domain(client, read_status=probe):
    project = require_private(client)
    vars_ = (project.get("deployment_configs") or {}).get("production", {}).get("env_vars") or {}
    if set(vars_) != {KEY} or vars_[KEY].get("type") != "secret_text":
        raise ProvisionError("Identity service proof not bound before domain exposure")
    alias = project["subdomain"]
    # The assigned project host AND actual immutable deployment aliases must
    # deny. Never guess a generic pages.dev URL.
    for hostname in actual_alias_hosts(project):
        if read_status("https://" + hostname + "/") != 404:
            raise ProvisionError("Pages alias is not fail-closed: refusing custom domain")
    project_url = project_path(client)
    domain_path = project_url + "/domains/" + urllib.parse.quote(HOST, safe="")
    if client.get(domain_path) is None:
        result = client.write("POST", project_url + "/domains", {"name": HOST})
        if not isinstance(result, dict) or result.get("name") != HOST:
            raise ProvisionError("Foreign custom domain returned by Pages")
    zones = client.get("/zones?" + urllib.parse.urlencode(
        {"name": readiness.ZONE, "account.id": client.account}))
    matches = [x for x in zones or [] if isinstance(x, dict) and x.get("name") == readiness.ZONE]
    if len(matches) != 1 or not isinstance(matches[0].get("id"), str):
        raise ProvisionError("Cannot resolve exact zone before DNS write")
    dns_base = "/zones/" + urllib.parse.quote(matches[0]["id"], safe="") + "/dns_records"
    query = urllib.parse.urlencode({"name": HOST, "per_page": 100})
    existing = client.get(dns_base + "?" + query)
    if not isinstance(existing, list) or len(existing) > 1:
        raise ProvisionError("DNS inventory ambiguous")
    if existing:
        row = existing[0]
        if (row.get("name") != HOST or row.get("type") != "CNAME" or
                row.get("proxied") is not True or
                str(row.get("content", "")).rstrip(".") != alias):
            raise ProvisionError("Foreign DNS record; refusing mutation")
    else:
        client.write("POST", dns_base, {"type": "CNAME", "name": HOST,
                                       "content": alias, "proxied": True, "ttl": 1})
    verified = readiness.inspect(client)
    if verified["domain"] != "present" or verified["dns"] != "present":
        raise ProvisionError("Snooker custom domain and DNS not converged")
    return {"domain": "owned", "dns": "owned", "alias_guest": "denied"}

def audit_canonical_release(client, expected_sha):
    """Check real Pages production deployment SHA, never latest preview.

    Cloudflare's canonical_deployment is documented as the most recent
    production deployment. Unlike latest_deployment, it cannot point to a
    preview build that happens to have been uploaded more recently.
    """
    if not isinstance(expected_sha, str) or not admission.SHA.fullmatch(expected_sha):
        raise ReleaseAlignmentBlocked("canonical-invalid")
    project = require_private(client)
    deployment = project.get("canonical_deployment")
    if deployment is None:
        raise ReleaseAlignmentBlocked("canonical-missing")
    if not isinstance(deployment, dict):
        raise ReleaseAlignmentBlocked("canonical-invalid")
    trigger = deployment.get("deployment_trigger")
    metadata = trigger.get("metadata") if isinstance(trigger, dict) else None
    latest = deployment.get("latest_stage")
    if (deployment.get("environment") != "production"
            or deployment.get("is_skipped") is not False
            or not isinstance(latest, dict) or latest.get("status") != "success"
            or not isinstance(trigger, dict) or trigger.get("type") != "ad_hoc"
            or not isinstance(metadata, dict)
            or metadata.get("branch") != "main"
            or metadata.get("commit_dirty") is not False):
        raise ReleaseAlignmentBlocked("canonical-invalid")
    deployed = metadata.get("commit_hash")
    if not isinstance(deployed, str) or not admission.SHA.fullmatch(deployed):
        raise ReleaseAlignmentBlocked("canonical-invalid")
    if deployed != expected_sha:
        raise ReleaseAlignmentBlocked("source-mismatch", deployed)
    return deployed


def smoke_guest(read_status=probe, aliases=None):
    if not aliases:
        raise ProvisionError("Explicit real Pages alias inventory required")
    checks = [(f"https://{alias}/", 404, "alias-root") for alias in aliases]
    checks += [(f"https://{alias}/release.json", 404, "alias-release") for alias in aliases]
    checks += [
        ("https://" + HOST + "/", 401, "custom-root"),
        ("https://" + HOST + "/assets/guest.js", 401, "custom-asset"),
        ("https://" + HOST + "/release.json", 401, "custom-release"),
    ]
    for address, expected, stage in checks:
        try:
            observed = read_status(address)
        except (ProvisionError, readiness.InventoryError, OSError):
            raise GuestDenialBlocked(stage, "unavailable") from None
        if observed != expected:
            code = str(observed) if type(observed) is int and 100 <= observed <= 599 else "invalid"
            raise GuestDenialBlocked(stage, code)
    return {"guest": "denied", "pages_alias": "denied", "identity_login": "required"}

def main():
    try:
        if sys.argv[1:] == ["identity-ready"]:
            current_proof()
            issuer_ready()
            print("SNOOKER_IDENTITY_READY audience=snooker proof_logged=false")
        elif sys.argv[1:] == ["bind"]:
            issuer_ready()
            bind(Client(os.environ), current_proof())
            print("SNOOKER_PAGES_SECRET_BOUND proof_logged=false")
        elif sys.argv[1:] == ["domain"]:
            attach_domain(Client(os.environ))
            print("SNOOKER_PAGES_DOMAIN_BOUND alias_guest=denied")
        elif sys.argv[1:] == ["release-audit"]:
            # Read-only source GET and Cloudflare project GET. The bounded SHA
            # receipt must NEVER be mistaken for guest or signed-in acceptance.
            source_sha = admission.current_sha(
                admission.GithubReader(os.environ.get("GH_TOKEN", "")))
            deployed = audit_canonical_release(Client(os.environ), source_sha)
            print("SNOOKER_STAGING_RELEASE_ALIGNMENT status=current"
                  " source=" + source_sha[:12] + " deployed=" + deployed[:12]
                  + " guest_auth=not-verified")
        elif sys.argv[1:] in (["smoke-guest"], ["smoke-audit"]):
            client = Client(os.environ)
            if sys.argv[1:] == ["smoke-audit"]:
                # Unlike publication, this is read-only. No published domain
                # yet is a clean pre-release state; partial routing must fail.
                inventory = readiness.inspect(client)
                if inventory["domain"] == "absent" and inventory["dns"] == "absent":
                    require_private(client)
                    print("SNOOKER_STAGING_GUEST_AUDIT status=not-cut-over")
                    return 0
                if inventory["domain"] != "present" or inventory["dns"] != "present":
                    raise ProvisionError("Incomplete Snooker domain routing")
            project = require_private(client)
            smoke_guest(aliases=actual_alias_hosts(project))
            print("SNOOKER_STAGING_GUEST_DENIAL_VERIFIED")
        else:
            raise ProvisionError("Usage: identity-ready | bind | domain | smoke-guest | smoke-audit | release-audit")
        return 0
    except ReleaseAlignmentBlocked as exc:
        marker = ("SNOOKER_STAGING_RELEASE_ALIGNMENT status=blocked"
                  " stage=" + exc.stage)
        if exc.deployed_sha:
            marker += " deployed=" + exc.deployed_sha[:12]
        print(marker, file=sys.stderr)
        return 1
    except GuestDenialBlocked as exc:
        print("SNOOKER_STAGING_BLOCKED type=ProvisionError stage=guest-" + exc.stage
              + " observed=" + exc.observed, file=sys.stderr)
        return 1
    except BindingBlocked as exc:
        # Only a finite categorical stage may leave the protected runner.
        marker = "SNOOKER_STAGING_BLOCKED type=ProvisionError stage=" + exc.stage
        if exc.provider_code is not None:
            marker += " provider_code=" + exc.provider_code
        print(marker, file=sys.stderr)
        return 1
    except Exception as exc:
        # OCI exceptions can contain secret identifiers; never display their message.
        print("SNOOKER_STAGING_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
