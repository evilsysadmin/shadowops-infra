#!/usr/bin/env python3
"""Provision the Chronicles API staging runtime: own Tunnel, DNS and Vault bundle.

Runs in GitHub Actions only (manual dispatch from protected main):

1. Cloudflare: find or create the remotely managed tunnel `chronicles-staging`
   (never Chess Studio's), set its ingress to the API container and point
   `chronicles-api-staging.shadowops.dpdns.org` at it. An existing DNS record
   that points anywhere else is NEVER overwritten.
2. OCI Vault: create or update ONE secret, `chronicles-staging-runtime-env`,
   with MONGO_URL, JWT_SECRET, INVITE_CODE (GitHub secrets) and the tunnel
   token. The A1 reads it with its Instance Principal at deploy time.

No secret, token, tunnel ID or DNS target is ever printed.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping

CF_API = "https://api.cloudflare.com/client/v4"
ZONE = "shadowops.dpdns.org"
# One level under the zone: covered by Cloudflare's Universal SSL. A deeper
# name (api-staging.chronicles.…) has no edge certificate without ACM.
HOSTNAME = "chronicles-api-staging.shadowops.dpdns.org"
# Earlier hostname; removed only if it still points at OUR tunnel.
LEGACY_HOSTNAMES = ("api-staging.chronicles.shadowops.dpdns.org",)
TUNNEL_NAME = "chronicles-staging"
FORBIDDEN_TUNNELS = frozenset({"chess-studio-staging", "chess-studio-production"})
ORIGIN_SERVICE = "http://chronicles-api:8080"
VAULT_NAME = "chess-studio-staging"
KEY_NAME = "chess-studio-staging-secrets"
SECRET_NAME = "chronicles-staging-runtime-env"
BUNDLE_KEYS = ("MONGO_URL", "JWT_SECRET", "INVITE_CODE", "TUNNEL_TOKEN")
# Password recovery by email reuses Chess Studio's staging Resend key, read
# from the same Vault by name. Opt-in per dispatch: the A1 wrapper must
# already accept it (installed by the operator bootstrap).
OPTIONAL_BUNDLE_KEYS = ("RESEND_API_KEY",)
RESEND_SECRET_NAME = "chess-studio-staging-resend-api-key"
GITHUB_SECRETS = {
    "MONGO_URL": "CHRONICLES_STAGING_MONGO_URL",
    "JWT_SECRET": "CHRONICLES_STAGING_JWT_SECRET",
    "INVITE_CODE": "CHRONICLES_STAGING_INVITE_CODE",
}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class ProvisionError(RuntimeError):
    pass


# ---------------------------------------------------------------- inputs

def read_inputs(env: Mapping[str, str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, name in GITHUB_SECRETS.items():
        value = str(env.get(name, "")).strip()
        if not value:
            raise ProvisionError(f"Missing GitHub secret {name}")
        if any(ch in value for ch in "'\x00\r\n") or len(value) > 4096:
            raise ProvisionError(f"GitHub secret {name} has an unsafe shape")
        values[key] = value
    if not values["MONGO_URL"].startswith(("mongodb://", "mongodb+srv://")):
        raise ProvisionError("CHRONICLES_STAGING_MONGO_URL is not a MongoDB URL")
    if len(values["JWT_SECRET"]) < 32:
        raise ProvisionError("CHRONICLES_STAGING_JWT_SECRET must be at least 32 characters")
    return values


def render_bundle(values: Mapping[str, str]) -> bytes:
    keys = set(values)
    if not set(BUNDLE_KEYS) <= keys <= set(BUNDLE_KEYS) | set(OPTIONAL_BUNDLE_KEYS):
        raise ProvisionError("Bundle keys do not match the contract")
    ordered = [key for key in (*BUNDLE_KEYS, *OPTIONAL_BUNDLE_KEYS) if key in values]
    return "".join(f"{key}={values[key]}\n" for key in ordered).encode("utf-8")


def read_vault_secret(oci: Any, config: dict, vault_id: str, name: str) -> str:
    """One secret's CURRENT value, by name; never printed."""
    client = oci.secrets.SecretsClient(config)
    bundle = client.get_secret_bundle_by_name(secret_name=name, vault_id=vault_id, stage="CURRENT").data
    value = base64.b64decode(bundle.secret_bundle_content.content).decode("utf-8").strip()
    if not value or len(value) > 4096 or any(ch in value for ch in "'\x00\r\n"):
        raise ProvisionError(f"Vault secret {name} is empty or has an unsafe shape")
    return value


# ---------------------------------------------------------------- Cloudflare

class Cloudflare:
    def __init__(self, env: Mapping[str, str], opener: Callable = urllib.request.urlopen):
        self.token = str(env.get("CLOUDFLARE_API_TOKEN", "")).strip()
        self.account = str(env.get("CLOUDFLARE_ACCOUNT_ID", "")).strip()
        if not self.token or not self.account:
            raise ProvisionError("Cloudflare credentials are required")
        self.opener = opener

    def call(self, method: str, path: str, payload: object | None = None) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(CF_API + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token, "Accept": "application/json",
            "Content-Type": "application/json",
        })
        try:
            with self.opener(request, timeout=30) as response:
                body = json.loads(response.read(2_000_000))
        except urllib.error.HTTPError as exc:
            # Status only: the response body may carry identifiers.
            raise ProvisionError(f"Cloudflare {method} {path.split('?')[0].rsplit('/', 1)[-1]} "
                                 f"returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise ProvisionError("Cloudflare API unavailable") from exc
        if not isinstance(body, dict) or body.get("success") is not True:
            raise ProvisionError("Cloudflare API reported failure")
        return body.get("result")


def ensure_tunnel(cf: Cloudflare) -> str:
    if TUNNEL_NAME in FORBIDDEN_TUNNELS:
        raise ProvisionError("Refusing to manage a Chess Studio tunnel")
    query = urllib.parse.urlencode({"name": TUNNEL_NAME, "is_deleted": "false"})
    rows = cf.call("GET", f"/accounts/{cf.account}/cfd_tunnel?{query}") or []
    rows = [row for row in rows if isinstance(row, dict) and row.get("name") == TUNNEL_NAME]
    if len(rows) > 1:
        raise ProvisionError("Ambiguous duplicate Chronicles tunnels")
    if rows:
        tunnel = rows[0]
        if tunnel.get("config_src") != "cloudflare":
            raise ProvisionError("Existing Chronicles tunnel is not remotely managed")
    else:
        tunnel = cf.call("POST", f"/accounts/{cf.account}/cfd_tunnel",
                         {"name": TUNNEL_NAME, "config_src": "cloudflare"})
    tunnel_id = str((tunnel or {}).get("id", ""))
    if not UUID_RE.fullmatch(tunnel_id):
        raise ProvisionError("Cloudflare returned an invalid tunnel ID")
    return tunnel_id


def desired_ingress() -> dict:
    return {"config": {"ingress": [
        {"hostname": HOSTNAME, "service": ORIGIN_SERVICE,
         "originRequest": {"connectTimeout": 10, "noTLSVerify": False}},
        {"service": "http_status:404"},
    ]}}


def configure_tunnel(cf: Cloudflare, tunnel_id: str) -> None:
    cf.call("PUT", f"/accounts/{cf.account}/cfd_tunnel/{tunnel_id}/configurations", desired_ingress())


def tunnel_token(cf: Cloudflare, tunnel_id: str) -> str:
    token = cf.call("GET", f"/accounts/{cf.account}/cfd_tunnel/{tunnel_id}/token")
    if not isinstance(token, str) or len(token) < 32 or any(ch in token for ch in "'\r\n\x00"):
        raise ProvisionError("Cloudflare returned an invalid tunnel token")
    return token


def ensure_dns(cf: Cloudflare, tunnel_id: str) -> str:
    zones = cf.call("GET", "/zones?" + urllib.parse.urlencode({"name": ZONE})) or []
    if len(zones) != 1:
        raise ProvisionError("Expected exactly one Cloudflare zone")
    zone_id = zones[0]["id"]
    target = f"{tunnel_id}.cfargotunnel.com"
    query = urllib.parse.urlencode({"name": HOSTNAME})
    records = cf.call("GET", f"/zones/{zone_id}/dns_records?{query}") or []
    if len(records) > 1:
        raise ProvisionError("Ambiguous DNS records for the Chronicles API hostname")
    retire_legacy(cf, zone_id, target)
    if records:
        record = records[0]
        if record.get("type") == "CNAME" and record.get("content") == target and record.get("proxied") is True:
            return "unchanged"
        raise ProvisionError("Chronicles API hostname is already owned by another target")
    cf.call("POST", f"/zones/{zone_id}/dns_records",
            {"type": "CNAME", "name": HOSTNAME, "content": target, "proxied": True,
             "comment": "Chronicles API staging tunnel (managed by shadowops-infra)"})
    return "created"


def retire_legacy(cf: Cloudflare, zone_id: str, target: str) -> None:
    """Delete an old Chronicles API record only when it points at our tunnel."""
    for name in LEGACY_HOSTNAMES:
        rows = cf.call("GET", f"/zones/{zone_id}/dns_records?" + urllib.parse.urlencode({"name": name})) or []
        for row in rows:
            if row.get("type") == "CNAME" and row.get("content") == target and row.get("id"):
                cf.call("DELETE", f"/zones/{zone_id}/dns_records/{row['id']}")


# ---------------------------------------------------------------- OCI Vault

def resolve_vault(oci: Any, config: dict, compartment_id: str) -> tuple[str, str, str]:
    client = oci.key_management.KmsVaultClient(config)
    vaults = [v for v in oci.pagination.list_call_get_all_results(client.list_vaults, compartment_id).data
              if getattr(v, "display_name", "") == VAULT_NAME
              and str(getattr(v, "lifecycle_state", "")).upper() == "ACTIVE"]
    if len(vaults) != 1:
        raise ProvisionError("Expected exactly one ACTIVE staging Vault")
    vault = vaults[0]
    kms = oci.key_management.KmsManagementClient(config, service_endpoint=vault.management_endpoint)
    keys = [k for k in oci.pagination.list_call_get_all_results(kms.list_keys, compartment_id).data
            if getattr(k, "display_name", "") == KEY_NAME
            and str(getattr(k, "lifecycle_state", "")).upper() == "ENABLED"]
    if len(keys) != 1:
        raise ProvisionError("Expected exactly one ENABLED staging Vault key")
    return vault.id, keys[0].id, compartment_id


def upsert_bundle(oci: Any, config: dict, compartment_id: str, vault_id: str, key_id: str,
                  payload: bytes) -> str:
    client = oci.vault.VaultsClient(config)
    composite = oci.vault.VaultsClientCompositeOperations(client)
    content = oci.vault.models.Base64SecretContentDetails(
        content_type="BASE64", stage="CURRENT", content=base64.b64encode(payload).decode("ascii"))
    rows = [r for r in oci.pagination.list_call_get_all_results(
        client.list_secrets, compartment_id, vault_id=vault_id, name=SECRET_NAME).data
        if str(getattr(r, "lifecycle_state", "")).upper() == "ACTIVE"]
    waiter = {"max_interval_seconds": 5, "max_wait_seconds": 300}
    if len(rows) > 1:
        raise ProvisionError("Ambiguous duplicate Chronicles runtime secrets")
    if rows:
        composite.update_secret_and_wait_for_state(
            rows[0].id, oci.vault.models.UpdateSecretDetails(secret_content=content),
            wait_for_states=["ACTIVE"], waiter_kwargs=waiter)
        return "updated"
    composite.create_secret_and_wait_for_state(
        oci.vault.models.CreateSecretDetails(
            compartment_id=compartment_id, vault_id=vault_id, key_id=key_id,
            secret_name=SECRET_NAME, description="Chronicles of Matthias API staging runtime.",
            freeform_tags={"application": "chronicles-of-matthias", "environment": "staging",
                           "managed-by": "shadowops-infra"},
            secret_content=content),
        wait_for_states=["ACTIVE"], waiter_kwargs=waiter)
    return "created"


# ---------------------------------------------------------------- main

def provision(env: Mapping[str, str], oci: Any, cf: Cloudflare) -> list[str]:
    from oci_control_plane import config_from_env, resolve_existing_host

    values = read_inputs(env)
    tunnel_id = ensure_tunnel(cf)
    configure_tunnel(cf, tunnel_id)
    values["TUNNEL_TOKEN"] = tunnel_token(cf, tunnel_id)
    dns = ensure_dns(cf, tunnel_id)
    config = config_from_env(oci, env)
    compartment_id, _instance = resolve_existing_host(oci, config)
    vault_id, key_id, compartment_id = resolve_vault(oci, config, compartment_id)
    recovery = str(env.get("CHRONICLES_EMAIL_RECOVERY", "")).strip().lower() == "true"
    if recovery:
        values["RESEND_API_KEY"] = read_vault_secret(oci, config, vault_id, RESEND_SECRET_NAME)
    secret = upsert_bundle(oci, config, compartment_id, vault_id, key_id, render_bundle(values))
    return [f"CHRONICLES_API_TUNNEL_OK name={TUNNEL_NAME}",
            f"CHRONICLES_API_DNS_OK hostname={HOSTNAME} state={dns}",
            f"CHRONICLES_API_VAULT_BUNDLE_OK name={SECRET_NAME} state={secret} email_recovery={str(recovery).lower()}"]


def self_test() -> None:
    assert TUNNEL_NAME not in FORBIDDEN_TUNNELS
    bundle = render_bundle({"MONGO_URL": "mongodb+srv://u:p@h/", "JWT_SECRET": "x" * 64,
                            "INVITE_CODE": "INV", "TUNNEL_TOKEN": "t" * 40}).decode()
    assert [line.split("=", 1)[0] for line in bundle.splitlines()] == list(BUNDLE_KEYS)
    with_mail = render_bundle({"MONGO_URL": "mongodb+srv://u:p@h/", "JWT_SECRET": "x" * 64,
                               "INVITE_CODE": "INV", "TUNNEL_TOKEN": "t" * 40, "RESEND_API_KEY": "re_x"}).decode()
    assert with_mail.splitlines()[-1].startswith("RESEND_API_KEY=")
    try:
        render_bundle({"MONGO_URL": "m", "JWT_SECRET": "j", "INVITE_CODE": "i", "TUNNEL_TOKEN": "t", "EXTRA": "x"})
    except ProvisionError:
        pass
    else:
        raise AssertionError("render_bundle accepted an unknown key")
    assert desired_ingress()["config"]["ingress"][-1] == {"service": "http_status:404"}
    print("CHRONICLES_API_PROVISION_SELF_TEST_OK")


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    try:
        import oci
        for line in provision(os.environ, oci, Cloudflare(os.environ)):
            print(line)
    except ProvisionError as exc:
        print("CHRONICLES_API_PROVISION_BLOCKED " + str(exc), file=sys.stderr)
        return 1
    except Exception as exc:  # never echo SDK payloads
        print("CHRONICLES_API_PROVISION_BLOCKED type=" + type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
