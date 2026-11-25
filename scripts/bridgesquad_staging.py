#!/usr/bin/env python3
"""Bridge Squad *staging* behind ShadowOps ID staging (id-staging), own DNS.

Owns only: Pages project `bridgesquad-staging`, custom domain and proxied
CNAME `staging.bridgesquad.shadowops.dpdns.org`, and its production-mode
`SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL` secret binding. Never touches the
production project/host, other games, or Identity itself.

Every Cloudflare write is an exact allowlisted request; provider messages,
response bodies and secrets are never printed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import bridgesquad_pages_readiness as readiness
import bridgesquad_source_admission as source
import bridgesquad_source_snapshot as snapshot
from bridgesquad_alias_bootstrap import guest_status, _hosts, _canonical
from bridgesquad_pages_provision import safe_provider_code

ROOT = Path(__file__).resolve().parents[1]
EDGE = ROOT / "edge" / "bridgesquad-staging-identity-gate.mjs"
PROJECT = "bridgesquad-staging"
HOST = "staging.bridgesquad.shadowops.dpdns.org"
ZONE = "shadowops.dpdns.org"
ISSUER = "https://id-staging.shadowops.dpdns.org"
KEY = "SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL"
PROOF = re.compile(r"soc1_[A-Za-z0-9_-]{43}\Z")
STRICT = "global_fetch_strictly_public"
GUEST_JSON_PATHS = ("/release.json", "/_worker.js", "/api/bridgesquad/session")
WORKER_MARKERS = (
    "export const HOST='" + HOST + "'",
    "export const ISSUER='" + ISSUER + "'",
    "export const AUDIENCE='bridgesquad'",
    "SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL",
)
assert PROJECT != readiness.PROJECT and HOST != readiness.HOST


class StagingError(ValueError):
    pass


def project_path(account: str) -> str:
    return "/accounts/" + account + "/pages/projects/" + PROJECT


class Client(readiness.CloudflareClient):
    """GET anything read-only; write only the exact staging resources."""

    def allowed(self, method: str, path: str, value: dict, zone: str | None) -> bool:
        root = "/accounts/" + self.account + "/pages/projects"
        exact = project_path(self.account)
        if method == "POST" and path == root:
            return value == {"name": PROJECT, "production_branch": "main"}
        if method == "PATCH" and path == exact and set(value) == {"deployment_configs"}:
            configs = value["deployment_configs"]
            if not isinstance(configs, dict):
                return False
            if set(configs) == {"production", "preview"}:  # fail-closed policy only
                return all(isinstance(c, dict) and set(c) == {"fail_open", "compatibility_flags"}
                           and c["fail_open"] is False and STRICT in c["compatibility_flags"]
                           and "global_fetch_private_origin" not in c["compatibility_flags"]
                           for c in configs.values())
            if set(configs) == {"production"}:  # the app-only secret binding only
                env = configs["production"].get("env_vars") if isinstance(configs["production"], dict) else None
                return (set(configs["production"]) == {"env_vars"} and isinstance(env, dict)
                        and set(env) == {KEY} and env[KEY].get("type") == "secret_text"
                        and isinstance(env[KEY].get("value"), str) and bool(PROOF.fullmatch(env[KEY]["value"])))
            return False
        if method == "POST" and path == exact + "/domains":
            return value == {"name": HOST}
        if method == "POST" and zone and path == "/zones/" + zone + "/dns_records":
            return value == {"type": "CNAME", "name": HOST, "content": PROJECT + ".pages.dev",
                             "proxied": True, "ttl": 1}
        return False

    def write(self, method: str, path: str, value: dict, *, zone: str | None = None):
        if not self.allowed(method, path, value, zone):
            raise StagingError("Noncanonical Cloudflare mutation denied")
        req = urllib.request.Request(
            readiness.API + path, method=method,
            data=json.dumps(value, separators=(",", ":")).encode(),
            headers={"Authorization": "Bearer " + self._token,
                     "Accept": "application/json", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as res:
                status, raw = res.status, res.read(2_000_001)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read(2_000_001)
        except urllib.error.URLError:
            raise StagingError("Cloudflare write unavailable") from None
        if status not in (200, 201) or len(raw) > 2_000_000:
            code = safe_provider_code(raw)
            raise StagingError("Cloudflare write rejected (HTTP " + str(status) + ")"
                               + (" API " + code if code else ""))
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError):
            raise StagingError("Invalid Cloudflare response") from None
        if not isinstance(data, dict) or data.get("success") is not True:
            raise StagingError("Cloudflare mutation unconfirmed")
        return data.get("result")


# ---------------------------------------------------------------- inventory
def zone_id(client) -> str:
    zones = client.get("/zones?name=" + urllib.parse.quote(ZONE))
    if not isinstance(zones, list) or len(zones) != 1 or zones[0].get("name") != ZONE:
        raise StagingError("Ambiguous or missing zone")
    return zones[0]["id"]


def dns_records(client, zone: str) -> list:
    records = client.get("/zones/" + zone + "/dns_records?name=" + urllib.parse.quote(HOST))
    if not isinstance(records, list):
        raise StagingError("DNS inventory unavailable")
    return records


def inventory(client) -> dict:
    """Classify project/domain/DNS ownership; refuse anything foreign."""
    project = client.get(project_path(client.account))
    if project is not None:
        if (not isinstance(project, dict) or project.get("name") != PROJECT
                or project.get("production_branch") != "main" or project.get("source")
                or not str(project.get("subdomain", "")).startswith(PROJECT)):
            raise StagingError("Foreign or Git-connected Pages project")
    domain = client.get(project_path(client.account) + "/domains/" + urllib.parse.quote(HOST, safe="")) \
        if project is not None else None
    if domain is not None and (not isinstance(domain, dict) or domain.get("name") != HOST):
        raise StagingError("Foreign Pages custom domain")
    zone = zone_id(client)
    records = dns_records(client, zone)
    if len(records) > 1:
        raise StagingError("Ambiguous DNS for staging host")
    dns = None
    if records:
        r = records[0]
        if r.get("type") != "CNAME" or r.get("content") != PROJECT + ".pages.dev" or r.get("proxied") is not True:
            raise StagingError("Foreign DNS record for staging host")
        dns = r
    if (dns is not None or domain is not None) and project is None:
        raise StagingError("Orphaned domain/DNS cannot be adopted")
    return {"project": project, "domain": domain, "dns": dns, "zone": zone}


def state_line(inv: dict) -> str:
    return " ".join(k + "=" + ("present" if inv[k] is not None else "absent")
                    for k in ("project", "domain", "dns"))


# ---------------------------------------------------------------- provision
def provision(client) -> dict:
    inv = inventory(client)
    path = project_path(client.account)
    if inv["project"] is None:
        created = client.write("POST", "/accounts/" + client.account + "/pages/projects",
                               {"name": PROJECT, "production_branch": "main"})
        if not isinstance(created, dict) or created.get("name") != PROJECT:
            raise StagingError("Pages project creation returned foreign identity")
    project = client.get(path)
    configs = (project or {}).get("deployment_configs") or {}
    settings = {}
    for mode in ("production", "preview"):
        flags = (configs.get(mode) or {}).get("compatibility_flags") or []
        if not isinstance(flags, list) or "global_fetch_private_origin" in flags:
            raise StagingError("Identity HTTPS origin must remain public-routed")
        settings[mode] = {"fail_open": False, "compatibility_flags": sorted(set(flags) | {STRICT})}
    client.write("PATCH", path, {"deployment_configs": settings})
    verify_posture(client.get(path))
    return {"project": PROJECT, "fail_open": "false"}


def verify_posture(project) -> dict:
    if not isinstance(project, dict) or project.get("name") != PROJECT:
        raise StagingError("Staging project missing")
    configs = project.get("deployment_configs") or {}
    for mode in ("production", "preview"):
        cfg = configs.get(mode) or {}
        if cfg.get("fail_open") is not False or STRICT not in (cfg.get("compatibility_flags") or []):
            raise StagingError("Pages fail-closed policy not in force")
    preview_env = (configs.get("preview") or {}).get("env_vars") or {}
    if preview_env:
        raise StagingError("Preview deployments must never carry Identity secrets")
    prod_env = (configs.get("production") or {}).get("env_vars") or {}
    if set(prod_env) - {KEY} or (KEY in prod_env and (prod_env[KEY] or {}).get("type") != "secret_text"):
        raise StagingError("Unexpected production environment variables")
    return {"proof": "bound" if KEY in prod_env else "pending"}


# ---------------------------------------------------------------- package
def trusted_worker() -> bytes:
    data = EDGE.read_bytes()
    text = data.decode("utf-8")
    if any(marker not in text for marker in WORKER_MARKERS) or "id.shadowops.dpdns.org'" in text:
        raise StagingError("Staging Worker does not match the reviewed contract")
    return data


def package(sha: str, destination: Path, *, reader=None, fetch=snapshot.download) -> dict:
    """Admit the exact green game main SHA and seal index.html + staging Worker."""
    if not isinstance(sha, str) or not source.SHA.fullmatch(sha):
        raise StagingError("Exact game SHA required")
    if reader is not None:
        source.admit(reader, sha)
    if destination.exists():
        raise StagingError("Package destination must be new")
    html = fetch(sha)
    snapshot.validate_html(sha, html)
    worker = trusted_worker()
    manifest = {
        "game": "matthias-bridge-squad", "source_commit": sha, "environment": "staging",
        "host": HOST, "issuer": ISSUER,
        "authentication": {"provider": "shadowops-id", "audience": "bridgesquad", "required": True},
        "index_sha256": hashlib.sha256(html).hexdigest(),
        "worker_sha256": hashlib.sha256(worker).hexdigest(),
    }
    destination.mkdir(parents=True)
    (destination / "index.html").write_bytes(html)
    (destination / "_worker.js").write_bytes(worker)
    (destination / "release.json").write_text(json.dumps(manifest, sort_keys=True, indent=1) + "\n")
    return verify_package(destination, sha)


def verify_package(destination: Path, sha: str) -> dict:
    names = sorted(p.name for p in destination.iterdir())
    if names != ["_worker.js", "index.html", "release.json"] or any(p.is_symlink() for p in destination.iterdir()):
        raise StagingError("Package must hold exactly index.html, _worker.js and release.json")
    manifest = json.loads((destination / "release.json").read_text())
    html, worker = (destination / "index.html").read_bytes(), (destination / "_worker.js").read_bytes()
    if (manifest.get("source_commit") != sha or manifest.get("host") != HOST
            or manifest.get("index_sha256") != hashlib.sha256(html).hexdigest()
            or manifest.get("worker_sha256") != hashlib.sha256(worker).hexdigest()
            or worker != trusted_worker()):
        raise StagingError("Sealed staging package does not verify")
    return {"source_sha": sha, "index_sha256": manifest["index_sha256"],
            "worker_sha256": manifest["worker_sha256"]}


# ---------------------------------------------------------------- deploy checks
def prove_aliases(project: dict, guest=guest_status) -> int:
    try:
        hosts = _hosts(project)
        for host in hosts:
            for path in ("/", "/index.html", "/release.json", "/api/bridgesquad/session"):
                for method in ("GET", "HEAD"):
                    if guest("https://" + host + path, method) != 404:
                        raise StagingError("A Pages alias does not deny guests with the Worker 404")
    except StagingError:
        raise
    except Exception:
        raise StagingError("Pages aliases could not be verified") from None
    return len(hosts)


def postdeploy(client, sha: str, guest=guest_status) -> dict:
    project = client.get(project_path(client.account))
    verify_posture(project)
    try:
        _canonical(project, sha)
    except Exception:
        raise StagingError("Canonical deployment is not the exact sealed game SHA") from None
    return {"source_sha": sha, "aliases": str(prove_aliases(project, guest))}


# ---------------------------------------------------------------- proof binding
def vault_proof(sdk, env) -> str | None:
    """Read Bridge Squad's own staging proof from the operator Vault bundle."""
    from identity_staging_provision import load_existing
    from chronicles_api_provision import resolve_vault
    from oci_control_plane import config_from_env, resolve_existing_host
    config = config_from_env(sdk, env)
    compartment, _ = resolve_existing_host(sdk, config)
    vault, _, _ = resolve_vault(sdk, config, compartment)
    bundle = load_existing(sdk, config, vault, compartment)
    credential = (bundle or {}).get("consumers", {}).get("bridgesquad")
    if credential is None:
        return None
    if not isinstance(credential, str) or not PROOF.fullmatch(credential):
        raise StagingError("Malformed Bridge Squad staging proof in Vault")
    return credential


def bind(client, credential: str) -> dict:
    if not isinstance(credential, str) or not PROOF.fullmatch(credential):
        raise StagingError("Malformed Bridge Squad staging proof")
    path = project_path(client.account)
    verify_posture(client.get(path))
    client.write("PATCH", path, {"deployment_configs": {"production": {
        "env_vars": {KEY: {"type": "secret_text", "value": credential}}}}})
    if verify_posture(client.get(path))["proof"] != "bound":
        raise StagingError("Cloudflare did not report the secret binding")
    return {"proof": "bound-by-name-type-only"}


# ---------------------------------------------------------------- domain / DNS
def attach(client, guest=guest_status) -> dict:
    inv = inventory(client)
    project = inv["project"]
    if project is None or project.get("canonical_deployment") is None:
        raise StagingError("Deploy the sealed Worker before exposing DNS")
    verify_posture(project)
    prove_aliases(project, guest)
    path = project_path(client.account)
    if inv["domain"] is None:
        result = client.write("POST", path + "/domains", {"name": HOST})
        if not isinstance(result, dict) or result.get("name") != HOST:
            raise StagingError("Pages domain was not assigned")
    if inv["dns"] is None:
        if project.get("subdomain") != PROJECT + ".pages.dev":
            raise StagingError("Unexpected Pages subdomain; refusing CNAME")
        client.write("POST", "/zones/" + inv["zone"] + "/dns_records",
                     {"type": "CNAME", "name": HOST, "content": PROJECT + ".pages.dev",
                      "proxied": True, "ttl": 1}, zone=inv["zone"])
    after = inventory(client)
    if after["domain"] is None or after["dns"] is None:
        raise StagingError("Domain/DNS read-after-write incomplete")
    return {"host": HOST, "domain": "owned", "dns": "owned"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def https_probe(path: str, method: str = "GET"):
    if path not in ("/", "/index.html") + GUEST_JSON_PATHS or method not in ("GET", "HEAD"):
        raise StagingError("Unsafe probe route")
    req = urllib.request.Request("https://" + HOST + path, method=method,
                                 headers={"User-Agent": "ShadowOps-BridgeSquad-Staging-Audit/1.0"})
    try:
        with urllib.request.build_opener(_NoRedirect()).open(req, timeout=12) as res:
            return res.status, dict(res.headers), res.read(16385)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read(16385)
    except (urllib.error.URLError, TimeoutError, OSError):
        raise StagingError("Staging HTTPS not yet reachable") from None


def audit(client, *, web=https_probe, guest=guest_status, resolve=socket.getaddrinfo) -> dict:
    inv = inventory(client)
    if inv["project"] is None or inv["domain"] is None or inv["dns"] is None:
        raise StagingError("Staging host is not fully configured (" + state_line(inv) + ")")
    posture = verify_posture(inv["project"])
    aliases = prove_aliases(inv["project"], guest)
    try:
        resolve(HOST, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise StagingError("Staging DNS not yet propagated") from None
    for path in ("/", "/index.html"):
        status, headers, body = web(path)
        lower = body.lower()
        if (status != 401 or b"Tu cuenta ShadowOps ID" not in body
                or (ISSUER + "/login?app=bridgesquad").encode() not in body
                or b"<canvas" in lower or b"id.shadowops.dpdns.org/" in body
                or "default-src 'none'" not in str(headers.get("Content-Security-Policy", ""))):
            raise StagingError("Guest root is not the id-staging login shell")
    for path in GUEST_JSON_PATHS:
        status, headers, body = web(path)
        if status != 401 or body != b'{"error":"authentication_required"}':
            raise StagingError("Guest can reach a protected staging asset")
    for path in ("/", "/index.html", "/release.json"):
        if web(path, "HEAD")[0] != 401:
            raise StagingError("Guest HEAD must be blocked")
    return {"host": HOST, "guest": "401-login-shell", "assets": "denied",
            "aliases": str(aliases), "proof": posture["proof"],
            "source_sha": (((inv["project"].get("canonical_deployment") or {})
                            .get("deployment_trigger") or {}).get("metadata") or {}).get("commit_hash", "")}


def identity_ready(read=None) -> bool:
    """Public check only: is the bridgesquad login callback live on id-staging?"""
    url = ISSUER + "/login?app=bridgesquad"
    try:
        if read is None:
            req = urllib.request.Request(url, headers={"User-Agent": "ShadowOps-BridgeSquad-Staging-Audit/1.0"})
            with urllib.request.build_opener(_NoRedirect()).open(req, timeout=12) as res:
                status, body = res.status, res.read(65537)
        else:
            status, body = read(url)
    except (urllib.error.URLError, TimeoutError, OSError):
        return False
    return status == 200 and ("https://" + HOST + "/?shadowops=central").encode() in body


# ---------------------------------------------------------------- CLI
def emit(tag: str, values: dict) -> None:
    print(tag + " " + " ".join(k + "=" + str(v) for k, v in values.items()))


def main(argv: list[str]) -> int:
    try:
        if argv == ["plan"]:
            emit("BRIDGESQUAD_STAGING_PLAN", {"project": PROJECT, "host": HOST, "issuer": ISSUER,
                                              "worker": EDGE.relative_to(ROOT)})
            return 0
        if argv == ["identity"]:
            emit("BRIDGESQUAD_STAGING_IDENTITY", {"login_callback": "live" if identity_ready() else "pending"})
            return 0
        if len(argv) == 3 and argv[0] == "package":
            reader = source.GithubReader(os.environ.get("GH_TOKEN", ""))
            emit("BRIDGESQUAD_STAGING_PACKAGED", package(argv[1], Path(argv[2]), reader=reader))
            return 0
        if argv == ["current-sha"]:
            print(source.current_sha(source.GithubReader(os.environ.get("GH_TOKEN", ""))))
            return 0
        known = (["inspect"], ["provision"], ["bind"], ["attach"], ["audit"])
        if argv not in known and not (len(argv) == 2 and argv[0] == "postdeploy"):
            print("Usage: bridgesquad_staging.py plan|identity|current-sha|package SHA DIR|"
                  "inspect|provision|postdeploy SHA|bind|attach|audit", file=sys.stderr)
            return 64
        client = Client(os.environ)
        if argv == ["inspect"]:
            inv = inventory(client)
            extra = verify_posture(inv["project"]) if inv["project"] is not None else {"proof": "n/a"}
            emit("BRIDGESQUAD_STAGING_INVENTORY", {"state": state_line(inv).replace(" ", ","), **extra})
        elif argv == ["provision"]:
            emit("BRIDGESQUAD_STAGING_PROVISIONED", provision(client))
        elif len(argv) == 2 and argv[0] == "postdeploy":
            emit("BRIDGESQUAD_STAGING_DEPLOYED", postdeploy(client, argv[1]))
        elif argv == ["bind"]:
            import oci  # installed only in the protected workflow
            proof = vault_proof(oci, os.environ)
            if proof is None:
                emit("BRIDGESQUAD_STAGING_PROOF_PENDING", {"vault_consumer": "absent",
                     "next": "identity-staging-operations action=bridgesquad-activate"})
            else:
                emit("BRIDGESQUAD_STAGING_PROOF", bind(client, proof))
        elif argv == ["attach"]:
            emit("BRIDGESQUAD_STAGING_DNS", attach(client))
        elif argv == ["audit"]:
            emit("BRIDGESQUAD_STAGING_AUDIT", audit(client))
        else:
            print("Usage: bridgesquad_staging.py plan|identity|current-sha|package SHA DIR|"
                  "inspect|provision|postdeploy SHA|bind|attach|audit", file=sys.stderr)
            return 64
        return 0
    except (StagingError, readiness.InventoryError, source.AdmissionError, snapshot.Refused) as exc:
        print("BRIDGESQUAD_STAGING_BLOCKED " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        # Never echo SDK/provider exception text (may carry identifiers).
        print("BRIDGESQUAD_STAGING_BLOCKED unexpected-" + "error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
