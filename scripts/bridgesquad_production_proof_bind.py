#!/usr/bin/env python3
"""Operator-only production Pages service-proof binding for Matthias Bridge Squad.

No GitHub Actions execution, automatic secret creation, game upload or DNS write.
A binding is a CONFIGURATION step, not evidence that a user can play.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.request

import bridgesquad_dns_quarantine as quarantine
import bridgesquad_pages_readiness as readiness
import bridgesquad_prod_identity_probe as identity
import bridgesquad_source_admission as source

KEY = "SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL"
PROOF = re.compile(r"soc1_[A-Za-z0-9_-]{43}\Z")
CONFIRM = "BIND_BRIDGESQUAD_PRODUCTION_PROOF_ONLY"
PROJECT_PATH = "/accounts/{account}/pages/projects/" + readiness.PROJECT


class Refused(ValueError):
    pass


def _production_project(client, expected_sha):
    config, _, actual_sha = quarantine.project(client)
    if not source.SHA.fullmatch(expected_sha) or actual_sha != expected_sha:
        raise Refused("deployed game SHA differs from operator-approved SHA")
    return config


def admission(client, expected_sha, *, audit=quarantine.audit, public=identity.inspect):
    """Check the EXISTING quarantine before allowing a single secret write."""
    if not source.SHA.fullmatch(expected_sha):
        raise Refused("explicit 40-character release SHA required")
    receipt = audit(client)
    if receipt.get("source_sha") != expected_sha or receipt.get("https") != "401-login-shell" \
            or receipt.get("assets") != "denied" or receipt.get("dns") != "present" \
            or receipt.get("domain") != "present":
        raise Refused("authenticated Pages release preflight failed")
    observed = public()
    # JWKS/login/readiness are prerequisites, not proof of a usable account,
    # service proof, JWT minting or live freshness/revocation.
    if observed.get("public_surface") != "present":
        raise Refused("dedicated production Identity public surface not ready")
    config = _production_project(client, expected_sha)
    return config["deployment_configs"]["production"]["compatibility_flags"]


def postflight(client, expected_sha, *, audit=quarantine.audit, public=identity.inspect):
    """Read-only verification. Do not return or print any secret data."""
    config, _, actual_sha = quarantine.project(client, allow_bound=True)
    if actual_sha != expected_sha:
        raise Refused("canonical release changed during binding")
    production = config["deployment_configs"]["production"]["env_vars"]
    preview = config["deployment_configs"]["preview"].get("env_vars") or {}
    if (not isinstance(production, dict) or set(production) != {KEY}
            or not isinstance(production[KEY], dict)
            or production[KEY].get("type") != "secret_text" or preview):
        raise Refused("Cloudflare did not confirm production-only encrypted binding")
    receipt = audit(client, allow_bound=True)
    if receipt.get("source_sha") != expected_sha or receipt.get("production_identity") != "proof-bound-unverified" \
            or receipt.get("https") != "401-login-shell" or receipt.get("assets") != "denied":
        raise Refused("binding has not passed live anonymous-denial checks")
    if public().get("public_surface") != "present":
        raise Refused("production Identity availability changed after binding")
    return {"source_sha": expected_sha, "proof": "encrypted-production-only",
            "guest": "denied", "authenticated": "NOT_VERIFIED"}


class CloudflareClient(readiness.CloudflareClient):
    def patch_proof(self, proof: str, flags) -> None:
        """The ONLY allowed Cloudflare mutation: Pages production encrypted variable."""
        if not PROOF.fullmatch(proof) or not isinstance(flags, list) \
                or "global_fetch_strictly_public" not in flags \
                or "global_fetch_private_origin" in flags:
            raise Refused("refusing an invalid consumer proof or unsafe Pages compatibility")
        body = json.dumps({"deployment_configs": {"production": {
            "fail_open": False, "compatibility_flags": flags,
            "env_vars": {KEY: {"type": "secret_text", "value": proof}},
        }}}, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            readiness.API + PROJECT_PATH.format(account=self.account),
            method="PATCH", data=body,
            headers={"Authorization": "Bearer " + self._token,
                     "Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                code, raw = response.status, response.read(1048577)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
            raise Refused("production binding was not confirmed by Cloudflare") from None
        if code != 200 or len(raw) > 1048576:
            raise Refused("production binding response invalid")
        try:
            body = json.loads(raw)
        except (UnicodeError, ValueError):
            raise Refused("Cloudflare binding response malformed") from None
        if not isinstance(body, dict) or body.get("success") is not True \
                or not isinstance(body.get("result"), dict) \
                or body["result"].get("name") != readiness.PROJECT:
            raise Refused("Cloudflare project binding acknowledgement invalid")


def read_private_proof(path: str) -> str:
    """Only an operator-owned root file; no symlinks, env values or argv secrets."""
    if not path or "\x00" in path:
        raise Refused("private proof file path required")
    target = Path(path)
    if not target.is_absolute() or target == Path("/"):
        raise Refused("proof path must be absolute")
    try:
        for node in (target, *target.parents):
            if stat.S_ISLNK(os.lstat(node).st_mode):
                raise Refused("symlink in secret path")
        info = os.stat(target, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 \
                or stat.S_IMODE(info.st_mode) not in (0o400, 0o600) \
                or info.st_size != 48:
            raise Refused("production secret file must be 48 bytes, root-only")
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            observed = os.fstat(fd)
            if (observed.st_ino, observed.st_dev) != (info.st_ino, info.st_dev):
                raise Refused("secret replaced during inspection")
            raw = os.read(fd, 49)
        finally:
            os.close(fd)
        proof = raw.decode("ascii")
        if not PROOF.fullmatch(proof):
            raise Refused("production service proof format invalid")
        return proof
    except (OSError, UnicodeError):
        raise Refused("production secret file unavailable") from None


def bind_once(client, expected_sha: str, proof: str, *,
              audit=quarantine.audit, public=identity.inspect):
    """Revalidate before the only write, then read back and verify guest denial."""
    flags = admission(client, expected_sha, audit=audit, public=public)
    # A second read excludes a changed release or newly attached bindings.
    _production_project(client, expected_sha)
    client.patch_proof(proof, flags)
    return postflight(client, expected_sha, audit=audit, public=public)


def main(argv: list[str]) -> int:
    if argv == ["plan"]:
        print("BRIDGESQUAD_PRODUCTION_PROOF_PLAN operation=operator-only "
              "target=production-only game_release=no guest=must-deny")
        return 0
    if len(argv) != 2 or argv[0] not in ("inspect", "bind"):
        print("Usage: bridgesquad_production_proof_bind.py plan|inspect SHA|bind SHA",
              file=sys.stderr)
        return 2
    mode, sha = argv
    try:
        client = CloudflareClient(os.environ)
        if mode == "inspect":
            admission(client, sha)
            print("BRIDGESQUAD_PRODUCTION_PROOF_INSPECT_OK "
                  "identity=public-only guest=denied binding=not-attempted")
            return 0
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS") \
                or os.geteuid() != 0 or not sys.stdin.isatty():
            raise Refused("production binding requires an interactive root operator")
        if input("Type " + CONFIRM + ": ") != CONFIRM:
            raise Refused("operator confirmation missing")
        # Public preflight before opening the private file.
        admission(client, sha)
        secret = read_private_proof(os.environ.get("BRIDGESQUAD_PROOF_FILE", ""))
        result = bind_once(client, sha, secret)
        print("BRIDGESQUAD_PRODUCTION_PROOF_BOUND source_sha=" + result["source_sha"]
              + " proof=encrypted-production-only guest=denied "
              "authenticated=NOT_VERIFIED")
        return 0
    except (Refused, ValueError, OSError, readiness.InventoryError,
            quarantine.QuarantineError):
        # Never print Cloudflare responses, secret values or private host paths.
        print("BRIDGESQUAD_PRODUCTION_PROOF_REFUSED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
