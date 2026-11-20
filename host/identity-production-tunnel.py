#!/usr/bin/env python3
"""Operator-only second-phase Identity tunnel activation.

Does not provision Cloudflare, DNS, Vault, Mongo or any Pages project. The
public identity surface is read-only; Bridge Squad must remain 401 for guests.
A failed post-launch public-key binding or quarantine check stops ONLY the
newly started tunnel. Never authorized from CI.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import bridgesquad_prod_identity_probe as public
import bridgesquad_alias_bootstrap as alias

spec = importlib.util.spec_from_file_location(
    "identity_production_origin_operator", ROOT / "host/identity-production-origin.py")
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)
origin = op.origin

CONFIRM_START = "ENABLE_ONLY_IDENTITY_NAMED_TUNNEL"
CONFIRM_STOP = "STOP_ONLY_IDENTITY_NAMED_TUNNEL"
TUNNEL_IMAGE = "cloudflare/cloudflared@"
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


class Refused(ValueError):
    pass


def exact_jwk(body: bytes) -> dict:
    def unique(pairs):
        values = {}
        for key, value in pairs:
            if key in values:
                raise Refused("ambiguous JWKS JSON")
            values[key] = value
        return values

    try:
        data = json.loads(body.decode("utf-8"), object_pairs_hook=unique)
        if not isinstance(data, dict) or set(data) != {"keys"} or not isinstance(data["keys"], list) or len(data["keys"]) != 1:
            raise Refused("unexpected Identity public key count")
        key = data["keys"][0]
        if (not isinstance(key, dict) or set(key) != {"kty", "crv", "use", "alg", "kid", "x"} or
                key["kty"] != "OKP" or key["crv"] != "Ed25519" or
                key["use"] != "sig" or key["alg"] != "EdDSA" or
                not isinstance(key["kid"], str) or not 1 <= len(key["kid"]) <= 128):
            raise Refused("unexpected Identity key attributes")
        origin.audit_jwks(body)
        return key
    except (ValueError, UnicodeError, TypeError, KeyError) as exc:
        raise Refused("invalid Identity public JWKS") from None


def local_key(ca: Path) -> dict:
    context = origin.tls_context(ca)
    status, _, body = origin.read_origin(context, "/api/identity/jwks")
    if status != 200:
        raise Refused("local JWKS unavailable")
    return exact_jwk(body)


def public_binding(expected: dict, *, read=public.read_public) -> None:
    observed = []

    def reader(url):
        response = read(url)
        if url == public.ISSUER + "/api/identity/jwks":
            if len(response) != 3 or response[0] != 200:
                raise Refused("public JWKS unavailable")
            observed.append(exact_jwk(response[2]))
        return response

    evidence = public.inspect(reader=reader)
    if (evidence["public_surface"] != "present" or
            len(observed) != 1 or observed[0] != expected):
        raise Refused("public issuer does not match healthy local production origin")


def guest_quarantine(*, observe=alias.guest_status):
    # A successful public IdP alone may NOT release protected game assets.
    for path, method in (("/", "GET"), ("/", "HEAD"), ("/index.html", "GET")):
        if observe(public.ORIGIN + path, method) != 401:
            raise Refused("Bridge Squad anonymous quarantine changed")


def local_admission(*, runner=None, inspect=origin.inspect):
    kwargs = {"runner": runner} if runner is not None else {}
    op.admission(**kwargs)
    images = op.run(["docker", "image", "inspect",
                     TUNNEL_IMAGE + os.environ["IDENTITY_PRODUCTION_TUNNEL_DIGEST"],
                     "--format", "{{.Id}}"], **kwargs)
    if not SHA256.fullmatch(images):
        raise Refused("pinned tunnel image not present locally")
    rows = op.container_status(**kwargs)
    if (len(rows) != 1 or rows[0].get("Service") != op.SERVICE or
            rows[0].get("State", "").lower() != "running"):
        raise Refused("exactly one running production origin required")
    ca = origin.ca_file(os.environ.get(origin.CA_ENV, ""))
    receipt = inspect(ca)
    if (receipt.get("tls") != "verified" or receipt.get("ready") != "yes" or
            receipt.get("jwks") != "ed25519-public" or
            receipt.get("foreign_host") != "denied" or
            receipt.get("registration") != "disabled"):
        raise Refused("local origin TLS/health/security contract refused")
    return ca


def start_tunnel(*, runner=None, inspect=origin.inspect,
                 get_local_key=local_key, check_public=public_binding,
                 check_guest=guest_quarantine, sleep=time.sleep):
    op.require_manual(CONFIRM_START)
    kwargs = {"runner": runner} if runner is not None else {}
    with op.exclusive():
        ca = local_admission(runner=runner, inspect=inspect)
        key = get_local_key(ca)
        check_guest()
        started = False
        try:
            started = True  # 'up' may leave a partial container on failure.
            op.run(op.compose_args("up", "--detach", "--no-deps", "--no-build",
                                   "--pull", "never", op.TUNNEL), **kwargs)
            rows = op.container_status(**kwargs)
            if (len(rows) != 2 or {x.get("Service") for x in rows} !=
                    {op.SERVICE, op.TUNNEL} or
                    any(x.get("State", "").lower() != "running" for x in rows)):
                raise Refused("unexpected services after tunnel start")
            for retry in range(6):
                try:
                    # If the origin fails or a different issuer appears at the
                    # public hostname, never keep the new tunnel connected.
                    fresh = inspect(ca)
                    if fresh.get("ready") != "yes" or fresh.get("tls") != "verified":
                        raise Refused("origin degraded after tunnel start")
                    if get_local_key(ca) != key:
                        raise Refused("origin signer rotated during activation")
                    check_public(key)
                    check_guest()
                    return
                except Exception:
                    if retry == 5:
                        raise Refused("public identity proof or guest quarantine failed") from None
                    sleep(2)
        except Exception:
            if started:
                try:
                    op.run(op.compose_args("stop", "--timeout", "10", op.TUNNEL), **kwargs)
                except Exception:
                    raise Refused("tunnel activation denied; scoped rollback ALSO failed") from None
            raise Refused("tunnel activation denied; tunnel stopped") from None


def stop_tunnel(*, runner=None):
    op.require_manual(CONFIRM_STOP)
    kwargs = {"runner": runner} if runner is not None else {}
    with op.exclusive():
        # Do not require public login to be healthy during rollback. Still
        # require the exact local deployment to avoid stopping unrelated apps.
        op.admission(**kwargs)
        rows = op.container_status(**kwargs)
        tunnel = [x for x in rows if x.get("Service") == op.TUNNEL]
        if len(tunnel) != 1 or tunnel[0].get("State", "").lower() != "running":
            raise Refused("expected one running production tunnel")
        op.run(op.compose_args("stop", "--timeout", "10", op.TUNNEL), **kwargs)


def main(argv):
    if argv == ["plan"]:
        print("IDENTITY_PRODUCTION_TUNNEL_PLAN start=operator-only rollback=tunnel-only game=401-required")
        return 0
    if argv not in (["inspect"], ["start-tunnel"], ["stop-tunnel"]):
        print("Usage: identity-production-tunnel.py plan|inspect|start-tunnel|stop-tunnel", file=sys.stderr)
        return 2
    try:
        if argv == ["inspect"]:
            ca = local_admission()
            local_key(ca)
            guest_quarantine()
            print("IDENTITY_PRODUCTION_TUNNEL_ADMITTED local-tls=yes game=quarantined deploy=none")
        elif argv == ["start-tunnel"]:
            start_tunnel()
            print("IDENTITY_PRODUCTION_TUNNEL_STARTED local-tls=yes public-jwks=bound game=401 authentication=not-verified")
        else:
            stop_tunnel()
            print("IDENTITY_PRODUCTION_TUNNEL_STOPPED origin=untouched game=unchanged")
        return 0
    except Exception:
        # Never disclose docker stderr, TLS material, JWTs or credentials.
        print("IDENTITY_PRODUCTION_TUNNEL_REFUSED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
