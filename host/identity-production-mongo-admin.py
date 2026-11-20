#!/usr/bin/env python3
"""One-time first Mongo production administrator via the localhost exception.

Never accepts a username/password/URI from argv or environment. A fixed JS
program calls mongosh passwordPrompt() on a real terminal, creates exactly
one admin user and authenticates it before reporting success. No passwords
cross Docker argv, CI, Python memory, log capture or a writable host file.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_replica", HERE / "identity-production-mongo-replica.py"
)
if spec is None or spec.loader is None:
    raise SystemExit("IDENTITY_PRODUCTION_MONGO_ADMIN_REFUSED")
replica = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replica)

USER = "identity_prod_admin"
ACK = "CREATE_FIRST_PRODUCTION_MONGO_ADMIN_ONLY"
# JS is a fixed literal: the password is prompted and handled entirely
# inside mongosh, never interpolated by Python or supplied over argv/stdin.
# A failed auth check after createUser is NOT retry-safe: the first user
# may already exist. Operator must inspect and recover manually.
CREATE_JS = (
    'const admin=db.getSiblingDB("admin");'
    'const pwd=passwordPrompt();'
    'const again=passwordPrompt();'
    'if(typeof pwd!=="string"||pwd.length<32||pwd!==again){quit(31);}'
    'const result=admin.runCommand({'
      'createUser:"identity_prod_admin",'
      'pwd:pwd,'
      'roles:[{role:"root",db:"admin"}],'
      'mechanisms:["SCRAM-SHA-256"],'
      'writeConcern:{w:"majority",wtimeout:15000}'
    '});'
    'if(result.ok!==1){quit(32);}'
    'if(!admin.auth("identity_prod_admin",pwd)){quit(33);}'
    'const created=admin.getUser("identity_prod_admin");'
    'if(!created||!Array.isArray(created.roles)||created.roles.length!==1||'
      'created.roles[0].role!=="root"||created.roles[0].db!=="admin"){quit(34);}'
    'print("FIRST_ADMIN_CREATED_AND_AUTHENTICATED");'
)


class Refused(ValueError):
    pass


def confirm_operator(*, euid=None, stdin=None, stdout=None, env=None,
                     prompt=input) -> None:
    env = os.environ if env is None else env
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    euid = os.geteuid() if euid is None else euid
    if (euid != 0 or env.get("CI") or env.get("GITHUB_ACTIONS") or
            not stdin.isatty() or not stdout.isatty()):
        raise Refused("root interactive local terminal required")
    if prompt("First Mongo admin operation, type ACK: ").strip() != ACK:
        raise Refused("operator confirmation denied")


def first_admin_argv(container_id: str) -> list[str]:
    import re
    if not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise Refused("untrusted Docker container ID")
    return [
        "docker", "exec", "-it", container_id,
        "mongosh", "--quiet", "--norc",
        "--tls", "--tlsCAFile", "/run/mongo/ca.pem",
        replica.DESTINATION, "--eval", CREATE_JS,
    ]


def create_first_admin(*, runner=subprocess.run, confirm=confirm_operator) -> None:
    # No Docker access whatsoever without explicit root+TTY authorization.
    confirm()
    # Reuse the exact lock from first-start and replica init. No competing
    # mutation may run while creating the first privileged Mongo user.
    with replica.operator.single_operator():
        cid = replica.verified_container()
        # Required first-user sequence: replica must already have PRIMARY.
        if replica.run_mongosh(cid, replica.PROBE_JS) != "PRIMARY":
            raise Refused("Mongo not primary")
        args = first_admin_argv(cid)
        # Inherit the operator's TTY, allowing mongosh passwordPrompt() to
        # mask input. Do NOT use PIPE, capture_output, env passwords, shell
        # interpolation or an executable JS file on disk.
        try:
            result = runner(args, check=False, timeout=180)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused("interactive first-admin command unavailable") from None
        if result.returncode != 0:
            # There is no safe automatic retry: a user might have been created.
            raise Refused("first-admin operation failed or needs manual recovery")
        # The JS itself verifies authentication and exact root role before
        # exiting zero. Keep output generic, even after command success.


def main(argv: list[str]) -> int:
    if argv == ["plan"]:
        print("IDENTITY_PRODUCTION_MONGO_FIRST_ADMIN_PLAN"
              " account=identity_prod_admin db=admin"
              " role=root purpose=breakglass bootstrap=localhost-exception"
              " password=mongosh-tty-prompt plaintext=never-in-argv"
              " repeat=deny account_file=operator-managed")
        return 0
    if argv not in (["inspect"], ["create"]):
        print("Usage: identity-production-mongo-admin.py plan|inspect|create",
              file=sys.stderr)
        return 2
    try:
        if argv == ["inspect"]:
            state = replica.inspect()
            print("IDENTITY_PRODUCTION_MONGO_FIRST_ADMIN_INSPECT"
                  " replica=" + state.lower() +
                  " admin_state=not-verified mutations=none")
        else:
            create_first_admin()
            print("IDENTITY_PRODUCTION_MONGO_FIRST_ADMIN_CREATED"
                  " user=identity_prod_admin"
                  " authenticated_by=mongosh"
                  " backup=not-proven runtime=not-created")
        return 0
    except Exception:
        print("IDENTITY_PRODUCTION_MONGO_FIRST_ADMIN_REFUSED"
              " if-partial=inspect-manually-do-not-retry", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
