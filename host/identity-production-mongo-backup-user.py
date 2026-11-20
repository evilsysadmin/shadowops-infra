#!/usr/bin/env python3
"""Manual creation of the single Mongo production backup-only user.

Mongo admin login is prompted by mongosh. The backup user's new password is
prompted twice inside mongosh. Neither password enters Python, argv, env,
captured logs or a repository file. This operator never enables backups.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_admin", HERE / "identity-production-mongo-admin.py"
)
if spec is None or spec.loader is None:
    raise SystemExit("IDENTITY_PRODUCTION_MONGO_BACKUP_USER_REFUSED")
admin_op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admin_op)
replica = admin_op.replica

ACCOUNT = "identity_prod_backup"
ADMIN = admin_op.USER
ACK = "CREATE_PRODUCTION_MONGO_BACKUP_USER_ONLY"
JS = (
    'const admin=db.getSiblingDB("admin");'
    'const existing=admin.getUser("identity_prod_backup");'
    'if(existing){quit(40);}'
    'const pwd=passwordPrompt();'
    'const repeated=passwordPrompt();'
    'if(typeof pwd!=="string"||pwd.length<32||pwd!==repeated){quit(41);}'
    'const r=admin.runCommand({'
      'createUser:"identity_prod_backup",'
      'pwd:pwd,'
      'roles:[{role:"backup",db:"admin"}],'
      'mechanisms:["SCRAM-SHA-256"],'
      'writeConcern:{w:"majority",wtimeout:15000}'
    '});'
    'if(r.ok!==1){quit(42);}'
    'const user=admin.getUser("identity_prod_backup");'
    'if(!user||!Array.isArray(user.roles)||user.roles.length!==1||'
      'user.roles[0].role!=="backup"||user.roles[0].db!=="admin"){quit(43);}'
    'print("BACKUP_USER_CREATED_ROLE_VERIFIED");'
)


class Refused(ValueError):
    pass


def authorize(*, euid=None, stdin=None, stdout=None, env=None, prompt=input):
    env = os.environ if env is None else env
    euid = os.geteuid() if euid is None else euid
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    if (euid != 0 or env.get("CI") or env.get("GITHUB_ACTIONS") or
            not stdin.isatty() or not stdout.isatty()):
        raise Refused("root TTY and non-CI operator required")
    if prompt("Confirm exact backup user creation: ").strip() != ACK:
        raise Refused("operator declined backup user creation")


def argv_for(cid: str) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{64}", cid):
        raise Refused("untrusted Mongo container ID")
    return [
        "docker", "exec", "-it", cid,
        "mongosh", "--quiet", "--norc",
        "--tls", "--tlsCAFile", "/run/mongo/ca.pem",
        "--username", ADMIN, "--authenticationDatabase", "admin",
        replica.DESTINATION, "--eval", JS,
    ]


def create(*, runner=subprocess.run, confirm=authorize):
    confirm()
    with replica.operator.single_operator():
        cid = replica.verified_container()
        if replica.run_mongosh(cid, replica.PROBE_JS) != "PRIMARY":
            raise Refused("Mongo backup user cannot be created without PRIMARY")
        # Authenticates the existing first admin using mongosh's masked
        # password prompt. JS itself prompts twice for a NEW backup password.
        try:
            result = runner(argv_for(cid), check=False, timeout=180)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused("interactive Mongo backup user creation unavailable") from None
        if result.returncode:
            # createUser may have committed before failure. Never auto-retry.
            raise Refused("backup user create failed; inspect manually before retry")


def main(args: list[str]) -> int:
    if args == ["plan"]:
        print("IDENTITY_PRODUCTION_MONGO_BACKUP_USER_PLAN"
              " account=identity_prod_backup role=backup authdb=admin"
              " access=mongodump-only password=masked-in-mongosh"
              " first_admin=required backup_timer=not-enabled")
        return 0
    if args not in (["inspect"], ["create"]):
        print("Usage: identity-production-mongo-backup-user.py plan|inspect|create",
              file=sys.stderr)
        return 2
    try:
        if args == ["inspect"]:
            state = replica.inspect()
            print("IDENTITY_PRODUCTION_MONGO_BACKUP_USER_INSPECT"
                  " replica=" + state.lower() +
                  " account_state=not-verified mutations=none")
        else:
            create()
            print("IDENTITY_PRODUCTION_MONGO_BACKUP_USER_CREATED"
                  " role=backup admin_rights=no"
                  " backup_secret_file=not-created timer=disabled")
        return 0
    except Exception:
        print("IDENTITY_PRODUCTION_MONGO_BACKUP_USER_REFUSED"
              " if-partial=inspect-manually-do-not-retry", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
