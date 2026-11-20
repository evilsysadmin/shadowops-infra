#!/usr/bin/env python3
"""Manual Mongo replica-set initiation, restricted to exact production CID.

Never creates Mongo users, exports secrets, joins staging or modifies Docker
Compose. It uses fixed mongosh JS and TLS via localhost inside the container.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import time

SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_start", SCRIPTS / "identity-production-mongo-start.py"
)
if spec is None or spec.loader is None:
    raise SystemExit("IDENTITY_PRODUCTION_MONGO_REPLICA_REFUSED")
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)

REPLICA = operator.host.REPLICA
MEMBER = "identity-mongo-production:27017"
ACK = "INIT_ISOLATED_PRODUCTION_MONGO_REPLICA_ONLY"
DESTINATION = "mongodb://127.0.0.1:27017/?directConnection=true"
# Never insert untrusted shell text into these fixed JS programs.
PROBE_JS = (
    "const h=db.hello();"
    'if(h.isWritablePrimary===true){print("PRIMARY");}'
    "else{const s=db.adminCommand({replSetGetStatus:1});"
    'if(s.code===94){print("UNINITIALIZED");}'
    'else if(s.ok===1){print("NONPRIMARY");}'
    "else{quit(17);}}"
)
INIT_JS = (
    'const r=rs.initiate({_id:"identity-production-rs",'
    'members:[{_id:0,host:"identity-mongo-production:27017"}]});'
    'if(r.ok===1){print("INIT_ACCEPTED");}else{quit(18);}'
)


class Refused(ValueError):
    pass


def run_mongosh(cid: str, program: str, *, runner=None) -> str:
    if program not in (PROBE_JS, INIT_JS):
        raise Refused("unapproved Mongo command")
    # The exact CID is already inspected, so Docker cannot resolve a foreign
    # container by friendly name. The JS contains no credentials.
    options = {
        "timeout": 25,
        "limit": 256,
    }
    if runner is not None:
        options["runner"] = runner
    return operator.docker(
        "exec", "-i", cid, "mongosh", "--quiet", "--norc",
        "--tls", "--tlsCAFile", "/run/mongo/ca.pem",
        DESTINATION, "--eval", program, **options,
    )


def verified_container(*, runner=None) -> str:
    args = {} if runner is None else {"runner": runner}
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        raise Refused("CI cannot operate a live Mongo replica")
    operator.host.validate_compose(
        operator.host.COMPOSE.read_text(encoding="utf-8")
    )
    operator.host.inspect_private_files()
    operator.image_admission(**args)
    operator.rendered_compose_admission(**args)
    return operator.poststart(**args)


def inspect(*, runner=None) -> str:
    cid = verified_container(runner=runner)
    result = run_mongosh(cid, PROBE_JS, runner=runner)
    if result not in ("PRIMARY", "UNINITIALIZED", "NONPRIMARY"):
        raise Refused("untrusted Mongo replica state")
    return result


def initiate(*, runner=None, sleep=time.sleep) -> None:
    # Real operator root/TTY gate and exact user-entered ACK.
    if (os.geteuid() != 0 or os.environ.get("CI") or
            os.environ.get("GITHUB_ACTIONS") or not sys.stdin.isatty()):
        raise Refused("manual root terminal required")
    if input("Confirm Mongo replica initiation: ").strip() != ACK:
        raise Refused("operator did not approve exact replica")
    with operator.single_operator():
        cid = verified_container(runner=runner)
        if run_mongosh(cid, PROBE_JS, runner=runner) != "UNINITIALIZED":
            raise Refused("replica has already been initiated or cannot be inspected")
        reply = run_mongosh(cid, INIT_JS, runner=runner)
        if reply != "INIT_ACCEPTED":
            raise Refused("replica initiation not confirmed")
        for index in range(20):
            state = run_mongosh(cid, PROBE_JS, runner=runner)
            if state == "PRIMARY":
                return
            if state != "NONPRIMARY":
                raise Refused("unexpected post-init replica state")
            if index < 19:
                sleep(2)
        # No rollback/reinit: replica initiation may have persisted.
        raise Refused("replica initiated but primary election unverified")


def main(argv: list[str]) -> int:
    if argv == ["plan"]:
        print("IDENTITY_PRODUCTION_MONGO_REPLICA_PLAN"
              " member=identity-mongo-production:27017"
              " primary=manual-validation"
              " first_admin=separate-step"
              " rollback=none user_creation=no")
        return 0
    if argv not in (["inspect"], ["init"]):
        print("Usage: identity-production-mongo-replica.py plan|inspect|init",
              file=sys.stderr)
        return 2
    try:
        if argv == ["inspect"]:
            state = inspect()
            print("IDENTITY_PRODUCTION_MONGO_REPLICA_INSPECT"
                  " state=" + state.lower() + " mutations=none")
        else:
            initiate()
            print("IDENTITY_PRODUCTION_MONGO_REPLICA_INIT_OK"
                  " state=primary first_admin=not-created"
                  " credentials=not-created backups=not-proven")
        return 0
    except Exception:
        # Driver errors and mongosh stderr can expose connection metadata.
        print("IDENTITY_PRODUCTION_MONGO_REPLICA_REFUSED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
