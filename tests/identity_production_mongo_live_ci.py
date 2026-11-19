#!/usr/bin/env python3
"""Authenticated/TLS MongoDB 7 integration fixture, localhost-only, no real secrets.

Never invoke the protected production CLI apply. The module-level provision()
is used directly against a disposable container with a deliberately different
replica set and port. Runtime proof is independently performed by real Go code.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

from pymongo import MongoClient
from pymongo.errors import OperationFailure, PyMongoError

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/identity_production_mongo_operator.py"
spec = importlib.util.spec_from_file_location("production_mongo_operator", SOURCE)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)

PORT = 27029
REPLICA = "identity-prod-ci-rs"
CONTAINER = "identity-prod-mongo-fixture-ci"
ROOT_USER = "identity_test_root"


def run(*args: str, cwd: Path | None = None, env: dict | None = None, output: bool = False):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=140)
    if result.returncode != 0:
        # Do not echo process arguments or stderr: driver errors can contain
        # credentials from the synthetic Mongo URI.
        raise AssertionError("disposable fixture command failed")
    if output:
        print(result.stdout.strip())
    return result.stdout.strip()


def tls_material(path: Path):
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", str(path / "ca.key"), "-out", str(path / "ca.pem"),
        "-subj", "/CN=disposable identity mongo test CA")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(path / "server.key"), "-out", str(path / "server.csr"),
        "-subj", "/CN=localhost")
    (path / "server.ext").write_text("subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n")
    run("openssl", "x509", "-req", "-in", str(path / "server.csr"),
        "-CA", str(path / "ca.pem"), "-CAkey", str(path / "ca.key"),
        "-CAcreateserial", "-days", "1", "-out", str(path / "server.crt"),
        "-extfile", str(path / "server.ext"))
    (path / "mongo.pem").write_bytes(
        (path / "server.crt").read_bytes() + (path / "server.key").read_bytes()
    )
    (path / "replica.key").write_text(secrets.token_urlsafe(384))
    path.chmod(0o755)


def start_mongo(path: Path):
    # MongoDB internal keyfile enables authenticated replica-set use.
    # Only bind loopback; no host data volumes or public/external Mongo URI.
    script = """
set -euo pipefail
cp /fixture/ca.pem /tmp/ca.pem
cp /fixture/mongo.pem /tmp/mongo.pem
cp /fixture/replica.key /tmp/replica.key
chown mongodb:mongodb /tmp/mongo.pem /tmp/replica.key
chmod 0400 /tmp/mongo.pem /tmp/replica.key
exec gosu mongodb mongod --replSet identity-prod-ci-rs --keyFile /tmp/replica.key \\
 --bind_ip 127.0.0.1 --port 27029 --wiredTigerCacheSizeGB 0.25 \\
 --tlsMode requireTLS --tlsCertificateKeyFile /tmp/mongo.pem \\
 --tlsCAFile /tmp/ca.pem --tlsAllowConnectionsWithoutCertificates
"""
    run("docker", "run", "-d", "--name", CONTAINER, "--network", "host",
        "--mount", f"type=bind,src={path},dst=/fixture,readonly",
        "--entrypoint", "bash", "mongo:7.0", "-c", script)


def client(uri: str, ca: Path) -> MongoClient:
    return MongoClient(uri, tls=True, tlsCAFile=str(ca),
                       serverSelectionTimeoutMS=2500, connectTimeoutMS=2500,
                       retryWrites=False)


def ready_without_auth(ca: Path):
    uri = f"mongodb://127.0.0.1:{PORT}/admin?directConnection=true&tls=true"
    for attempt in range(50):
        try:
            c = client(uri, ca)
            hello = c.admin.command({"hello": 1})
            if hello.get("isWritablePrimary") is not None:
                return c
        except PyMongoError:
            pass
        time.sleep(1)
    raise AssertionError("disposable TLS MongoDB did not start")


def must_deny(func, reason: str):
    try:
        func()
    except OperationFailure as exc:
        if exc.code != 13:
            raise AssertionError("unexpected Mongo error for " + reason) from None
    else:
        raise AssertionError("overprivileged runtime Mongo principal: " + reason)


def assert_runtime_boundaries(runtime):
    auth = runtime.admin.command({"connectionStatus": 1, "showPrivileges": True})["authInfo"]
    assert len(auth["authenticatedUsers"]) == 1
    assert auth["authenticatedUsers"][0]["user"] == operator.USER
    assert auth["authenticatedUserRoles"] == operator.USER_ROLES
    assert operator.expected_grants(auth["authenticatedUserPrivileges"])
    db = runtime[operator.DB]
    assert db["sessions"].find_one({}) is None
    # Destructive operations are denied on account and token collections;
    # only the session collection has remove for logout/revocation.
    must_deny(lambda: db["native_accounts"].delete_one({"_id": "synthetic"}),
              "delete native account")
    must_deny(lambda: db["production_application_tokens"].delete_one({"_id": "synthetic"}),
              "delete bound token")
    must_deny(lambda: db.create_collection("forbidden"), "create collection")
    must_deny(lambda: db["native_accounts"].drop(), "drop collection")
    must_deny(lambda: runtime["shadowops_identity_staging"]["sessions"].find_one({}),
              "cross-environment read")
    must_deny(lambda: runtime.admin.command({"usersInfo": 1}),
              "admin user inventory")


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("IDENTITY_PRODUCTION_MONGO_LIVE_CI") != "1" or
            os.environ.get("CI") != "true"):
        raise AssertionError("refusing non-CI executable fixture")
    # Ensure the runner is not already listening on our reserved port.
    import socket
    sock = socket.socket()
    try:
        if sock.connect_ex(("127.0.0.1", PORT)) == 0:
            raise AssertionError("refusing to overwrite existing Mongo listener")
    finally:
        sock.close()
    with tempfile.TemporaryDirectory(prefix="identity-prod-mongo-ci-", dir="/tmp") as temp:
        p = Path(temp)
        tls_material(p)
        root_pass = secrets.token_hex(32)
        runtime_pass = secrets.token_hex(32)
        started = False
        try:
            start_mongo(p)
            started = True
            bootstrap = ready_without_auth(p / "ca.pem")
            try:
                bootstrap.admin.command({"replSetInitiate": {
                    "_id": REPLICA,
                    "members": [{"_id": 0, "host": f"127.0.0.1:{PORT}"}],
                }})
                for attempt in range(50):
                    if bootstrap.admin.command({"hello": 1}).get("isWritablePrimary"):
                        break
                    time.sleep(1)
                else:
                    raise AssertionError("ephemeral replica primary unavailable")
                bootstrap.admin.command({"createUser": ROOT_USER,
                    "pwd": root_pass, "roles": [{"role": "root", "db": "admin"}]})
            finally:
                bootstrap.close()
            root_uri = (
                f"mongodb://{ROOT_USER}:{quote(root_pass)}@127.0.0.1:{PORT}/admin?"
                f"tls=true&authSource=admin&replicaSet={REPLICA}"
            )
            root = client(root_uri, p / "ca.pem")
            runtime_uri = (
                f"mongodb://{operator.USER}:{quote(runtime_pass)}@127.0.0.1:{PORT}/"
                f"{operator.DB}?tls=true&authSource={operator.DB}&replicaSet={REPLICA}"
            )
            try:
                hello = root.admin.command({"hello": 1})
                if hello.get("setName") != REPLICA or not hello.get("isWritablePrimary"):
                    raise AssertionError("expected fresh local replica missing")
                before = operator.provision(root[operator.DB])
                if before["role"] or before["user"]:
                    raise AssertionError("fixture not empty")
                result = operator.provision(root[operator.DB], runtime_pass, apply=True)
                if not all((result["role"], result["user"],
                            result["collections"] == 3, result["indexes_ready"])):
                    raise AssertionError("Mongo provisioning incomplete")
                if result != operator.provision(root[operator.DB], apply=True):
                    raise AssertionError("idempotent reinspection differs")
                runtime = client(runtime_uri, p / "ca.pem")
                try:
                    assert_runtime_boundaries(runtime)
                finally:
                    runtime.close()
                print("DISPOSABLE_MONGO_TLS_RBAC_ALLOWED_DENIED_PASSED")
                env = {**os.environ,
                    "IDENTITY_PRODUCTION_TEST_RUNTIME_PASSWORD": runtime_pass,
                    "IDENTITY_PRODUCTION_TEST_CA_FILE": str(p / "ca.pem"),
                    "IDENTITY_PRODUCTION_MONGO_EXPECT_DRIFT": "0",
                }
                run("go", "test", "-race", "-count=1", "-v",
                    "./production", "-run", "^TestDisposableTLSMongoProductionRoleAndFailClosedDrift$",
                    cwd=ROOT / "services/identity", env=env, output=True)
                # Malicious operator drift: grant a second, broader role.
                # Real Go service must now refuse to start.
                root[operator.DB].command({"grantRolesToUser": operator.USER,
                    "roles": [{"role": "readWrite", "db": operator.DB}]})
                try:
                    operator.snapshot(root[operator.DB])
                except operator.Refused:
                    pass
                else:
                    raise AssertionError("operator failed to reject broadened runtime role")
                env["IDENTITY_PRODUCTION_MONGO_EXPECT_DRIFT"] = "1"
                run("go", "test", "-race", "-count=1", "-v",
                    "./production", "-run", "^TestDisposableTLSMongoProductionRoleAndFailClosedDrift$",
                    cwd=ROOT / "services/identity", env=env, output=True)
                print("DISPOSABLE_MONGO_ROLE_BROADENING_FAIL_CLOSED_PASSED")
            finally:
                root.close()
        finally:
            if started:
                subprocess.run(["docker", "rm", "-f", CONTAINER],
                               capture_output=True, timeout=40, check=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Deliberately never emit the driver exception: it might embed
        # synthetic credentials or server addresses.
        print("DISPOSABLE_MONGO_TLS_RBAC_TEST_FAILED (" + type(exc).__name__ + ")",
              file=sys.stderr)
        sys.exit(1)
