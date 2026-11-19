#!/usr/bin/env python3
"""Operator-only, fail-closed Mongo bootstrap for isolated ShadowOps Identity.

No CI deployment, no secret generation, no staging access, no role broadening.
The separate admin URI comes from a private local file; the new runtime user's
password is prompted on a TTY and is never passed in argv, env or logged.
"""
from __future__ import annotations

import getpass
import hmac
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import parse_qs, urlsplit

DB = "shadowops_identity_production"
ROLE = "shadowops_identity_production_runtime"
USER = "identity_prod_runtime"
COLLECTIONS = ("native_accounts", "sessions", "production_application_tokens")
READ_WRITE_INDEX = ("find", "insert", "update", "createIndex", "listIndexes")
PRIVILEGES = [
    {"resource": {"db": DB, "collection": name},
     "actions": list(READ_WRITE_INDEX) + (["remove"] if name == "sessions" else [])}
    for name in COLLECTIONS
]
USER_ROLES = [{"role": ROLE, "db": DB}]
INDEXES = {
    "native_accounts": [
        {"name": "production_native_alias_unique",
         "key": [("environment", 1), ("source", 1), ("alias_key", 1)], "unique": True},
    ],
    "sessions": [
        {"name": "environment_digest_unique",
         "key": [("environment", 1), ("digest", 1)], "unique": True},
        {"name": "expires_at_ttl", "key": [("expires_at", 1)], "expireAfterSeconds": 0},
        {"name": "environment_subject_revoke",
         "key": [("environment", 1), ("subject", 1)]},
    ],
    "production_application_tokens": [
        {"name": "production_application_token_ttl",
         "key": [("expires_at", 1)], "expireAfterSeconds": 0},
    ],
}
ACK = "PROVISION_EXACT_PRODUCTION_IDENTITY_DB"


class Refused(ValueError):
    pass


def private_file(path: str, *, secret: bool) -> bytes:
    if not path or not Path(path).is_absolute():
        raise Refused("absolute operator-owned path required")
    target = Path(path)
    try:
        for part in (target, *target.parents):
            if stat.S_ISLNK(os.lstat(part).st_mode):
                raise Refused("symlink in private path")
        info = os.lstat(target)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > 131072:
            raise Refused("invalid private input")
        if secret and (info.st_uid != os.geteuid() or
                       stat.S_IMODE(info.st_mode) not in (0o400, 0o600)):
            raise Refused("secret file must be 0400/0600 and operator-owned")
        return target.read_bytes()
    except OSError as exc:
        raise Refused("operator input missing") from exc


def validate_connection(uri: str, expected_set: str) -> None:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,63}", expected_set):
        raise Refused("expected replica set not pinned")
    try:
        value = urlsplit(uri)
        query = parse_qs(value.query, strict_parsing=True)
        allowed = {"tls", "authSource", "replicaSet"}
        if (value.scheme not in ("mongodb", "mongodb+srv") or
                not value.hostname or not value.username or not value.password or
                value.path != "/admin" or value.fragment or set(query) != allowed or
                query.get("tls") != ["true"] or query.get("authSource") != ["admin"] or
                query.get("replicaSet") != [expected_set]):
            raise Refused("unexpected admin connection contract")
        if any(s in (value.hostname or "").lower() for s in ("staging", "test")):
            raise Refused("production operator cannot point to staging host")
    except (ValueError, UnicodeError) as exc:
        raise Refused("invalid admin connection") from exc


def expected_grants(privileges) -> bool:
    def normalized(records):
        result = {}
        for item in records:
            resource = item.get("resource", {})
            if (set(resource) != {"db", "collection"} or
                    resource.get("db") != DB or
                    resource.get("collection") not in COLLECTIONS or
                    not isinstance(item.get("actions"), list)):
                raise Refused("foreign resource or Mongo action")
            name = resource["collection"]
            if name in result:
                raise Refused("duplicate resource privileges")
            result[name] = frozenset(item["actions"])
            if len(result[name]) != len(item["actions"]):
                raise Refused("duplicate Mongo actions")
        return result
    return normalized(privileges) == normalized(PRIVILEGES)


def role_and_user(db):
    role_data = db.command({"rolesInfo": {"role": ROLE, "db": DB},
                            "showPrivileges": True}).get("roles", [])
    user_data = db.command({"usersInfo": {"user": USER, "db": DB}}).get("users", [])
    if len(role_data) > 1 or len(user_data) > 1:
        raise Refused("ambiguous Mongo principal")
    role = role_data[0] if role_data else None
    user = user_data[0] if user_data else None
    if role and (role.get("role") != ROLE or role.get("db") != DB or
                 role.get("roles") != [] or
                 not expected_grants(role.get("privileges", []))):
        raise Refused("existing role has privilege drift")
    if user and (user.get("user") != USER or user.get("db") != DB or
                 user.get("roles") != USER_ROLES):
        raise Refused("existing user has role drift")
    return role is not None, user is not None


def index_state(db):
    names = set(db.list_collection_names())
    # A foreign collection in the production Identity namespace is not
    # silently adopted or dropped. Never touch any other database.
    if any(name not in COLLECTIONS and not name.startswith("system.") for name in names):
        raise Refused("unexpected production collection")
    missing = []
    for name in COLLECTIONS:
        if name not in names:
            missing.extend((name, idx) for idx in INDEXES[name])
            continue
        present = {idx["name"]: idx for idx in db[name].list_indexes()}
        allowed = {"_id_"} | {idx["name"] for idx in INDEXES[name]}
        if set(present) - allowed:
            raise Refused("unexpected production index")
        for index in INDEXES[name]:
            found = present.get(index["name"])
            if found is None:
                missing.append((name, index))
                continue
            if (list(found.get("key", {}).items()) != index["key"] or
                    bool(found.get("unique", False)) != index.get("unique", False) or
                    found.get("expireAfterSeconds") != index.get("expireAfterSeconds")):
                raise Refused("existing index has incompatible definition")
    return names, missing


def snapshot(db):
    role, user = role_and_user(db)
    names, missing = index_state(db)
    return role, user, names, missing


def provision(db, password: str | None = None, *, apply: bool = False):
    role, user, names, missing = snapshot(db)  # preflight before first write
    if not apply:
        return {"role": role, "user": user, "collections": len(set(COLLECTIONS) & names),
                "indexes_ready": not missing}
    if not user and (not isinstance(password, str) or
                     len(password) < 24 or len(password) > 256 or
                     any(c in password for c in ("\x00", "\n", "\r"))):
        raise Refused("new runtime credential must be high entropy and 24+ chars")
    for name in COLLECTIONS:
        if name not in names:
            db.create_collection(name)
    for name, index in missing:
        kwargs = {"name": index["name"]}
        if "unique" in index:
            kwargs["unique"] = True
        if "expireAfterSeconds" in index:
            kwargs["expireAfterSeconds"] = 0
        db[name].create_index(index["key"], **kwargs)
    if not role:
        db.command({"createRole": ROLE, "privileges": PRIVILEGES, "roles": []})
    if not user:
        db.command({"createUser": USER, "pwd": password, "roles": USER_ROLES})
    result = provision(db)
    if not result["role"] or not result["user"] or result["collections"] != 3 or not result["indexes_ready"]:
        raise Refused("post-provisioning audit failed")
    return result


def operator_client():
    uri_bytes = private_file(os.environ.get("IDENTITY_PRODUCTION_MONGO_ADMIN_URI_FILE", ""), secret=True)
    if len(uri_bytes) > 8192 or b"\n" in uri_bytes or b"\r" in uri_bytes:
        raise Refused("invalid private Mongo URI file")
    try:
        uri = uri_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise Refused("invalid URI encoding") from exc
    expected_set = os.environ.get("IDENTITY_PRODUCTION_MONGO_REPLICA_SET", "")
    validate_connection(uri, expected_set)
    ca_file = os.environ.get("IDENTITY_PRODUCTION_MONGO_CA_FILE", "")
    private_file(ca_file, secret=False)
    # Runtime imports are intentionally absent from plan / offline CI.
    from pymongo import MongoClient
    client = MongoClient(uri, tls=True, tlsCAFile=ca_file,
                         serverSelectionTimeoutMS=5000, retryWrites=False)
    try:
        hello = client.admin.command({"hello": 1})
        auth = client.admin.command({"connectionStatus": 1}).get("authInfo", {})
        if (hello.get("setName") != expected_set or
                hello.get("isWritablePrimary") is not True or
                len(auth.get("authenticatedUsers", [])) != 1 or
                not any(x.get("db") == "admin" for x in auth["authenticatedUsers"]) or
                any(x.get("role") == ROLE for x in auth.get("authenticatedUserRoles", []))):
            raise Refused("authenticated production operator replica not proven")
        return client
    except Exception:
        client.close()
        raise


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in ("plan", "inspect", "apply"):
        print("Usage: identity_production_mongo_operator.py plan|inspect|apply", file=sys.stderr)
        return 2
    if argv[0] == "plan":
        print("PRODUCTION_MONGO_PLAN db=" + DB +
              " collections=3 runtime_role=" + ROLE +
              " runtime_user=" + USER + " apply=manual-only")
        return 0
    if (argv[0] == "apply" and
            (os.environ.get("IDENTITY_PRODUCTION_MONGO_APPLY") != ACK or
             os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS") or
             not sys.stdin.isatty())):
        print("PRODUCTION_MONGO_REFUSED", file=sys.stderr)
        return 1
    try:
        client = operator_client()
        try:
            db = client[DB]
            if argv[0] == "inspect":
                result = provision(db)
            else:
                _, user, _, _ = snapshot(db)
                password = None
                if not user:
                    password = getpass.getpass("New isolated production Mongo runtime password: ")
                    confirm = getpass.getpass("Confirm new password: ")
                    if not hmac.compare_digest(password, confirm):
                        raise Refused("runtime password confirmation differs")
                result = provision(db, password, apply=True)
        finally:
            client.close()
        print("PRODUCTION_MONGO_" + ("APPLIED" if argv[0] == "apply" else "INSPECT") +
              " role=" + ("ready" if result["role"] else "missing") +
              " user=" + ("ready" if result["user"] else "missing") +
              " collections=" + str(result["collections"]) +
              " indexes=" + ("ready" if result["indexes_ready"] else "missing"))
        if argv[0] == "inspect" and not all((result["role"], result["user"],
                                             result["collections"] == 3, result["indexes_ready"])):
            return 1
        return 0
    except Exception:
        # Never render MongoClient errors: some drivers include sensitive URIs.
        print("PRODUCTION_MONGO_REFUSED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
