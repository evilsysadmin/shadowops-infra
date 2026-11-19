"""Offline least-privilege operator contract. Never connects to MongoDB."""
import importlib.util
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / "scripts/identity_production_mongo_operator.py"
spec = importlib.util.spec_from_file_location("identity_production_mongo_operator", FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Collection:
    def __init__(self):
        self.indexes = {"_id_": {"name": "_id_", "key": {"_id": 1}}}
        self.writes = 0
    def list_indexes(self):
        return list(self.indexes.values())
    def create_index(self, key, **opts):
        self.writes += 1
        self.indexes[opts["name"]] = {"name": opts["name"],
                                      "key": dict(key), **{k:v for k,v in opts.items() if k != "name"}}


class Mongo:
    def __init__(self):
        self.cols = {}
        self.role = None
        self.user = None
        self.calls = []
    def list_collection_names(self):
        return list(self.cols)
    def __getitem__(self, key):
        return self.cols[key]
    def create_collection(self, name):
        self.calls.append("collection:" + name)
        self.cols[name] = Collection()
    def command(self, arg):
        command = next(iter(arg))
        if command == "rolesInfo":
            return {"roles": [self.role] if self.role else []}
        if command == "usersInfo":
            return {"users": [self.user] if self.user else []}
        self.calls.append(command)
        if command == "createRole":
            self.role = {"db": m.DB, "role": m.ROLE, "roles": [], "privileges": arg["privileges"]}
        elif command == "createUser":
            self.user = {"db": m.DB, "user": m.USER, "roles": arg["roles"]}
        else:
            raise AssertionError("foreign Mongo command")
        return {"ok": 1}


class OperatorContracts(unittest.TestCase):
    def test_exact_production_collections_role_actions_and_ttl(self):
        self.assertEqual(set(m.INDEXES), set(m.COLLECTIONS))
        self.assertEqual(set(x["resource"]["collection"] for x in m.PRIVILEGES), set(m.COLLECTIONS))
        self.assertEqual([x["resource"]["db"] for x in m.PRIVILEGES], [m.DB]*3)
        self.assertEqual(m.USER_ROLES, [{"role": m.ROLE, "db": m.DB}])
        self.assertTrue(m.expected_grants(m.PRIVILEGES))
        self.assertFalse(m.expected_grants([m.PRIVILEGES[0]]))
        self.assertFalse(m.expected_grants([dict(m.PRIVILEGES[0], actions=["find","dropCollection"])]))
        self.assertEqual({idx["name"] for idx in m.INDEXES["sessions"]},
                         {"environment_digest_unique", "expires_at_ttl", "environment_subject_revoke"})
        self.assertEqual(m.INDEXES["production_application_tokens"][0]["expireAfterSeconds"], 0)

    def test_plan_and_inspect_do_not_mutate(self):
        db = Mongo()
        self.assertEqual(m.main(["plan"]), 0)
        self.assertEqual(m.provision(db), {"role": False, "user": False, "collections": 0, "indexes_ready": False})
        self.assertEqual(db.calls, [])

    def test_idempotent_provision_and_exact_index_contract(self):
        db = Mongo()
        result = m.provision(db, "correct horse battery staple synthetic 2026", apply=True)
        self.assertEqual(result, {"role": True, "user": True, "collections": 3, "indexes_ready": True})
        self.assertEqual(db.calls, ["collection:native_accounts", "collection:sessions",
                                    "collection:production_application_tokens", "createRole", "createUser"])
        self.assertEqual(sum(v.writes for v in db.cols.values()), 5)
        m.provision(db, apply=True)
        self.assertEqual(len(db.calls), 5)
        self.assertEqual(sum(v.writes for v in db.cols.values()), 5)

    def test_preflight_refuses_role_user_index_and_foreign_namespace_drift_without_writes(self):
        for poison in ("role", "user", "index", "namespace"):
            with self.subTest(poison=poison):
                db = Mongo()
                m.provision(db, "correct horse battery staple synthetic 2026", apply=True)
                if poison == "role":
                    db.role["privileges"][0]["actions"].append("dropDatabase")
                if poison == "user":
                    db.user["roles"].append({"role": "readWrite", "db": "admin"})
                if poison == "index":
                    db.cols["sessions"].indexes["expires_at_ttl"]["expireAfterSeconds"] = 60
                if poison == "namespace":
                    db.cols["shadowops_identity_staging"] = Collection()
                before = list(db.calls)
                with self.assertRaises(m.Refused):
                    m.provision(db, apply=True)
                self.assertEqual(db.calls, before)

    def test_apply_requires_strong_password_before_writes(self):
        for candidate in ("bad", "", "password\\nwith\\nnewline" * 3, None):
            with self.subTest(candidate=candidate):
                db = Mongo()
                with self.assertRaises(m.Refused):
                    m.provision(db, candidate, apply=True)
                self.assertEqual(db.calls, [])

    def test_admin_connection_must_be_tls_authenticated_pinned_and_not_staging(self):
        good = "mongodb://operator:private@prod-mongo.example.org/admin?tls=true&authSource=admin&replicaSet=identity-prod-rs"
        m.validate_connection(good, "identity-prod-rs")
        for bad in (good.replace("tls=true", "tls=false"),
                    good.replace("/admin?", "/shadowops_identity_staging?"),
                    good.replace("replicaSet=identity-prod-rs", "replicaSet=staging"),
                    good.replace("prod-mongo", "staging-mongo"),
                    good.replace("operator:private@", ""),
                    good + "&tlsInsecure=true"):
            with self.subTest(bad=bad.replace("private", "redacted")):
                with self.assertRaises(m.Refused):
                    m.validate_connection(bad, "identity-prod-rs")
        with self.assertRaises(m.Refused):
            m.validate_connection(good, "")

    def test_apply_refuses_ci_noninteractive_and_missing_explicit_gate(self):
        with patch.dict(os.environ, {"IDENTITY_PRODUCTION_MONGO_APPLY": m.ACK, "CI": "true"}):
            self.assertEqual(m.main(["apply"]), 1)
        with patch.dict(os.environ, {"IDENTITY_PRODUCTION_MONGO_APPLY": ""}):
            self.assertEqual(m.main(["apply"]), 1)
        self.assertEqual(m.main([]), 2)

    def test_private_file_is_local_owner_only_no_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "operator.uri"
            path.write_text("not-a-credential")
            path.chmod(0o600)
            self.assertEqual(m.private_file(str(path), secret=True), b"not-a-credential")
            path.chmod(0o644)
            with self.assertRaises(m.Refused):
                m.private_file(str(path), secret=True)
            path.chmod(0o600)
            link = Path(temp) / "alias"
            link.symlink_to(path)
            with self.assertRaises(m.Refused):
                m.private_file(str(link), secret=True)


if __name__ == "__main__":
    unittest.main()
