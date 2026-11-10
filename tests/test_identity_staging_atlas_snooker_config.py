"""No-host Snooker Atlas candidate staging and old-image rollback isolation tests."""
from contextlib import nullcontext
import copy
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
from identity_staging_atlas_snooker_config import candidate_config, SnookerConfigBlocked

spec = spec_from_file_location("snooker_stage_root", ROOT / "host/identity-atlas-staging-snooker-config.py")
host = module_from_spec(spec)
spec.loader.exec_module(host)

CH = "soc1_" + "c" * 43
SN = "soc1_" + "s" * 43
ATLAS_APP = "mongodb+srv://app:synthetic-password-123@cluster.mongodb.net/shadowops_identity_staging?tls=true&authSource=admin"
ATLAS_INV = "mongodb+srv://inventory:synthetic-password-234@cluster.mongodb.net/shadowops_identity_staging?tls=true&authSource=admin"
VAULT = "ocid1.vault.oc1." + "v" * 20


def fixture():
    local = {
        "environment": "staging",
        "mongo_uri": "mongodb://identity_runtime@identity-mongo:27017",
        "admin_inventory_mongo_uri": "mongodb://identity_inventory@identity-mongo:27017",
        "mongo_ca_pem": "private-test-ca",
        "signing_seed": "private-synthetic-signing-seed",
        "tls_certificate_pem": "private-synthetic-certificate",
        "tls_private_key_pem": "private-synthetic-key",
        "admin_inventory_access_history": True,
        "consumers": {"chronicles": CH},
    }
    atlas = copy.deepcopy(local)
    atlas.update({"mongo_uri": ATLAS_APP, "admin_inventory_mongo_uri": ATLAS_INV,
                  "mongo_ca_pem": "", "mongo_privilege_mode": "database-scoped"})
    vault_service = copy.deepcopy(local)
    vault_service["consumers"]["snooker"] = SN
    return local, atlas, vault_service


class CandidateDerivationTests(unittest.TestCase):
    def test_only_snooker_credential_is_new_and_originals_are_unchanged(self):
        local, atlas, vault = fixture()
        before = copy.deepcopy((local, atlas, vault))
        result = candidate_config(local, atlas, vault)
        self.assertEqual((local, atlas, vault), before)
        self.assertEqual(set(result), set(atlas))
        self.assertEqual(result["consumers"], {"chronicles": CH, "snooker": SN})
        self.assertEqual({k: v for k, v in result.items() if k != "consumers"},
                         {k: v for k, v in atlas.items() if k != "consumers"})
        self.assertNotEqual(id(result["consumers"]), id(atlas["consumers"]))

    def test_other_vault_secret_rotation_and_unexpected_consumer_are_blocked(self):
        for update in (
            {"signing_seed": "not-original"},
            {"tls_private_key_pem": "not-original"},
            {"consumers": {"chronicles": "soc1_" + "d" * 43, "snooker": SN}},
            {"consumers": {"chronicles": CH, "snooker": SN, "football": "soc1_" + "f" * 43}},
        ):
            with self.subTest(update=update):
                local, atlas, vault = fixture()
                vault.update(update)
                with self.assertRaises(SnookerConfigBlocked):
                    candidate_config(local, atlas, vault)
        local, atlas, vault = fixture()
        del vault["consumers"]["snooker"]
        with self.assertRaises(SnookerConfigBlocked):
            candidate_config(local, atlas, vault)

    def test_modified_atlas_uri_previous_credential_and_scope_are_rejected(self):
        for field, value in (
            ("signing_seed", "wrong"),
            ("consumers", {"chronicles": "soc1_" + "d" * 43}),
            ("mongo_privilege_mode", "admin"),
            ("mongo_ca_pem", "untrusted-ca"),
        ):
            with self.subTest(field=field):
                local, atlas, vault = fixture()
                atlas[field] = value
                with self.assertRaises(SnookerConfigBlocked):
                    candidate_config(local, atlas, vault)

    def test_no_mutation_on_error(self):
        local, atlas, vault = fixture()
        atlas["consumers"]["snooker"] = SN
        before = copy.deepcopy((local, atlas, vault))
        with self.assertRaises(SnookerConfigBlocked):
            candidate_config(local, atlas, vault)
        self.assertEqual((local, atlas, vault), before)


class RootStageTests(unittest.TestCase):
    def run_stage(self, *, missing=False, preexisting=None):
        local, atlas, desired = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            state.mkdir()
            source = root / "service.json"
            old = root / "atlas-service.json"
            candidate = root / "atlas-snooker-service.json"
            for path, data in ((source, local), (old, atlas)):
                path.write_text(json.dumps(data))
                path.chmod(0o400)
            if preexisting is not None:
                candidate.write_text(json.dumps(preexisting))
                candidate.chmod(0o400)
            old_bytes, source_bytes = old.read_bytes(), source.read_bytes()

            def read_private(path, uid):
                return json.loads(path.read_text())
            prepare = SimpleNamespace(trusted_dir=lambda _: None, load_private=read_private)
            release = SimpleNamespace(root_file=lambda *args, **kwargs: None,
                live_image=lambda run: ("sha256:" + "a" * 64, host.PREVIOUS_SOURCE),
                public_release_sha=lambda run: host.PREVIOUS_SOURCE, run=lambda *args: None)
            vault = {"consumers": {"chronicles": CH}}
            if not missing:
                vault["consumers"]["snooker"] = SN
            local_reader = SimpleNamespace(read_bundle=lambda _: vault)
            def load(name, path):
                if name.startswith("atlas_prepare"): return prepare
                if name.startswith("atlas_release"): return release
                if name.startswith("local_identity"): return local_reader
                raise AssertionError("unexpected operator")
            before_fchown = os.fchown
            def test_chown(fd, uid, gid):
                return before_fchown(fd, os.getuid(), os.getgid())
            with patch.object(host, "ROOT", root), patch.object(host, "STATE", state), patch.object(
                host, "CANDIDATE", candidate), patch.object(host, "atlas_lock", return_value=nullcontext()), patch.object(
                host, "service_config", return_value=desired), patch.object(host.os, "fchown",
                side_effect=test_chown):
                if missing:
                    with self.assertRaises(host.MissingVaultConsumer):
                        host.stage(VAULT, load=load, verify_host=lambda: None)
                    self.assertFalse(candidate.exists())
                    result = None
                elif preexisting is not None and preexisting != candidate_config(local, atlas, desired):
                    with self.assertRaises(host.StageBlocked):
                        host.stage(VAULT, load=load, verify_host=lambda: None)
                    result = None
                else:
                    result = host.stage(VAULT, load=load, verify_host=lambda: None)
                    self.assertIn("previous_config=unchanged", result)
                    self.assertIn("deploy=not-attempted", result)
                    self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o400)
                    self.assertEqual(json.loads(candidate.read_text()),
                                     candidate_config(local, atlas, desired))
                    if preexisting is None:
                        result2 = host.stage(VAULT, load=load, verify_host=lambda: None)
                        self.assertIn("result=already-matching", result2)
            self.assertEqual(old.read_bytes(), old_bytes)
            self.assertEqual(source.read_bytes(), source_bytes)
            return result

    def test_only_separate_candidate_is_created(self):
        self.assertIn("result=created", self.run_stage())

    def test_already_matching_candidate_is_accepted_without_overwrite(self):
        self.run_stage(preexisting=candidate_config(*fixture()))

    def test_mismatched_candidate_is_denied_and_legacy_intact(self):
        wrong = candidate_config(*fixture())
        wrong["signing_seed"] = "untrusted"
        self.run_stage(preexisting=wrong)

    def test_unprovisioned_vault_consumer_writes_nothing(self):
        self.run_stage(missing=True)

    def test_workflow_requires_manual_protected_environment_and_no_deploy(self):
        w = (ROOT / ".github/workflows/identity-staging-operations.yml").read_text()
        self.assertIn("atlas-snooker-config", w)
        self.assertIn("inputs.action == 'atlas-snooker-config'", w)
        self.assertIn("run: python scripts/identity_staging_release.py atlas-snooker-config", w)
        self.assertIn("environment: staging", w)
        installer = (ROOT / "host/install-identity-staging.sh").read_text()
        sudo = (ROOT / "host/identity-staging.sudoers").read_text()
        self.assertIn("shadowops-identity-atlas-snooker-config", installer)
        self.assertIn("identity_staging_atlas_snooker_config", installer)
        self.assertIn("/usr/local/sbin/shadowops-identity-atlas-snooker-config stage *", sudo)
        old = (ROOT / "compose.identity.atlas.staging.yaml").read_text()
        self.assertIn("/etc/shadowops/identity-staging/atlas-service.json", old)
        self.assertNotIn("atlas-snooker-service.json", old)


class ProtectedHandoffTests(unittest.TestCase):
    def test_only_exact_candidate_stage_receipt_is_accepted(self):
        import test_identity_staging_atlas_release_handoff as base
        import identity_staging_release as release
        receipt = ("IDENTITY_ATLAS_SNOOKER_CONFIG_STAGED result=created "
                   "previous_config=unchanged local_source=unchanged deploy=not-attempted")
        for output, accepted in (
            (receipt, True),
            (receipt + "\nsecret=PRIVATE", False),
            ("PRIVATE_UNTRUSTED", False),
            ("", False),
        ):
            sdk, observed = base.sdk_with_result(output=output)
            with patch.object(release, "inspect"), patch.object(
                release, "resolve_existing_host", return_value=("compartment", "host")
            ), patch.object(release, "resolve_vault", return_value=(VAULT, None, None)):
                if accepted:
                    self.assertIn("activation=not-attempted",
                                  release.execute_atlas_snooker_config(sdk, {}))
                else:
                    with self.assertRaises(release.ReleaseError) as caught:
                        release.execute_atlas_snooker_config(sdk, {})
                    self.assertNotIn("PRIVATE", str(caught.exception))
            self.assertEqual(len(observed), 1)
            command = observed[0].content.source.text
            self.assertIn("shadowops-identity-atlas-snooker-config stage " + VAULT, command)
            self.assertNotIn("docker", command)
            self.assertNotIn("deploy", command)


if __name__ == "__main__":
    unittest.main()
