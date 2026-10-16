"""Unit tests for the offline OCI host preflight (no secret values logged)."""
from __future__ import annotations

import stat
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent))
from staging_host_preflight import PreflightError, verify_staging_environment

DIGEST = "sha256:" + "a" * 64
MONGO = "/run/local/chronicles-mongo.secret"
JWT = "/run/local/chronicles-jwt.secret"

ENV = {
    "CHRONICLES_IMAGE_DIGEST": DIGEST,
    "CHRONICLES_MONGODB_DATABASE": "chronicles_staging",
    "CHRONICLES_MONGO_SECRET_FILE": MONGO,
    "CHRONICLES_STAGING_JWT_SECRET_FILE": JWT,
}
FILES = {
    MONGO: b"mongodb://127.0.0.1:27017",
    JWT: b"staging-only-secret-with-at-least-32-bytes",
}


def loader(
    *,
    mode=0o400,
    owner=65532,
    group=65532,
    mongo=FILES[MONGO],
    jwt=FILES[JWT],
    same_inode=False,
):
    def load(path):
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | mode, st_uid=owner, st_gid=group,
            st_dev=1, st_ino=10 if same_inode or path == MONGO else 11,
        )
        return metadata, mongo if path == MONGO else jwt
    return load


class StagingPreflightTest(unittest.TestCase):
    def test_accepts_sha_digest_and_container_readable_private_secrets(self):
        self.assertEqual(verify_staging_environment(ENV, loader()), DIGEST)
        self.assertEqual(
            verify_staging_environment(ENV, loader(mode=0o440, owner=0, group=65532)),
            DIGEST,
        )

    def test_rejects_invalid_digest_database_or_deployment_environment(self):
        for changed in (
            {"CHRONICLES_IMAGE_DIGEST": "staging-latest"},
            {"CHRONICLES_IMAGE_DIGEST": "sha256:short"},
            {"CHRONICLES_MONGODB_DATABASE": "chess_studio_prod"},
            {"CHRONICLES_MONGODB_DATABASE": "chess_study_staging"},
            {"CHRONICLES_MONGODB_DATABASE": "other_staging"},
            {"CHRONICLES_MONGODB_DATABASE": "bad.name_staging"},
            {"CHRONICLES_ENABLE_READ_API": "false"},
            {"CHRONICLES_ENVIRONMENT": "production"},
            {"CHRONICLES_MONGO_SECRET_FILE": "relative-secret"},
            {"CHRONICLES_STAGING_JWT_SECRET_FILE": ""},
        ):
            with self.subTest(changed=changed), self.assertRaises(PreflightError):
                verify_staging_environment({**ENV, **changed}, loader())

    def test_rejects_public_wrong_owner_or_unreadable_secret_files(self):
        for kwargs in (
            {"mode": 0o404},
            {"mode": 0o644},
            {"mode": 0o400, "owner": 0, "group": 0},
            {"mode": 0o440, "owner": 0, "group": 0},
            {"mode": 0o000},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(PreflightError):
                verify_staging_environment(ENV, loader(**kwargs))

    def test_rejects_symlinks_and_directories(self):
        for file_type in (stat.S_IFLNK, stat.S_IFDIR):
            def forged(path, file_type=file_type):
                metadata, data = loader()(path)
                return SimpleNamespace(**{
                    **vars(metadata), "st_mode": file_type | 0o400
                }), data
            with self.subTest(file_type=file_type), self.assertRaises(PreflightError):
                verify_staging_environment(ENV, forged)

    def test_rejects_reused_or_corrupt_credentials(self):
        for kwargs in (
            {"same_inode": True},
            {"mongo": b"postgres://bad-server"},
            {"mongo": b"mongodb://valid\nsecret-leak"},
            {"mongo": b"mongodb://x\x00malformed"},
            {"jwt": b"too-short"},
            {"jwt": b"x" * 4097},
            {"jwt": b"staging-secret" + b"\x00" + b"x" * 32},
        ):
            with self.subTest(kwargs=list(kwargs)), self.assertRaises(PreflightError):
                verify_staging_environment(ENV, loader(**kwargs))

    def test_rejects_unreadable_or_missing_files(self):
        def error_loader(_path):
            raise FileNotFoundError("should not leak this path")
        with self.assertRaisesRegex(PreflightError, "cannot be inspected"):
            verify_staging_environment(ENV, error_loader)


if __name__ == "__main__":
    unittest.main()
