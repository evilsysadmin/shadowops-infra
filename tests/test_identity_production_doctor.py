"""The production doctor must diagnose absence WITHOUT exposing secrets."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("production_doctor", ROOT / "scripts/identity_production_doctor.py")
doctor = module_from_spec(spec)
spec.loader.exec_module(doctor)


class IdentityProductionDoctorTests(TestCase):
    def test_empty_l14_context_reports_missing_without_probing(self):
        lines = doctor.audit({}, uid=1000, tty=True, has_docker=False,
                             has_pymongo=False, has_yaml=False)
        output = "\n".join(lines)
        self.assertIn("scope=local read_only=yes secrets=not-opened network=not-probed", output)
        self.assertIn("phase=mongo mongo_admin_uri_file=missing", output)
        self.assertIn("phase=origin image_digest=missing source_sha=missing", output)
        self.assertIn("phase=tunnel tunnel_digest=missing", output)
        self.assertIn("root=no tty=yes ci=no docker_cli=no pymongo=no pyyaml=no", output)
        self.assertIn("run_on=authorized-production-host", output)

    def test_present_paths_are_not_opened_or_printed(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "secret-identity-production-hidden.json"
            path.write_text("NEVER_PRINT_THIS_PASSWORD")
            env = {
                "IDENTITY_PRODUCTION_MONGO_ADMIN_URI_FILE": str(path),
                "IDENTITY_PRODUCTION_MONGO_CA_FILE": str(path),
                "IDENTITY_PRODUCTION_MONGO_REPLICA_SET": "rs-prod-do-not-disclose",
                "IDENTITY_PRODUCTION_IMAGE_DIGEST": "sha256:" + "a" * 64,
                "IDENTITY_PRODUCTION_SOURCE_SHA": "b" * 40,
                "IDENTITY_PRODUCTION_BUNDLE_FILE": str(path),
                "IDENTITY_PRODUCTION_ORIGIN_CA_FILE": str(path),
                "IDENTITY_PRODUCTION_TUNNEL_DIGEST": "sha256:" + "c" * 64,
                "IDENTITY_PRODUCTION_TUNNEL_CONFIG_FILE": str(path),
                "IDENTITY_PRODUCTION_TUNNEL_CREDENTIALS_FILE": str(path),
                "IDENTITY_PRODUCTION_TUNNEL_ORIGIN_CA_FILE": str(path),
                "CLOUDFLARE_API_TOKEN": "SUPER_SECRET_SHOULD_NOT_PRINT",
            }
            with patch.object(Path, "read_bytes", side_effect=AssertionError("secret read")):
                lines = doctor.audit(env, uid=0, tty=True, has_docker=True,
                                     has_pymongo=True, has_yaml=True)
            output = "\n".join(lines)
            self.assertIn("mongo_admin_uri_file=present", output)
            self.assertIn("image_digest=set", output)
            self.assertIn("origin_ca_file=present", output)
            self.assertIn("tunnel_credentials_file=present", output)
            self.assertIn("root=yes tty=yes ci=no docker_cli=yes", output)
            for secret in (str(path), "NEVER_PRINT_THIS_PASSWORD", "rs-prod-do-not-disclose",
                           "SUPER_SECRET_SHOULD_NOT_PRINT", "a" * 64, "b" * 40, "c" * 64):
                self.assertNotIn(secret, output)

    def test_reject_bad_sha_digest_relative_and_symlink_without_opening(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.write_text("not a secret")
            symlink = Path(tmp) / "alias"
            symlink.symlink_to(target)
            env = {
                "IDENTITY_PRODUCTION_IMAGE_DIGEST": "sha256:INVALID",
                "IDENTITY_PRODUCTION_SOURCE_SHA": "f" * 39,
                "IDENTITY_PRODUCTION_BUNDLE_FILE": "relative/path",
                "IDENTITY_PRODUCTION_ORIGIN_CA_FILE": str(symlink),
                "IDENTITY_PRODUCTION_TUNNEL_CONFIG_FILE": str(Path(tmp) / "absent"),
                "CI": "true",
            }
            output = "\n".join(doctor.audit(env, uid=1000, tty=False,
                                             has_docker=False, has_pymongo=False,
                                             has_yaml=False))
            self.assertIn("image_digest=invalid", output)
            self.assertIn("source_sha=invalid", output)
            self.assertIn("bundle_file=invalid", output)
            self.assertIn("origin_ca_file=invalid", output)
            self.assertIn("tunnel_config_file=unavailable", output)
            self.assertIn("ci=yes", output)

    def test_no_actions_from_diagnostic(self):
        with patch.object(doctor, "audit", return_value=["SAFE_PROBE"]), \
             patch("builtins.print") as display:
            self.assertEqual(doctor.main([]), 0)
            display.assert_called_once_with("SAFE_PROBE")
        self.assertEqual(doctor.main(["apply"]), 2)
