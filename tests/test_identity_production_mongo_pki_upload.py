"""Offline negative tests for L14 -> Cloudflare A1 exact-three-file transfer."""
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pki_upload", ROOT / "scripts/identity_production_mongo_pki_upload.py")
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.package = self.home / "pki"
        self.package.mkdir(mode=0o700)
        (self.package / u.TRANSFER).mkdir(mode=0o700)
        (self.package / u.OFFLINE).mkdir(mode=0o700)
        key = self.package / u.OFFLINE / "ca-private.key"
        key.write_bytes(b"fictional-key")
        key.chmod(0o600)
        for name in u.NAMES:
            path = self.package / u.TRANSFER / name
            path.write_bytes(b"fictional-fixture-" + name.encode())
            path.chmod(0o600)
        self.env = {"MONGO_PKI_OUTPUT_DIR": str(self.package)}

    def test_exact_private_bundle_only_no_ca_private_in_sources(self):
        files = u.local_package(self.env, uid=os.geteuid(), home=self.home)
        self.assertEqual(tuple(f.name for f in files), u.NAMES)
        self.assertFalse(any("ca-private.key" in str(p) for p in files))
        (self.package / u.TRANSFER / "ca-private.key").write_text("forbidden")
        with self.assertRaises(u.Refused):
            u.local_package(self.env, uid=os.geteuid(), home=self.home)

    def test_reject_symlink_hardlink_wrong_permissions_and_extra_ca_key(self):
        leaf = self.package / u.TRANSFER / "mongo.pem"
        leaf.chmod(0o644)
        with self.assertRaises(u.Refused):
            u.local_package(self.env, uid=os.geteuid(), home=self.home)
        leaf.chmod(0o600)
        linked = self.home / "linked"
        os.link(leaf, linked)
        with self.assertRaises(u.Refused):
            u.local_package(self.env, uid=os.geteuid(), home=self.home)
        linked.unlink()
        leaf.unlink()
        leaf.symlink_to(self.home / "nonexistent")
        with self.assertRaises(u.Refused):
            u.local_package(self.env, uid=os.geteuid(), home=self.home)
        leaf.unlink()
        leaf.write_text("test")
        leaf.chmod(0o600)
        (self.package / u.OFFLINE / "another-private.key").write_text("forbidden")
        with self.assertRaises(u.Refused):
            u.local_package(self.env, uid=os.geteuid(), home=self.home)

    def test_reject_external_dir_relative_and_ci(self):
        with self.assertRaises(u.Refused):
            u.local_package({"MONGO_PKI_OUTPUT_DIR": "relative"}, home=self.home)
        with self.assertRaises(u.Refused):
            u.local_package({}, home=self.home)
        with self.assertRaises(u.Refused):
            u.local_package({"MONGO_PKI_OUTPUT_DIR": "/tmp/other"},
                            home=self.home)
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(u.main(["upload"], env={"CI": "true"}), 1)
        self.assertIn("UPLOAD_REFUSED", err.getvalue())

    def test_cloudflare_rsync_command_no_recursive_ca_key_or_remote_command(self):
        files = u.local_package(self.env, home=self.home)
        argv = u.rsync_args(
            "/usr/bin/rsync", "/usr/bin/ssh", "/usr/bin/cloudflared",
            u.a1.SSH_HOST, u.a1.SSH_USER, "/home/operator/id", files,
        )
        self.assertEqual(argv[0], "/usr/bin/rsync")
        for required in ("--ignore-existing", "--chmod=F600", "--no-links",
                         "--no-owner", "--no-group", "--no-specials", "--quiet"):
            self.assertIn(required, argv)
        self.assertIn("ProxyCommand=", argv[argv.index("-e")+1])
        self.assertIn("StrictHostKeyChecking=ask", argv[argv.index("-e")+1])
        self.assertIn("/home/operator/id", argv[argv.index("-e")+1])
        self.assertEqual(argv[-1], "ubuntu@" + u.a1.SSH_HOST + ":" + u.DEST)
        self.assertEqual(tuple(Path(x).name for x in argv[-4:-1]), u.NAMES)
        for dangerous in ("ca-private.key", "--delete", "--remove-source-files",
                          "sudo ", "docker ", "chmod 777", "rm -rf"):
            self.assertNotIn(dangerous, " ".join(argv))
        with self.assertRaises(u.Refused):
            u.rsync_args("rsync", "ssh", "cloudflared", u.a1.SSH_HOST,
                         "ubuntu", "", files[:2])

    def test_root_ci_non_tty_and_operator_ack_rejected(self):
        tty = SimpleNamespace(isatty=lambda: True)
        notty = SimpleNamespace(isatty=lambda: False)
        good = dict(euid=1001, stdin=tty, stdout=tty, prompt=lambda _: u.ACK)
        for changes in ({"euid": 0}, {"stdin": notty}, {"stdout": notty},
                        {"prompt": lambda _: "NO"}):
            with self.subTest(changes=list(changes)), self.assertRaises(u.Refused):
                u.require_workstation({}, **(good | changes))
        for env in ({"CI": "1"}, {"GITHUB_ACTIONS": "true"}):
            with self.assertRaises(u.Refused):
                u.require_workstation(env, **good)

    def test_check_only_edge_and_not_remote(self):
        with mock.patch.object(u, "local_package",
                               return_value=list(Path("/dummy") / x for x in u.NAMES)), \
             mock.patch.object(u, "check_crypto"), \
             mock.patch.object(u.a1, "operator_settings",
                               return_value=(u.a1.SSH_HOST, "ubuntu", "")), \
             mock.patch.object(u.shutil, "which",
                               side_effect=lambda name: "/usr/bin/" + name), \
             mock.patch.object(u.a1, "check_edge_tls") as edge, \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(u.main(["check"], env=self.env), 0)
            edge.assert_called_once_with(u.a1.SSH_HOST)
        self.assertIn("remote_staging=not-inspected", out.getvalue())

    def test_upload_only_one_canonical_rsync_and_no_verified_remote_claim(self):
        files = [Path("/private/transfer-THREE-FILES-ONLY") / n for n in u.NAMES]
        runner = mock.Mock(side_effect=[
            SimpleNamespace(returncode=0, stdout=b"EMPTY_PRIVATE_STAGE" + bytes([10])),
            SimpleNamespace(returncode=0),
        ])
        with mock.patch.object(u, "require_workstation") as approval, \
             mock.patch.object(u, "local_package", return_value=files), \
             mock.patch.object(u, "check_crypto"), \
             mock.patch.object(u.a1, "operator_settings",
                               return_value=(u.a1.SSH_HOST, "ubuntu", "")), \
             mock.patch.object(u.shutil, "which",
                               side_effect=lambda name: "/usr/bin/" + name), \
             mock.patch.object(u.a1, "check_edge_tls"), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(u.main(["upload"], env=self.env, runner=runner), 0)
            approval.assert_called_once()
            self.assertEqual(runner.call_count, 2)
        remote = runner.call_args_list[0].args[0]
        self.assertEqual(remote[-2], "ubuntu@" + u.a1.SSH_HOST)
        self.assertIn("python3 -I -c", remote[-1])
        self.assertIn("EMPTY_PRIVATE_STAGE", remote[-1])
        self.assertIn("--ignore-existing", runner.call_args_list[1].args[0])
        self.assertEqual(runner.call_args_list[1].kwargs["timeout"], 300)
        self.assertIn("remote_state=requires-A1-inspect", out.getvalue())

    def test_remote_stage_readonly_rejection_prevents_rsync(self):
        for response in (
            SimpleNamespace(returncode=21, stdout=b""),
            SimpleNamespace(returncode=0, stdout=b"NOT_PRIVATE"),
        ):
            with self.subTest(response=response.stdout):
                runner = mock.Mock(return_value=response)
                with self.assertRaises(u.Refused):
                    u.remote_stage_probe(
                        "/usr/bin/ssh", "/usr/bin/cloudflared",
                        u.a1.SSH_HOST, "ubuntu", "", runner=runner,
                    )
                runner.assert_called_once()
                self.assertEqual(runner.call_args.kwargs["timeout"], 35)
        self.assertIn("stat.S_IMODE(s.st_mode) == 0o700", u.REMOTE_PROBE)
        self.assertIn("not os.listdir(p)", u.REMOTE_PROBE)
        self.assertNotIn("os.mkdir", u.REMOTE_PROBE)
        self.assertNotIn("os.chmod", u.REMOTE_PROBE)

    def test_prepare_stage_only_exact_remote_mkdir_and_no_ca_transfer(self):
        self.assertIn("os.mkdir(p, 0o700)", u.REMOTE_PREPARE)
        self.assertIn("os.geteuid() == 1001", u.REMOTE_PREPARE)
        self.assertIn("root.st_uid == 0", u.REMOTE_PREPARE)
        self.assertIn("not os.listdir(p)", u.REMOTE_PREPARE)
        for forbidden in ("sudo", "rsync", "shutil", "subprocess", "os.chmod",
                          "os.remove", "os.rmdir", "os.system", "ca-private.key"):
            self.assertNotIn(forbidden, u.REMOTE_PREPARE)
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout=b"EMPTY_PRIVATE_STAGE_READY\n"))
        with mock.patch.object(u, "require_workstation") as approval, \
             mock.patch.object(u, "local_package") as local, \
             mock.patch.object(u.a1, "operator_settings",
                               return_value=(u.a1.SSH_HOST, "ubuntu", "")), \
             mock.patch.object(u.shutil, "which",
                               side_effect=lambda name: None if name == "rsync" else "/usr/bin/" + name), \
             mock.patch.object(u.a1, "check_edge_tls"), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(u.main(["prepare-stage"], env=self.env, runner=runner), 0)
            approval.assert_called_once_with(self.env, ack=u.STAGE_ACK)
            local.assert_not_called()
        self.assertEqual(runner.call_count, 1)
        argv = runner.call_args.args[0]
        self.assertEqual(argv[-2], "ubuntu@" + u.a1.SSH_HOST)
        self.assertIn("python3 -I -c", argv[-1])
        self.assertIn("EMPTY_PRIVATE_STAGE_READY", argv[-1])
        self.assertNotIn("rsync", str(argv))
        self.assertEqual(runner.call_args.kwargs["timeout"], 35)
        self.assertIn("secrets=not-transferred", out.getvalue())

    def test_prepare_stage_rejects_remote_bad_state_and_ci(self):
        for bad in (SimpleNamespace(returncode=21, stdout=b""),
                    SimpleNamespace(returncode=0, stdout=b"UNVERIFIED")):
            with self.subTest(bad=bad.stdout), self.assertRaises(u.Refused):
                u.remote_stage_prepare("/usr/bin/ssh", "/usr/bin/cloudflared",
                                       u.a1.SSH_HOST, "ubuntu", "",
                                       runner=mock.Mock(return_value=bad))
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(u.main(["prepare-stage"], env={"CI": "true"}), 1)
        self.assertIn("UPLOAD_REFUSED", err.getvalue())

    def test_synthetic_real_package_crypto_matches_local_generator(self):
        if not shutil.which("openssl"):
            self.skipTest("OpenSSL not available")
        spec = importlib.util.spec_from_file_location(
            "generator", ROOT / "scripts/identity_production_mongo_pki_generate.py")
        g = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(g)
        work = self.home / "created-offline"
        g.create_local_bundle(work, ca_passphrase=b'test_only_43_char_offline_CA_passphrase_for_CI_2026')
        env = {"MONGO_PKI_OUTPUT_DIR": str(work)}
        files = u.local_package(env, uid=os.geteuid(), home=self.home)
        u.check_crypto(files)

    def test_make_targets_and_ci_rejection(self):
        for target, action in (("identity-prod-mongo-pki-upload-plan", "plan"),
                               ("identity-prod-mongo-pki-upload-check", "check"),
                               ("identity-prod-mongo-pki-stage-prepare", "prepare-stage"),
                               ("identity-prod-mongo-pki-upload", "upload")):
            p = subprocess.run(["make", "--no-print-directory", "-n", target],
                               cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("identity_production_mongo_pki_upload.py " + action, p.stdout)
            self.assertNotIn("sudo ", p.stdout)
            self.assertNotIn("docker ", p.stdout)
        p = subprocess.run(
            ["python3", "-I", str(ROOT / "scripts/identity_production_mongo_pki_upload.py"),
             "upload"], capture_output=True, text=True, timeout=10,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CI": "true"})
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("Traceback", p.stderr)


if __name__ == "__main__":
    unittest.main()
