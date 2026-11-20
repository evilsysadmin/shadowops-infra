"""Star Adventures must never publish a bare static bundle after Identity cutover work."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_protected_bundle as protected

SHA = "a" * 40
JS = b"console.log('pinned-staradvs-js')"


def fixture(tmp: str) -> Path:
    dist = Path(tmp) / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(
        '<title>Star Adventures</title><div id="root"></div>'
        '<script type="module" src="/assets/index-fixed.js"></script>', encoding="utf-8")
    (dist / "assets/index-fixed.js").write_bytes(JS)
    (dist / "release.json").write_text(json.dumps({
        "build": SHA, "environment": "staging",
        "entry_js": {
            "path": "/assets/index-fixed.js",
            "sha256": hashlib.sha256(JS).hexdigest(),
        },
    }), encoding="utf-8")
    return dist


class ProtectedBundleTests(unittest.TestCase):
    def test_default_publication_is_paused_without_environment_override(self):
        self.assertEqual(protected.policy_status(), "pending-identity")
        self.assertEqual(protected.main(["gate"]), 10)
        for obj in ({"mode": "active"}, {"mode": "auto"},
                    {"mode": "pending-identity", "bypass": True}, {}):
            with tempfile.TemporaryDirectory() as tmp:
                config = Path(tmp) / "policy.json"
                config.write_text(json.dumps(obj), encoding="utf-8")
                with self.assertRaises(protected.ProtectionError):
                    protected.policy_status(config)

    def test_package_uses_exact_pinned_worker_and_verifies_both_digests(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = fixture(tmp)
            protected.prepare(dist, SHA)
            protected.verify(dist, SHA)
            self.assertEqual((dist / "_worker.js").read_bytes(), protected.WORKER.read_bytes())
            data = json.loads((dist / "release.json").read_text())
            self.assertEqual(data["authentication"], protected.AUTH)
            self.assertEqual(data["build"], SHA)
            with self.assertRaisesRegex(protected.ProtectionError, "overwrite"):
                protected.prepare(dist, SHA)
            with self.assertRaisesRegex(protected.ProtectionError, "Worker differs"):
                (dist / "_worker.js").write_text("export default {fetch(){return new Response('open')}}")
                protected.verify(dist, SHA)

    def test_missing_worker_and_static_build_cannot_pass_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = fixture(tmp)
            with self.assertRaises(protected.ProtectionError):
                protected.verify(dist, SHA)
            protected.prepare(dist, SHA)
            (dist / "_worker.js").unlink()
            with self.assertRaises(protected.ProtectionError):
                protected.verify(dist, SHA)

    def test_protects_exact_js_release_and_untrusted_asset_routes(self):
        for mutation in ("js", "sha", "identity", "routes", "function", "symlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                dist = fixture(tmp)
                protected.prepare(dist, SHA)
                if mutation == "js":
                    (dist / "assets/index-fixed.js").write_text("wrong JS")
                elif mutation == "sha":
                    (dist / "release.json").write_text(
                        (dist / "release.json").read_text().replace(SHA, "b" * 40))
                elif mutation == "identity":
                    (dist / "release.json").write_text(
                        (dist / "release.json").read_text().replace('"staradvs"', '"snooker"'))
                elif mutation == "routes":
                    (dist / "_routes.json").write_text('{"exclude":["/assets/*"]}')
                elif mutation == "function":
                    (dist / "functions").mkdir()
                else:
                    (dist / "assets/external").symlink_to(dist / "index.html")
                with self.assertRaises(protected.ProtectionError):
                    protected.verify(dist, SHA)

    def test_bad_source_manifest_or_conflicting_worker_is_not_overwritten(self):
        for mutation in ("sha", "entry", "worker", "routes"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                dist = fixture(tmp)
                if mutation == "sha":
                    (dist / "release.json").write_text(
                        (dist / "release.json").read_text().replace(SHA, "b" * 40))
                elif mutation == "entry":
                    (dist / "assets/index-fixed.js").write_text("tampered")
                elif mutation == "worker":
                    (dist / "_worker.js").write_text("unsafe")
                else:
                    (dist / "_routes.json").write_text("{}")
                with self.assertRaises(protected.ProtectionError):
                    protected.prepare(dist, SHA)

    def test_existing_publisher_has_no_static_only_deploy_path(self):
        flow = (ROOT / ".github/workflows/staradvs-pages-staging.yml").read_text()
        self.assertIn("staradvs_protected_bundle.py gate", flow)
        self.assertIn("steps.protection.outputs.allowed == 'true'", flow)
        self.assertIn("staradvs_protected_bundle.py prepare", flow)
        self.assertIn("staradvs_protected_bundle.py verify", flow)
        self.assertIn("staradvs_protected_bundle.py gate", flow.split("npx --yes wrangler@")[0])
        self.assertIn("staradvs_protected_bundle.py verify", flow.split("npx --yes wrangler@")[0])
        self.assertIn("config/staradvs-protected-release.json", flow)
        self.assertIn("scripts/staradvs_protected_bundle.py", flow)
        self.assertIn("tests/test_staradvs_protected_bundle.py", flow)


if __name__ == "__main__":
    unittest.main()
