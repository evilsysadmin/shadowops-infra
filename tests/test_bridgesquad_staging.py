"""Offline contracts for Bridge Squad staging (id-staging) Pages, proof and DNS."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import bridgesquad_staging as st
import bridgesquad_pages_readiness as readiness

ACCOUNT = "a" * 32
ZONE_ID = "z" * 32
SHA = "c" * 40
PROOF = "soc1_" + "Q" * 43
GOOD_HTML = b"<!doctype html><html><head><title>Matthias Bridge Squad</title></head><body>" + b"x" * 64 + b"</body></html>"


class FakeCloudflare(st.Client):
    def __init__(self):
        super().__init__({"CLOUDFLARE_ACCOUNT_ID": ACCOUNT, "CLOUDFLARE_API_TOKEN": "t"})
        self.project = None
        self.domain = None
        self.dns = []
        self.writes = []

    def get(self, path):
        base = st.project_path(ACCOUNT)
        if path == base:
            return copy.deepcopy(self.project)
        if path.startswith(base + "/domains/"):
            return copy.deepcopy(self.domain)
        if path.startswith("/zones?name="):
            return [{"id": ZONE_ID, "name": st.ZONE}]
        if path.startswith("/zones/" + ZONE_ID + "/dns_records?name="):
            return copy.deepcopy(self.dns)
        raise AssertionError("unexpected GET " + path)

    def write(self, method, path, value, *, zone=None):
        if not self.allowed(method, path, value, zone):
            raise st.StagingError("Noncanonical Cloudflare mutation denied")
        self.writes.append((method, path, copy.deepcopy(value)))
        if method == "POST" and path.endswith("/pages/projects"):
            self.project = {"name": st.PROJECT, "production_branch": "main", "source": None,
                            "subdomain": st.PROJECT + ".pages.dev", "deployment_configs": {},
                            "canonical_deployment": None, "latest_deployment": None}
            return {"name": st.PROJECT}
        if method == "PATCH":
            cfgs = self.project.setdefault("deployment_configs", {})
            for mode, cfg in value["deployment_configs"].items():
                current = cfgs.setdefault(mode, {})
                if "env_vars" in cfg:
                    current["env_vars"] = {k: {"type": v["type"]} for k, v in cfg["env_vars"].items()}
                else:
                    current.update(cfg)
            return self.project
        if path.endswith("/domains"):
            self.domain = {"name": st.HOST}
            return self.domain
        if path.endswith("/dns_records"):
            self.dns = [{"type": "CNAME", "name": st.HOST, "content": st.PROJECT + ".pages.dev", "proxied": True}]
            return self.dns[0]
        raise AssertionError("unexpected write")

    def deploy(self, sha=SHA):
        self.project["canonical_deployment"] = {
            "environment": "production", "is_skipped": False, "url": "https://abc123." + st.PROJECT + ".pages.dev",
            "latest_stage": {"status": "success"},
            "deployment_trigger": {"type": "ad_hoc", "metadata": {"branch": "main", "commit_dirty": False, "commit_hash": sha}}}
        self.project["latest_deployment"] = self.project["canonical_deployment"]


deny = lambda url, method="GET": 404


class StagingTests(unittest.TestCase):
    def test_isolated_from_production(self):
        self.assertNotEqual(st.PROJECT, readiness.PROJECT)
        self.assertNotEqual(st.HOST, readiness.HOST)
        self.assertEqual(st.ISSUER, "https://id-staging.shadowops.dpdns.org")
        worker = st.trusted_worker().decode()
        self.assertIn("export const HOST='staging.bridgesquad.shadowops.dpdns.org'", worker)
        self.assertNotIn("https://id.shadowops.dpdns.org", worker)

    def test_full_flow_provision_deploy_bind_attach(self):
        cf = FakeCloudflare()
        st.provision(cf)
        self.assertEqual(st.verify_posture(cf.project), {"proof": "pending"})
        with self.assertRaises(st.StagingError):
            st.attach(cf, guest=deny)  # DNS never before a sealed deployment
        cf.deploy()
        self.assertEqual(st.postdeploy(cf, SHA, guest=deny)["source_sha"], SHA)
        with self.assertRaises(st.StagingError):
            st.postdeploy(cf, "d" * 40, guest=deny)
        st.bind(cf, PROOF)
        self.assertEqual(st.verify_posture(cf.project), {"proof": "bound"})
        st.attach(cf, guest=deny)
        self.assertIsNotNone(cf.domain)
        self.assertEqual(len(cf.dns), 1)
        # Idempotent: a second run performs no new domain/DNS/create writes.
        before = len(cf.writes)
        st.provision(cf)
        st.attach(cf, guest=deny)
        self.assertEqual([w[0] for w in cf.writes[before:]], ["PATCH"])
        for method, path, value in cf.writes:
            self.assertNotIn("bridgesquad-production", path)
            self.assertNotIn('"' + readiness.HOST + '"', json.dumps(value))

    def test_alias_leak_blocks_deploy_and_dns(self):
        cf = FakeCloudflare()
        st.provision(cf)
        cf.deploy()
        leak = lambda url, method="GET": 200 if url.endswith("/index.html") else 404
        with self.assertRaises(st.StagingError):
            st.postdeploy(cf, SHA, guest=leak)
        with self.assertRaises(st.StagingError):
            st.attach(cf, guest=leak)
        self.assertIsNone(cf.domain)

    def test_foreign_or_orphaned_resources_are_never_adopted(self):
        cf = FakeCloudflare()
        cf.dns = [{"type": "CNAME", "name": st.HOST, "content": st.PROJECT + ".pages.dev", "proxied": True}]
        with self.assertRaises(st.StagingError):
            st.provision(cf)  # orphan DNS without project
        cf = FakeCloudflare()
        cf.dns = [{"type": "A", "name": st.HOST, "content": "1.2.3.4", "proxied": True}]
        with self.assertRaises(st.StagingError):
            st.inventory(cf)
        cf = FakeCloudflare()
        st.provision(cf)
        cf.project["source"] = {"type": "github"}
        with self.assertRaises(st.StagingError):
            st.inventory(cf)

    def test_writes_are_exact_allowlist(self):
        cf = FakeCloudflare()
        base = st.project_path(ACCOUNT)
        for method, path, value in (
            ("POST", "/accounts/" + ACCOUNT + "/pages/projects", {"name": "bridgesquad-production", "production_branch": "main"}),
            ("PATCH", base, {"deployment_configs": {"production": {"fail_open": True, "compatibility_flags": [st.STRICT]},
                                                    "preview": {"fail_open": False, "compatibility_flags": [st.STRICT]}}}),
            ("PATCH", base, {"deployment_configs": {"preview": {"env_vars": {st.KEY: {"type": "secret_text", "value": PROOF}}}}}),
            ("PATCH", base, {"deployment_configs": {"production": {"env_vars": {st.KEY: {"type": "plain_text", "value": PROOF}}}}}),
            ("PATCH", base, {"deployment_configs": {"production": {"env_vars": {"OTHER": {"type": "secret_text", "value": PROOF}}}}}),
            ("POST", base + "/domains", {"name": "bridgesquad.shadowops.dpdns.org"}),
            ("POST", "/zones/" + ZONE_ID + "/dns_records", {"type": "CNAME", "name": st.HOST, "content": "bridgesquad-production.pages.dev", "proxied": True, "ttl": 1}),
            ("DELETE", base, {}),
        ):
            with self.subTest(method=method, value=value), self.assertRaises(st.StagingError):
                cf.write(method, path, value, zone=ZONE_ID)

    def test_preview_secrets_or_extra_variables_block(self):
        for cfgs in ({"preview": {"env_vars": {st.KEY: {"type": "secret_text"}}}},
                     {"production": {"env_vars": {"DEBUG": {"type": "plain_text"}}}}):
            project = {"name": st.PROJECT, "deployment_configs": {
                m: {"fail_open": False, "compatibility_flags": [st.STRICT]} for m in ("production", "preview")}}
            for mode, extra in cfgs.items():
                project["deployment_configs"][mode].update(extra)
            with self.assertRaises(st.StagingError):
                st.verify_posture(project)

    def test_package_seals_exact_html_and_reviewed_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            proof = st.package(SHA, out, fetch=lambda sha: GOOD_HTML)
            self.assertEqual(sorted(p.name for p in out.iterdir()), ["_worker.js", "index.html", "release.json"])
            manifest = json.loads((out / "release.json").read_text())
            self.assertEqual((manifest["environment"], manifest["host"], manifest["source_commit"]), ("staging", st.HOST, SHA))
            self.assertEqual(proof["source_sha"], SHA)
            (out / "index.html").write_bytes(GOOD_HTML + b"tampered")
            with self.assertRaises(st.StagingError):
                st.verify_package(out, SHA)
            with self.assertRaises(st.StagingError):
                st.package(SHA, out, fetch=lambda sha: GOOD_HTML)  # destination must be new

    def test_audit_requires_id_staging_shell_and_denied_assets(self):
        cf = FakeCloudflare()
        st.provision(cf); cf.deploy(); st.attach(cf, guest=deny)
        shell = ("<p>Tu cuenta ShadowOps ID</p><a href=\"" + st.ISSUER + "/login?app=bridgesquad\">").encode()
        csp = {"Content-Security-Policy": "default-src 'none'"}
        def good(path, method="GET"):
            if path in ("/", "/index.html"):
                return 401, csp, shell if method == "GET" else b""
            return 401, {}, b'{"error":"authentication_required"}'
        ok = st.audit(cf, web=good, guest=deny, resolve=lambda *a, **k: [1])
        self.assertEqual((ok["guest"], ok["proof"]), ("401-login-shell", "pending"))
        for bad in (
            lambda p, m="GET": (200, csp, b"<canvas>") if p == "/" else good(p, m),
            lambda p, m="GET": (200, {}, b"secret") if p == "/release.json" else good(p, m),
            lambda p, m="GET": (401, csp, shell.replace(b"id-staging", b"id")) if p == "/" else good(p, m),
            lambda p, m="GET": (200, {}, b"") if m == "HEAD" else good(p, m),
        ):
            with self.assertRaises(st.StagingError):
                st.audit(cf, web=bad, guest=deny, resolve=lambda *a, **k: [1])

    def test_identity_ready_requires_exact_staging_callback(self):
        good = ("https://" + st.HOST + "/?shadowops=central").encode()
        self.assertTrue(st.identity_ready(lambda url: (200, b"x" + good)))
        self.assertFalse(st.identity_ready(lambda url: (400, b"application denied")))
        self.assertFalse(st.identity_ready(lambda url: (200, b"https://bridgesquad.shadowops.dpdns.org/?shadowops=central")))

    def test_cli_plan_is_offline(self):
        self.assertEqual(st.main(["plan"]), 0)
        self.assertEqual(st.main(["unknown"]), 64)


if __name__ == "__main__":
    unittest.main()
