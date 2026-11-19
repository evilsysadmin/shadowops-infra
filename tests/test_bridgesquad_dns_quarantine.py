"""Offline contract tests for quarantined DNS: real game remains anonymous-denied."""
import copy
import sys
import unittest
from pathlib import Path
from unittest import mock
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bridgesquad_dns_quarantine as q
import bridgesquad_pages_readiness as readiness
import bridgesquad_alias_watchdog as watchdog

ACCOUNT = "b" * 32
ZONE_ID = "c" * 32
SHA = "a" * 40
ALIAS = "bridgesquad-production.pages.dev"
ROOT = f"/accounts/{ACCOUNT}/pages/projects/{readiness.PROJECT}"
PROBE_BODY = b'{"error":"authentication_required"}'
SHELL = (b"<!doctype html><title>Bridge Squad</title>"
         b"<h1>Tu cuenta ShadowOps ID</h1><a>Entrar</a>")
HTML_HEADERS = {"Content-Type": "text/html; charset=utf-8",
                "Content-Security-Policy": "default-src 'none'; script-src 'self'"}
JSON_HEADERS = {"Content-Type": "application/json"}


def project():
    deploy = {
        "url": "https://abc123." + ALIAS, "environment": "production",
        "is_skipped": False, "latest_stage": {"status": "success"},
        "deployment_trigger": {"type": "ad_hoc", "metadata": {
            "branch": "main", "commit_dirty": False, "commit_hash": SHA,
        }},
    }
    return {
        "name": readiness.PROJECT, "subdomain": ALIAS,
        "production_branch": "main", "source": None, "domains": [],
        "deployment_configs": {
            mode: {"fail_open": False, "env_vars": {},
                   "compatibility_flags": ["global_fetch_strictly_public"]}
            for mode in ("production", "preview")
        },
        "canonical_deployment": copy.deepcopy(deploy),
        "latest_deployment": copy.deepcopy(deploy),
    }


class FakeClient:
    account = ACCOUNT

    def __init__(self):
        self.project = project()
        self.domain = None
        self.record = None
        self.writes = []

    def get(self, path):
        if path == ROOT:
            return self.project
        if path == ROOT + q.DOMAIN_PATH:
            return self.domain
        if path.startswith("/zones?"):
            return [{"name": readiness.ZONE, "id": ZONE_ID}]
        if path.startswith("/zones/" + ZONE_ID + "/dns_records?"):
            return [self.record] if self.record else []
        raise AssertionError("Unexpected Cloudflare read: " + path)

    def write(self, method, path, value, *, zone):
        if zone != ZONE_ID or method != "POST":
            raise AssertionError("Unexpected write")
        self.writes.append((method, path, value))
        if path == ROOT + "/domains" and value == {"name": readiness.HOST}:
            self.domain = {"name": readiness.HOST, "status": "active"}
            self.project["domains"] = [readiness.HOST]
            return self.domain
        if path == "/zones/" + ZONE_ID + "/dns_records" and value == {
            "type": "CNAME", "name": readiness.HOST, "content": ALIAS, "proxied": True, "ttl": 1,
        }:
            self.record = {"name": readiness.HOST, "type": "CNAME",
                           "content": ALIAS, "proxied": True}
            return self.record
        raise AssertionError("Noncanonical mutation")


def guest(url, method):
    return 404


def web(path, method):
    if path in ("/", "/index.html"):
        return 401, HTML_HEADERS, SHELL if method == "GET" else b""
    return 401, JSON_HEADERS, PROBE_BODY if method == "GET" else b""


class QuarantineDNSContracts(unittest.TestCase):
    def test_production_pages_owner_aliases_and_private_worker_preflight(self):
        client = FakeClient()
        cfg, hosts, sha = q.project(client)
        self.assertEqual(sha, SHA)
        self.assertEqual(set(hosts), {ALIAS, "abc123." + ALIAS})
        q.prove_aliases(hosts, guest)

    def test_canonical_domain_registration_and_proxied_dns_exactly_once(self):
        c = FakeClient()
        proof = q.attach(c, guest=guest)
        self.assertEqual(proof["dns"], "owned")
        self.assertEqual(proof["game"], "locked")
        self.assertEqual(c.writes, [
            ("POST", ROOT + "/domains", {"name": readiness.HOST}),
            ("POST", "/zones/" + ZONE_ID + "/dns_records", {
                "type": "CNAME", "name": readiness.HOST, "content": ALIAS,
                "proxied": True, "ttl": 1,
            }),
        ])
        self.assertEqual(readiness.inspect(c)["domain"], "present")
        self.assertEqual(readiness.inspect(c)["dns"], "present")
        q.attach(c, guest=guest)
        self.assertEqual(len(c.writes), 2, "retry created another record")

    def test_resume_after_pages_domain_written_but_before_dns(self):
        c = FakeClient()
        c.domain = {"name": readiness.HOST, "status": "pending"}
        c.project["domains"] = [readiness.HOST]
        q.attach(c, guest=guest)
        self.assertEqual(len(c.writes), 1)
        self.assertEqual(c.writes[0][1], "/zones/" + ZONE_ID + "/dns_records")

    def test_foreign_or_orphan_dns_never_adopted(self):
        for change in (
            {"name": readiness.HOST, "type": "A", "content": "192.0.2.1", "proxied": True},
            {"name": readiness.HOST, "type": "CNAME", "content": "evil.pages.dev", "proxied": True},
        ):
            c = FakeClient()
            c.record = change
            with self.subTest(change=change), self.assertRaises((q.QuarantineError, readiness.InventoryError)):
                q.attach(c, guest=guest)
            self.assertEqual(c.writes, [])
        c = FakeClient()
        c.record = {"name": readiness.HOST, "type": "CNAME", "content": ALIAS, "proxied": True}
        with self.assertRaises(q.QuarantineError):
            q.attach(c, guest=guest)

    def test_no_deploy_if_production_id_secret_or_foreign_hostname_exists(self):
        for mutate in (
            lambda c: c.project["deployment_configs"]["production"]["env_vars"].update({"secret": "bad"}),
            lambda c: c.project["deployment_configs"]["preview"].update({"fail_open": True}),
            lambda c: c.project["domains"].append("other.shadowops.dpdns.org"),
            lambda c: c.project.update({"production_branch": "feature"}),
            lambda c: c.project["canonical_deployment"]["deployment_trigger"]["metadata"].update({"commit_hash": "bad"}),
            lambda c: c.project.update({"source": {"type": "github"}}),
        ):
            c = FakeClient()
            mutate(c)
            with self.subTest(which=str(mutate)), self.assertRaises((q.QuarantineError, readiness.InventoryError, ValueError)):
                q.attach(c, guest=guest)
            self.assertEqual(c.writes, [])

    def test_alias_probes_must_all_return_verified_worker_404(self):
        c = FakeClient()
        for code in (200, 301, 401, 503, 599):
            with self.subTest(code=code), self.assertRaises(q.QuarantineError):
                q.attach(c, guest=lambda url, method: code)
            self.assertEqual(c.writes, [])

    def test_domain_probe_requires_real_https_auth_only_shell_not_game(self):
        c = FakeClient()
        q.attach(c, guest=guest)
        with mock.patch.object(q.socket, "getaddrinfo", return_value=[("ip",)]):
            receipt = q.audit(c, guest=guest, web=web)
            self.assertEqual(receipt["https"], "401-login-shell")
            self.assertEqual(receipt["assets"], "denied")
            self.assertEqual(receipt["aliases"], "2")
            with mock.patch.object(q, "https_probe", side_effect=web):
                result = watchdog.audit(c, probe=guest)
            self.assertEqual(result["host"], readiness.HOST)

    def test_leaking_game_assets_login_redirects_and_auth_bypass_fail(self):
        c = FakeClient()
        q.attach(c, guest=guest)
        for bad in (
            lambda path, method: (200, HTML_HEADERS, b"<canvas>game</canvas>"),
            lambda path, method: (302, {"Location": "https://id-staging.shadowops.dpdns.org"}, b""),
            lambda path, method: (401, HTML_HEADERS, SHELL + b"<canvas></canvas>"),
            lambda path, method: (401, JSON_HEADERS, PROBE_BODY),
            lambda path, method: (503, JSON_HEADERS, b"unavailable"),
        ):
            with mock.patch.object(q.socket, "getaddrinfo", return_value=[("ip",)]):
                with self.subTest(bad=str(bad)), self.assertRaises(q.QuarantineError):
                    q.audit(c, guest=guest, web=bad)

    def test_write_client_has_only_domain_and_exact_cname_permissions(self):
        c = q.Client.__new__(q.Client)
        c.account = ACCOUNT
        c._token = "test-credential-not-used"
        for method, path, body in (
            ("DELETE", ROOT, {}),
            ("POST", ROOT + "/deployments", {}),
            ("POST", ROOT + "/domains", {"name": "other.shadowops.dpdns.org"}),
            ("PATCH", ROOT, {"fail_open": True}),
            ("POST", "/zones/" + ZONE_ID + "/dns_records", {"name": readiness.HOST, "type": "A"}),
            ("POST", "/zones/" + ZONE_ID + "/dns_records", {
                "name": readiness.HOST, "type": "CNAME", "content": ALIAS,
                "proxied": False, "ttl": 1,
            }),
        ):
            with self.subTest(method=method, path=path), self.assertRaises(q.QuarantineError):
                c.write(method, path, body, zone=ZONE_ID)

    def test_probe_only_exact_host_read_only_methods(self):
        for path, method in (("/api/identity/token", "GET"), ("/", "POST"),
                             ("/api/bridgesquad/logout", "POST"), ("//evil.test", "GET")):
            with self.subTest(path=path), self.assertRaises(q.QuarantineError):
                q.https_probe(path, method)


if __name__ == "__main__":
    unittest.main()
