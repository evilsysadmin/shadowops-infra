import importlib.util
import io
import json
import pathlib
import unittest
from unittest.mock import patch

MODULE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "staradvs_pages.py"
spec = importlib.util.spec_from_file_location("staradvs_pages", MODULE)
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class FakeCloudflare:
    account = "a" * 32

    def __init__(self, *, foreign=False, project=False, domain=False, duplicates=False):
        self.foreign = foreign
        self.project = project
        self.domain = domain
        self.duplicates = duplicates
        self.dns = False
        self.calls = []

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if path.startswith("/zones?"):
            return 200, [{"name": s.ZONE, "id": "z" * 32}]
        if "/dns_records?" in path:
            if self.foreign:
                result = [{"name": s.HOST, "type": "CNAME", "proxied": True,
                           "content": "foreign.pages.dev"}]
            elif self.dns:
                result = [{"name": s.HOST, "type": "CNAME", "proxied": True,
                           "content": s.TARGET}]
            else:
                result = []
            if self.duplicates:
                result *= 2
            return 200, result
        if path.endswith("/dns_records") and method == "POST":
            assert data["name"] == s.HOST and data["content"] == s.TARGET and data["proxied"] is True
            self.dns = True
            return 200, {"id": "record"}
        if path.endswith("/pages/projects"):
            if method == "POST":
                assert data == {"name": s.PROJECT, "production_branch": "main"}
                self.project = True
                return 201, {"name": s.PROJECT, "production_branch": "main"}
        if path.endswith("/pages/projects/" + s.PROJECT):
            if self.project:
                return 200, {"name": s.PROJECT, "production_branch": "main"}
            return 404, None
        if path.endswith("/domains/" + s.HOST):
            if self.domain:
                return 200, {"name": s.HOST, "status": "active"}
            return 404, None
        if path.endswith("/domains") and method == "POST":
            assert data == {"name": s.HOST}
            self.domain = True
            return 201, {"name": s.HOST, "status": "pending"}
        raise AssertionError("Unknown Cloudflare endpoint " + method + " " + path)


class StagingPagesTests(unittest.TestCase):
    def test_preflight_is_read_only_and_fixed_to_expected_identity(self):
        cf = FakeCloudflare()
        zone, statuses = s.inspect(cf)
        self.assertEqual(zone, "z" * 32)
        self.assertEqual(statuses, {"dns": "absent", "project": "absent", "domain": "absent"})
        self.assertTrue(all(method == "GET" for method, _, _ in cf.calls))

    def test_foreign_hostname_aborts_before_any_write(self):
        cf = FakeCloudflare(foreign=True)
        with self.assertRaisesRegex(s.AdmissionError, "another target"):
            s.ensure_project(cf)
        with self.assertRaisesRegex(s.AdmissionError, "another target"):
            s.ensure_domain(cf)
        self.assertTrue(all(method == "GET" for method, _, _ in cf.calls))

    def test_duplicate_or_ambiguous_hostname_aborts(self):
        cf = FakeCloudflare(project=True, domain=True, duplicates=True)
        cf.dns = True
        with self.assertRaisesRegex(s.AdmissionError, "Multiple DNS owners"):
            s.inspect(cf)

    def test_only_dedicated_project_created(self):
        cf = FakeCloudflare()
        s.ensure_project(cf)
        self.assertTrue(cf.project)
        self.assertEqual(len([x for x in cf.calls if x[0] == "POST"]), 1)
        self.assertEqual([p for method, p, _ in cf.calls if method == "POST"],
                         [f"/accounts/{cf.account}/pages/projects"])

    def test_domain_and_dns_created_only_after_owned_project(self):
        cf = FakeCloudflare()
        with self.assertRaisesRegex(s.AdmissionError, "not found"):
            s.ensure_domain(cf)
        self.assertTrue(all(op == "GET" for op, _, _ in cf.calls))
        s.ensure_project(cf)
        s.ensure_domain(cf)
        self.assertTrue(cf.domain and cf.dns)
        self.assertEqual([p for op,p,_ in cf.calls if op == "POST"][-2:],
                         [f"/accounts/{cf.account}/pages/projects/{s.PROJECT}/domains",
                          "/zones/" + "z"*32 + "/dns_records"])
        # Repeated reconciliation never creates a second record.
        before = len([x for x in cf.calls if x[0] == "POST"])
        s.ensure_domain(cf)
        self.assertEqual(len([x for x in cf.calls if x[0] == "POST"]), before)

    def test_existing_owned_resources_are_left_untouched(self):
        cf = FakeCloudflare(project=True, domain=True)
        cf.dns = True
        s.ensure_project(cf)
        s.ensure_domain(cf)
        self.assertTrue(all(op == "GET" for op,_,_ in cf.calls))

    def test_future_or_wrong_sha_rejected_for_live_public_probe(self):
        for sha in ["", "main", "A"*40, "z"*40, "0"*39]:
            with self.assertRaisesRegex(s.AdmissionError, "source SHA"):
                s.public_check(sha)

    def test_credentials_not_available_without_token(self):
        for env in ({}, {"CLOUDFLARE_API_TOKEN": "foo"}):
            with self.assertRaises(s.AdmissionError):
                s.CloudflareClient(env)


if __name__ == "__main__":
    unittest.main()
