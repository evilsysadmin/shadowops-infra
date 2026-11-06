"""Offline/no-network tests for create-once empty Pages project reservation."""
from __future__ import annotations
import io
import json
import sys
import unittest
import urllib.error
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_pages_create as mod
from pawn_action_pages import HOST, PROJECT
from cloudflare_control_plane import API, InventoryError
ACCOUNT = "a" * 32
ENV = {"CLOUDFLARE_ACCOUNT_ID": ACCOUNT, "CLOUDFLARE_API_TOKEN": "reader",
       "PAWN_ACTION_PAGES_PROVISION_TOKEN": "writer"}

class Reader:
    account = ACCOUNT
    def __init__(self, state="absent"):
        self.state, self.calls = state, []
    def get(self, path, *, allow_missing=False):
        self.calls.append(path)
        if path.startswith("/zones?"):
            return 200, [{"name": "shadowops.dpdns.org", "id": "z" * 32}]
        if path.endswith("/pages/projects/" + PROJECT):
            if self.state == "absent":
                assert allow_missing
                return 404, None
            obj = {"name": PROJECT, "production_branch": "main",
                   "source": None, "subdomain": PROJECT + ".pages.dev",
                   "domains": [PROJECT + ".pages.dev"]}
            if self.state == "foreign":
                obj["source"] = {"type": "github"}
            return 200, obj
        if "/pages/projects/" in path and "/domains/" in path:
            return 404, None
        if "/dns_records?" in path:
            if self.state == "orphan":
                return 200, [{"name": HOST, "type": "CNAME",
                              "proxied": True, "content": "alien.pages.dev"}]
            return 200, []
        raise AssertionError("Unexpected endpoint " + path)

class Writer:
    account = ACCOUNT
    def __init__(self, reader, result="created"):
        self.reader, self.result, self.posts = reader, result, 0
    def create_project(self):
        self.posts += 1
        if self.result in ("timeout", "conflict"):
            raise mod.ProvisionError("Unverified create")
        self.reader.state = self.result
        return {"name": PROJECT}

class FakeResponse:
    def __init__(self, status=200, obj=None):
        self.status = status
        self.obj = obj if obj is not None else {
            "success": True, "result": {"name": PROJECT,
                "production_branch": "main", "subdomain": PROJECT + ".pages.dev",
                "domains": [], "source": None}}
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, size):
        assert size == 32769
        return self.obj if isinstance(self.obj, bytes) else json.dumps(self.obj).encode()

class FakeOpener:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result or FakeResponse(), error, []
    def open(self, request, *, timeout):
        self.calls.append((request, timeout))
        if self.error: raise self.error
        return self.result

class Tests(unittest.TestCase):
    def test_offline_plan_requires_no_credentials_or_cloud(self):
        with patch.object(mod, "CloudflareReadClient") as r, \
             patch.object(mod, "PagesCreator") as w, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(mod.main(["plan"], {}), 0)
            r.assert_not_called(); w.assert_not_called()
        payload = json.loads(out.getvalue().split("PAWN_ACTION_PAGES_RESERVATION_PLAN ")[1])
        self.assertEqual(payload["writes"], 0)
        self.assertFalse(payload["deploysWorker"])

    def test_exact_single_post_then_owner_and_route_verified(self):
        reader = Reader(); writer = Writer(reader)
        actual = mod.reserve_once(reader, writer, PROJECT)
        self.assertEqual(actual, {"project": PROJECT, "state": "reserved_unrouted", "published": False})
        self.assertEqual(writer.posts, 1)
        self.assertEqual(len(reader.calls), 7)

    def test_existing_unrouted_project_is_noop(self):
        reader = Reader("created"); writer = Writer(reader)
        self.assertEqual(mod.reserve_once(reader, writer, PROJECT)["state"], "already_reserved_unrouted")
        self.assertEqual(writer.posts, 0)

    def test_wrong_confirmation_account_blocks_before_reads(self):
        for confirmation in ("", "chess-studio", "football-staging", PROJECT + "2"):
            reader = Reader(); writer = Writer(reader)
            with self.subTest(confirmation=confirmation), self.assertRaises(mod.ProvisionError):
                mod.reserve_once(reader, writer, confirmation)
            self.assertEqual(reader.calls, []); self.assertEqual(writer.posts, 0)
        reader = Reader(); writer = Writer(reader); writer.account = "b"*32
        with self.assertRaises(mod.ProvisionError): mod.reserve_once(reader, writer, PROJECT)
        self.assertEqual(reader.calls, [])

    def test_foreign_or_orphan_is_never_adopted(self):
        for state in ("foreign", "orphan"):
            reader = Reader(state); writer = Writer(reader)
            with self.subTest(state=state), self.assertRaises((mod.ProvisionError, InventoryError)):
                mod.reserve_once(reader, writer, PROJECT)
            self.assertEqual(writer.posts, 0)

    def test_postcheck_is_required_even_after_successful_post(self):
        for state in ("absent", "foreign", "orphan"):
            reader = Reader(); writer = Writer(reader, state)
            with self.subTest(state=state), self.assertRaises((mod.ProvisionError, InventoryError)):
                mod.reserve_once(reader, writer, PROJECT)
            self.assertEqual(writer.posts, 1)

    def test_write_failure_never_retries(self):
        for state in ("timeout", "conflict"):
            reader = Reader(); writer = Writer(reader, state)
            with self.assertRaises(mod.ProvisionError):
                mod.reserve_once(reader, writer, PROJECT)
            self.assertEqual(writer.posts, 1)

    def test_http_request_is_one_exact_post_without_redirect(self):
        creator = mod.PagesCreator(ENV)
        opener = FakeOpener()
        with patch.object(mod.urllib.request, "build_opener", return_value=opener) as build:
            self.assertEqual(creator.create_project()["name"], PROJECT)
            self.assertIsInstance(build.call_args.args[0], mod.NoRedirect)
        self.assertEqual(len(opener.calls), 1)
        req, timeout = opener.calls[0]
        self.assertEqual(timeout, 20)
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.full_url, API + "/accounts/" + ACCOUNT + "/pages/projects")
        self.assertEqual(json.loads(req.data), {"name": PROJECT, "production_branch": "main"})
        self.assertEqual(req.get_header("Authorization"), "Bearer writer")

    def test_bad_api_response_is_rejected(self):
        invalid = [
            FakeResponse(status=201),
            FakeResponse(obj=b"not-json"),
            FakeResponse(obj=b"x" * 32769),
            FakeResponse(obj={"success": False, "result": {"name": PROJECT}}),
            FakeResponse(obj={"success": True, "result": {"name": "football"}}),
            FakeResponse(obj={"success": True, "result": {"name": PROJECT,
                "production_branch": "dev", "subdomain": PROJECT+".pages.dev", "domains": []}}),
            FakeResponse(obj={"success": True, "result": {"name": PROJECT,
                "production_branch": "main", "subdomain": PROJECT+".pages.dev",
                "domains": [], "latest_deployment": {"id": "exposed"}}}),
            FakeResponse(obj={"success": True, "result": {"name": PROJECT,
                "production_branch": "main", "subdomain": "football.pages.dev", "domains": []}}),
            FakeResponse(obj={"success": True, "result": {"name": PROJECT,
                "production_branch": "main", "subdomain": PROJECT+".pages.dev", "domains": [HOST]}}),
        ]
        creator = mod.PagesCreator(ENV)
        for response in invalid:
            with self.subTest(response=str(response.obj)[:45]):
                with patch.object(mod.urllib.request, "build_opener",
                                  return_value=FakeOpener(response)):
                    with self.assertRaises(mod.ProvisionError): creator.create_project()

    def test_network_errors_do_not_expose_secret_or_retry(self):
        creator = mod.PagesCreator(ENV)
        for error in (TimeoutError("writer leaked"),
                      urllib.error.HTTPError(API, 409, "conflict", {}, None)):
            opener = FakeOpener(error=error)
            with patch.object(mod.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(mod.ProvisionError) as result:
                    creator.create_project()
            self.assertEqual(len(opener.calls), 1)
            self.assertNotIn("writer", str(result.exception))

    def test_separate_tokens_before_any_io(self):
        for update in ({"CLOUDFLARE_ACCOUNT_ID": "foo"},
                       {"CLOUDFLARE_API_TOKEN": ""},
                       {"PAWN_ACTION_PAGES_PROVISION_TOKEN": ""},
                       {"PAWN_ACTION_PAGES_PROVISION_TOKEN": "reader"}):
            with self.subTest(update=update), self.assertRaises(mod.ProvisionError):
                mod.PagesCreator({**ENV, **update})

    def test_cli_missing_confirmation_never_reads_secrets(self):
        with patch.object(mod, "PagesCreator") as w, \
             patch.object(mod, "CloudflareReadClient") as r, redirect_stderr(io.StringIO()):
            self.assertEqual(mod.main(["reserve"], ENV), 1)
            w.assert_not_called(); r.assert_not_called()

    def test_no_other_mutation_methods_or_assets_publish(self):
        source = Path(mod.__file__).read_text()
        for forbidden in ('method="PUT"', 'method="PATCH"', 'method="DELETE"',
                          "deployments", "dns_records", "chess-studio-assets"):
            self.assertNotIn(forbidden, source)
        self.assertIn('method="POST"', source)
if __name__ == "__main__":
    unittest.main()
