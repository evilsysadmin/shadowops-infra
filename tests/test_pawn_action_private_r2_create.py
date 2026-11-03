"""No-network R2 create-once tests: zero existing-resource mutations."""
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
import pawn_action_private_r2_create as create
from pawn_action_private_r2 import BUCKET
from cloudflare_control_plane import API, InventoryError

ACCOUNT = "a" * 32
ENV = {"CLOUDFLARE_ACCOUNT_ID": ACCOUNT,
       "CLOUDFLARE_API_TOKEN": "read-only-fixture",
       "PAWN_ACTION_R2_PROVISION_TOKEN": "separate-create-fixture"}


class ReadOnlyCloudflare:
    account = ACCOUNT

    def __init__(self, state="absent"):
        self.state = state
        self.calls = []

    def get(self, path, *, allow_missing=False):
        self.calls.append(path)
        root = f"/accounts/{self.account}/r2/buckets/{BUCKET}"
        if path == root:
            if self.state == "absent":
                if not allow_missing:
                    raise AssertionError("Bucket may be absent only in preflight")
                return 404, None
            return 200, {"name": BUCKET}
        if path == root + "/domains/managed":
            return 200, {"enabled": self.state == "public"}
        if path == root + "/domains/custom":
            return 200, {"domains": []}
        raise AssertionError("Unexpected endpoint " + path)


class CreateOnlyCloudflare:
    account = ACCOUNT

    def __init__(self, reader, *, outcome="success"):
        self.reader = reader
        self.outcome = outcome
        self.posts = 0

    def create_bucket(self):
        self.posts += 1
        if self.outcome == "conflict":
            raise create.ProvisionError("R2 create rejected (HTTP 409)")
        if self.outcome == "timeout":
            raise create.ProvisionError("R2 creation outcome unknown")
        if self.outcome == "mismatch":
            raise create.ProvisionError("R2 create response did not confirm exact bucket")
        self.reader.state = "public" if self.outcome == "exposed" else "private"
        return {"name": BUCKET}


class FakeHTTP:
    def __init__(self, *, status=200, body=None):
        self.status = status
        self.body = body if body is not None else {
            "success": True, "result": {"name": BUCKET},
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, length):
        assert length == 32769
        if isinstance(self.body, bytes):
            return self.body
        return json.dumps(self.body).encode("utf-8")


class CreateOnlyTests(unittest.TestCase):
    def test_plan_is_offline_and_needs_no_secret_or_cloud_calls(self):
        with patch.object(create, "CloudflareReadClient") as reader, \
             patch.object(create, "BucketCreator") as writer, \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(create.main(["plan"], {}), 0)
            reader.assert_not_called()
            writer.assert_not_called()
        result = json.loads(output.getvalue().split("PAWN_ACTION_R2_CREATE_PLAN ")[1])
        self.assertEqual(result["bucket"], BUCKET)
        self.assertEqual(result["writes"], 0)

    def test_absent_bucket_created_once_and_verified_private(self):
        read = ReadOnlyCloudflare()
        write = CreateOnlyCloudflare(read)
        outcome = create.create_once(read, write, BUCKET)
        self.assertEqual(outcome, {"bucket": BUCKET,
                                  "state": "created_private", "private": "true"})
        self.assertEqual(write.posts, 1)
        self.assertEqual(len(read.calls), 4)
        self.assertEqual(read.calls[0], read.calls[1])
        self.assertFalse(any("chess-studio-assets" in p for p in read.calls))

    def test_repeat_create_is_idempotent_without_post(self):
        read = ReadOnlyCloudflare("private")
        write = CreateOnlyCloudflare(read)
        result = create.create_once(read, write, BUCKET)
        self.assertEqual(result["state"], "already_private")
        self.assertEqual(write.posts, 0)
        self.assertEqual(len(read.calls), 3)

    def test_existing_public_bucket_refused_without_post(self):
        read = ReadOnlyCloudflare("public")
        write = CreateOnlyCloudflare(read)
        with self.assertRaises(InventoryError):
            create.create_once(read, write, BUCKET)
        self.assertEqual(write.posts, 0)

    def test_exact_confirmation_before_any_get_or_post(self):
        for confirmation in ("", "chess-studio-assets", "pawn-action",
                             BUCKET + "-evil", "football-staging"):
            with self.subTest(confirmation=confirmation):
                read = ReadOnlyCloudflare()
                write = CreateOnlyCloudflare(read)
                with self.assertRaises(create.ProvisionError):
                    create.create_once(read, write, confirmation)
                self.assertEqual(write.posts, 0)
                self.assertEqual(read.calls, [])

    def test_reader_writer_account_mismatch_before_network(self):
        read = ReadOnlyCloudflare()
        write = CreateOnlyCloudflare(read)
        write.account = "b" * 32
        with self.assertRaises(create.ProvisionError):
            create.create_once(read, write, BUCKET)
        self.assertEqual(write.posts, 0)
        self.assertEqual(read.calls, [])

    def test_conflict_unknown_timeout_never_retries_or_adopts(self):
        for failure in ("conflict", "timeout", "mismatch"):
            with self.subTest(failure=failure):
                read = ReadOnlyCloudflare()
                write = CreateOnlyCloudflare(read, outcome=failure)
                with self.assertRaises(create.ProvisionError):
                    create.create_once(read, write, BUCKET)
                self.assertEqual(write.posts, 1)
                self.assertEqual(read.state, "absent")

    def test_postcheck_public_fails_without_second_post_or_rollback(self):
        read = ReadOnlyCloudflare()
        write = CreateOnlyCloudflare(read, outcome="exposed")
        with self.assertRaises(InventoryError):
            create.create_once(read, write, BUCKET)
        self.assertEqual(write.posts, 1)
        self.assertEqual(read.state, "public")

    def test_creator_uses_one_exact_200_api_post_and_only_bucket_name(self):
        writer = create.BucketCreator(ENV)
        def fake_http(request, timeout):
            self.assertEqual(timeout, 20)
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.full_url, API + f"/accounts/{ACCOUNT}/r2/buckets")
            self.assertEqual(json.loads(request.data), {"name": BUCKET})
            self.assertEqual(request.get_header("Authorization"), "Bearer separate-create-fixture")
            return FakeHTTP()
        with patch.object(create.urllib.request, "urlopen", side_effect=fake_http) as http:
            self.assertEqual(writer.create_bucket()["name"], BUCKET)
            http.assert_called_once()

    def test_non_success_or_incomplete_api_response_never_accepted(self):
        invalid = [
            FakeHTTP(status=201),
            FakeHTTP(body={"success": False, "result": {"name": BUCKET}}),
            FakeHTTP(body={"success": True, "result": {"name": "chess-studio-assets"}}),
            FakeHTTP(body={"success": True, "result": None}),
            FakeHTTP(body=b"not-json"),
            FakeHTTP(body=b"x" * 32769),
        ]
        writer = create.BucketCreator(ENV)
        for response in invalid:
            with self.subTest(status=response.status, body=str(response.body)[:35]):
                with patch.object(create.urllib.request, "urlopen",
                                  return_value=response):
                    with self.assertRaises(create.ProvisionError):
                        writer.create_bucket()

    def test_unknown_api_failure_is_not_logged_or_automatically_retried(self):
        writer = create.BucketCreator(ENV)
        with patch.object(create.urllib.request, "urlopen",
                          side_effect=RuntimeError("secret leak read-only-fixture")) as http:
            with self.assertRaises(create.ProvisionError) as issue:
                writer.create_bucket()
            self.assertNotIn("secret", str(issue.exception))
            http.assert_called_once()

    def test_independent_credential_contract_before_io(self):
        for change in (
            {"PAWN_ACTION_R2_PROVISION_TOKEN": ""},
            {"CLOUDFLARE_API_TOKEN": ""},
            {"PAWN_ACTION_R2_PROVISION_TOKEN": ENV["CLOUDFLARE_API_TOKEN"]},
            {"CLOUDFLARE_ACCOUNT_ID": "football"},
        ):
            with self.subTest(change=change):
                with self.assertRaises(create.ProvisionError):
                    create.BucketCreator({**ENV, **change})

    def test_cli_missing_confirmation_denies_even_if_tokens_present(self):
        with patch.object(create, "CloudflareReadClient") as reader, \
             patch.object(create, "BucketCreator") as creator, \
             redirect_stderr(io.StringIO()):
            self.assertEqual(create.main(["create"], ENV), 1)
            reader.assert_not_called()
            creator.assert_not_called()

    def test_no_mutation_capabilities_beyond_bucket_create(self):
        source = Path(create.__file__).read_text(encoding="utf-8")
        for forbidden in ("method=\"PUT\"", "method=\"PATCH\"",
                          "method=\"DELETE\"", "delete_bucket(", "put_object(",
                          "chess-studio-assets"):
            self.assertNotIn(forbidden, source)
        self.assertIn("method=\"POST\"", source)


if __name__ == "__main__":
    unittest.main()
