"""A Star Adventures staging Pages proof must be strictly isolated from other games."""
from __future__ import annotations

import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_identity_binding as binding
import staradvs_pages as pages

OWN_PROOF = "soc1_" + "z" * 43


def owned():
    cfg = lambda: {
        "fail_open": False,
        "compatibility_flags": ["global_fetch_strictly_public"],
        "env_vars": {},
    }
    return {
        "name": pages.PROJECT, "subdomain": pages.TARGET,
        "production_branch": "main", "source": None,
        "domains": [pages.HOST],
        "deployment_configs": {"production": cfg(), "preview": cfg()},
    }


class FakeCloudflare:
    account = "a" * 32

    def __init__(self, value=None):
        self.value = value if value is not None else owned()
        self.calls = []

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if path.startswith("/zones?"):
            return 200, [{"name": pages.ZONE, "id": "b" * 32}]
        if "/dns_records?" in path:
            return 200, [{"name": pages.HOST, "type": "CNAME",
                          "content": pages.TARGET, "proxied": True}]
        if path.endswith("/pages/projects/" + pages.PROJECT):
            if method == "GET":
                return 200, copy.deepcopy(self.value)
            if method == "PATCH":
                assert set(data) == {"deployment_configs"}
                assert set(data["deployment_configs"]) == {"production"}
                assert set(data["deployment_configs"]["production"]) == {"env_vars"}
                vars_ = data["deployment_configs"]["production"]["env_vars"]
                assert set(vars_) == {binding.KEY}
                self.value["deployment_configs"]["production"]["env_vars"] = copy.deepcopy(vars_)
                return 200, copy.deepcopy(self.value)
        if path.endswith("/domains/" + pages.HOST):
            return 200, {"name": pages.HOST, "status": "active"}
        raise AssertionError("Foreign Cloudflare path " + method + " " + path)


class IdentityBindingTests(unittest.TestCase):
    def test_plan_is_read_only_and_does_not_claim_secret_value_equality(self):
        cf = FakeCloudflare()
        self.assertEqual(binding.posture(cf), "binding-missing")
        self.assertTrue(all(m == "GET" for m, _, _ in cf.calls))
        cf.value["deployment_configs"]["production"]["env_vars"] = {
            binding.KEY: {"type": "secret_text", "value": "OPAQUE"}
        }
        self.assertEqual(binding.posture(cf), "named-binding-present-not-value-verified")

    def test_only_own_staradvs_service_proof_is_written_with_exact_secret_type(self):
        cf = FakeCloudflare()
        self.assertEqual(binding.bind(cf, OWN_PROOF), "bound-by-name-type-only")
        writes = [(path, data) for method, path, data in cf.calls if method == "PATCH"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][0],
                         f"/accounts/{cf.account}/pages/projects/{pages.PROJECT}")
        self.assertEqual(writes[0][1], {"deployment_configs": {
            "production": {"env_vars": {
                binding.KEY: {"type": "secret_text", "value": OWN_PROOF}
            }}
        }})
        self.assertEqual(cf.value["deployment_configs"]["preview"]["env_vars"], {})
        self.assertEqual(cf.value["deployment_configs"]["production"]["fail_open"], False)
        self.assertEqual(binding.posture(cf), "named-binding-present-not-value-verified")

    def test_invalid_proof_never_calls_cloudflare(self):
        for proof in ("", "soc1_short", "Bearer " + OWN_PROOF,
                      "soc1_" + "w" * 42, "sno1_" + "x" * 43, None):
            with self.subTest(proof=proof):
                cf = FakeCloudflare()
                with self.assertRaises(binding.BindingError):
                    binding.bind(cf, proof)
                self.assertFalse(cf.calls)

    def test_unsafe_pages_policy_or_foreign_bindings_block_mutation(self):
        for bad in ("fail-open", "preview-fail-open", "missing-compat",
                    "private-origin", "wrong-app", "plain-secret",
                    "preview-proof", "foreign-domain"):
            with self.subTest(bad=bad):
                proj = owned()
                prod = proj["deployment_configs"]["production"]
                if bad == "fail-open":
                    prod["fail_open"] = True
                elif bad == "preview-fail-open":
                    proj["deployment_configs"]["preview"]["fail_open"] = True
                elif bad == "missing-compat":
                    prod["compatibility_flags"] = []
                elif bad == "private-origin":
                    prod["compatibility_flags"].append("global_fetch_private_origin")
                elif bad == "wrong-app":
                    prod["env_vars"]["SHADOWOPS_SNOOKER_SERVICE_CREDENTIAL"] = {"type": "secret_text"}
                elif bad == "plain-secret":
                    prod["env_vars"][binding.KEY] = {"type": "plain_text"}
                elif bad == "preview-proof":
                    proj["deployment_configs"]["preview"]["env_vars"][binding.KEY] = {"type": "secret_text"}
                else:
                    proj["domains"] = ["foreign.invalid"]
                cf = FakeCloudflare(proj)
                with self.assertRaises((binding.BindingError, pages.AdmissionError)):
                    binding.bind(cf, OWN_PROOF)
                self.assertFalse(any(method == "PATCH" for method, _, _ in cf.calls))

    def test_invalid_operator_request_and_direct_cli_bind_never_load_providers(self):
        from unittest.mock import patch
        cases = (
            ("plan", "", True),
            ("plan", binding.CONFIRM, False),
            ("bind", binding.CONFIRM, True),
            ("bind", "wrong", False),
            ("bind", "", False),
            ("other", binding.CONFIRM, False),
        )
        for operation, confirm, accepted in cases:
            with self.subTest(operation=operation, confirm=confirm):
                with patch.dict("os.environ", {
                    "STARADVS_BIND_OPERATION": operation,
                    "STARADVS_BIND_CONFIRM": confirm,
                }, clear=True), patch.object(
                    binding.pages, "CloudflareClient",
                    side_effect=AssertionError("Cloudflare must remain untouched"),
                ):
                    self.assertEqual(binding.main(["validate-intent"]),
                                     0 if accepted else 64)
                if accepted:
                    self.assertEqual(binding.validate_dispatch_intent(operation, confirm),
                                     operation)
                else:
                    with self.assertRaises(binding.BindingError):
                        binding.validate_dispatch_intent(operation, confirm)
        with patch.dict("os.environ", {}, clear=True), patch.object(
            binding.pages, "CloudflareClient",
            side_effect=AssertionError("Unconfirmed direct bind cannot access provider"),
        ):
            self.assertEqual(binding.main(["bind"]), 64)

    def test_manual_operator_is_the_only_binding_write_path(self):
        flow = (ROOT / ".github/workflows/staradvs-identity-binding.yml").read_text()
        self.assertIn("workflow_dispatch:", flow)
        self.assertIn("staradvs_identity_binding.py validate-intent", flow)
        self.assertIn("STARADVS_BIND_OPERATION: ${{ inputs.operation }}", flow)
        self.assertIn("STARADVS_BIND_CONFIRM: ${{ inputs.confirm }}", flow)
        self.assertIn("inputs.operation == 'bind'", flow)
        self.assertIn("inputs.confirm == 'STARADVS_BIND_ISOLATED_IDENTITY'", flow)
        self.assertIn("github.event_name == 'workflow_dispatch'", flow)
        self.assertIn("github.ref == 'refs/heads/main'", flow)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", flow)
        self.assertIn("environment: staging", flow)
        self.assertIn("shadowops-staradvs-staging-pages", flow)
        self.assertNotIn("pages deploy", flow)
        self.assertNotIn("wrangler", flow)
        self.assertNotIn("printf '%s' $PROOF", flow)


if __name__ == "__main__":
    unittest.main()
