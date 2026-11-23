"""Read-only Star Adventures ShadowOps ID cutover checks: no secrets, no writes."""
from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_identity_readiness as r

ALIAS = "staradvs-staging.pages.dev"
RETURN = b'<html><a href="https://staging.staradvs.shadowops.dpdns.org/?shadowops=central">Star Adventures</a></html>'


def project():
    conf = lambda: {"fail_open": False,
                    "compatibility_flags": ["global_fetch_strictly_public"],
                    "env_vars": {}}
    return {
        "name": "staradvs-staging", "production_branch": "main",
        "subdomain": ALIAS, "domains": [ALIAS, r.pages.HOST],
        "deployment_configs": {"production": conf(), "preview": conf()},
        "canonical_deployment": {"url": "https://abc123." + ALIAS},
        "latest_deployment": {"url": "https://abc123." + ALIAS},
    }


def ready_project():
    obj = project()
    obj["deployment_configs"]["production"]["env_vars"] = {
        r.BINDING: {"type": "secret_text", "value": "MUST_NOT_PRINT"}
    }
    return obj


class Client:
    account = "f" * 32

    def __init__(self, instance=None, missing=False):
        self.instance = instance if instance is not None else project()
        self.missing = missing
        self.calls = []
        self.result_info = None
        self.second_deployments = None
        self.second_info = None
        self.extra_pages = {}
        self.deployments = [{"project_name": "staradvs-staging",
                             "url": "https://old123." + ALIAS,
                             "aliases": ["https://old-branch." + ALIAS]}]

    def request_with_info(self, path):
        if "/deployments?page=" in path:
            self.calls.append(("GET", path, None))
            page = int(path.rsplit("=", 1)[-1])
            if page == 2 and self.second_deployments is not None:
                return 200, copy.deepcopy(self.second_deployments), copy.deepcopy(self.second_info)
            if page in self.extra_pages:
                rows, meta = self.extra_pages[page]
                return 200, copy.deepcopy(rows), copy.deepcopy(meta)
            raise r.pages.AdmissionError("Cloudflare GET failed (HTTP 400)")
        status, rows = self.request("GET", path)
        return status, rows, copy.deepcopy(self.result_info)

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if method != "GET" or data is not None:
            raise AssertionError("Cutover inventory must never mutate Cloudflare")
        if path.startswith("/zones?"):
            return 200, [{"name": r.pages.ZONE, "id": "z" * 32}]
        if "/dns_records?" in path:
            return 200, [{"name": r.pages.HOST, "type": "CNAME",
                          "content": r.pages.TARGET, "proxied": True}]
        if path.endswith("/pages/projects/" + r.pages.PROJECT + "/deployments"):
            return 200, copy.deepcopy(self.deployments)
        if path.endswith("/pages/projects/" + r.pages.PROJECT):
            return (404, None) if self.missing else (200, copy.deepcopy(self.instance))
        if path.endswith("/domains/" + r.pages.HOST):
            return (404, None) if self.missing else (
                200, {"name": r.pages.HOST, "status": "active"})
        raise AssertionError("Unexpected Cloudflare path: " + path)


def public(url, method):
    if url == r.ISSUER + "/login?app=staradvs":
        return 200, RETURN
    if url.startswith("https://staging.staradvs.shadowops.dpdns.org/"):
        return 401, b""
    if url.endswith(".pages.dev/") or ".pages.dev/" in url:
        return 404, b""
    raise AssertionError("Unexpected public URL " + url)


class CutoverReadinessTests(unittest.TestCase):
    def test_prepared_current_hosts_never_certify_incomplete_history(self):
        cf = Client(ready_project())
        result = r.collect(cf, public)
        self.assertFalse(result["next_gate_ready"])
        self.assertIs(result["historical_inventory_complete"], False)
        self.assertIs(result["can_activate"], False)
        self.assertEqual(result["signed_in_e2e"], "not-performed")
        self.assertEqual(result["pages_app_proof"], "bound")
        self.assertEqual(result["identity_login"], "audience-recognized")
        self.assertEqual(result["pages_alias_guest"], "denied-404")
        self.assertEqual(result["pages_historical_guest"], "sample-denied-404")
        self.assertEqual(result["historical_deployments_scanned"], 1)
        self.assertEqual(result["historical_aliases_scanned"], 2)
        self.assertNotIn("MUST_NOT_PRINT", json.dumps(result))
        self.assertTrue(all(method == "GET" and data is None for method, _, data in cf.calls))

    def test_current_static_public_200_is_an_exposure_not_a_green_signin(self):
        cf = Client(ready_project())
        def static_probe(url, method):
            if url.startswith(r.ISSUER):
                return 200, RETURN
            if ".pages.dev" in url or url.startswith("https://" + r.pages.HOST):
                return 200, b"game"
            return 0, b""
        state = r.collect(cf, static_probe)
        self.assertFalse(state["next_gate_ready"])
        self.assertEqual(state["canonical_guest"], "anonymous-content-observed")
        self.assertEqual(state["pages_alias_guest"], "anonymous-content-observed")
        self.assertEqual(state["pages_historical_guest"], "anonymous-content-observed")

    def test_missing_proof_policy_or_login_never_approves_cutover(self):
        variations = [
            (project(), public, "pages_app_proof"),
            (ready_project(), lambda url, method: (400, b"") if url.startswith(r.ISSUER) else public(url, method), "identity_login"),
        ]
        for obj, probe, key in variations:
            with self.subTest(key=key):
                state = r.collect(Client(obj), probe)
                self.assertFalse(state["next_gate_ready"])
                self.assertNotIn(state[key], ("bound", "audience-recognized"))
        self.assertFalse(r.collect(Client(ready_project(), missing=True), public)["next_gate_ready"])

    def test_reject_foreign_or_untrusted_deployment_aliases(self):
        for url in ("https://not-staradvs.pages.dev",
                    "http://abc123.staradvs-staging.pages.dev",
                    "https://abc123.staradvs-staging.pages.dev.evil.test",
                    "https://abc123.staradvs-staging.pages.dev/?x=1",
                    "https://abc123.staradvs-staging.pages.dev:8443/"):
            with self.subTest(url=url):
                p = ready_project()
                p["latest_deployment"]["url"] = url
                with self.assertRaises(r.CutoverBlocked):
                    r.alias_hosts(p)
        p = ready_project()
        p["domains"].append("foreign.example")
        with self.assertRaises(r.CutoverBlocked):
            r.pages_posture(p)

    def test_any_missing_security_property_is_not_ready(self):
        for change in ("fail-open", "compat", "proof-type", "other-binding"):
            with self.subTest(change=change):
                p = ready_project()
                prod = p["deployment_configs"]["production"]
                if change == "fail-open":
                    prod["fail_open"] = True
                elif change == "compat":
                    p["deployment_configs"]["preview"]["compatibility_flags"] = []
                elif change == "proof-type":
                    prod["env_vars"][r.BINDING]["type"] = "plain_text"
                else:
                    prod["env_vars"]["FOREIGN_SECRET"] = {"type": "secret_text"}
                state = r.collect(Client(p), public)
                self.assertFalse(state["next_gate_ready"])


    def test_historical_alias_exposure_blocks_even_when_current_alias_is_closed(self):
        cf = Client(ready_project())
        def guest(url, method):
            if url.startswith(r.ISSUER):
                return 200, RETURN
            if "old123." + ALIAS in url:
                return 200, b"old public build"
            return public(url, method)
        state = r.collect(cf, guest)
        self.assertFalse(state["next_gate_ready"])
        self.assertEqual(state["canonical_guest"], "denied-401")
        self.assertEqual(state["pages_alias_guest"], "denied-404")
        self.assertEqual(state["pages_historical_guest"], "anonymous-content-observed")

    def test_historical_sample_uses_known_working_bare_get_and_never_claims_complete(self):
        cf = Client(ready_project())
        cf.deployments = [{"project_name": r.pages.PROJECT,
                           "url": f"https://history{i}.{ALIAS}", "aliases": []}
                          for i in range(51)]
        hosts, count, total = r.historical_alias_hosts(cf, ready_project())
        self.assertEqual((len(hosts), count, total), (51, 51, None))
        self.assertEqual(
            [path for method, path, _ in cf.calls if "/deployments" in path],
            [f"/accounts/{cf.account}/pages/projects/{r.pages.PROJECT}/deployments"])
        cf.deployments += [{"project_name": r.pages.PROJECT,
                            "url": f"https://history{i}.{ALIAS}", "aliases": []}
                           for i in range(51, 70)]
        with self.assertRaisesRegex(r.CutoverBlocked, "bounded probe"):
            r.historical_alias_hosts(cf, ready_project())
        cf.deployments = []
        self.assertEqual(r.historical_alias_hosts(cf, ready_project()), ([], 0, None))
        self.assertFalse(r.collect(cf, public)["next_gate_ready"])

    def test_cloudflare_total_count_is_observable_but_not_release_authorization(self):
        cf = Client(ready_project())
        cf.result_info = {"page": 1, "per_page": 25, "count": 1, "total_count": 137}
        hosts, count, total = r.historical_alias_hosts(cf, ready_project())
        self.assertEqual((len(hosts), count, total), (2, 1, 137))
        report = r.collect(cf, public)
        self.assertEqual(report["historical_deployments_reported_total"], 137)
        self.assertEqual(report["historical_deployments_scanned"], 1)
        self.assertFalse(report["historical_inventory_complete"])
        self.assertFalse(report["next_gate_ready"])
        cf.result_info["total_count"] = 1
        self.assertFalse(r.collect(cf, public)["next_gate_ready"])

    def test_malformed_provider_pagination_rejected_without_secret_output(self):
        cf = Client(ready_project())
        for meta in ([], {"total_count": -1},
                     {"total_count": True, "page": 1, "count": 1, "per_page": 25},
                     {"total_count": 0, "page": 1, "count": 1, "per_page": 25},
                     {"total_count": 1, "page": 2, "count": 1, "per_page": 25},
                     {"total_count": 1, "page": 1, "count": 2, "per_page": 25},
                     {"total_count": 1, "page": 1, "count": 1, "per_page": 0}):
            with self.subTest(meta=meta):
                cf.result_info = meta
                with self.assertRaises(r.CutoverBlocked):
                    r.historical_alias_hosts(cf, ready_project())
        cf.result_info = {"page": 1, "count": 1, "per_page": 25}
        self.assertIsNone(r.collect(cf, public)["historical_deployments_reported_total"])

    def test_page2_only_canary_indexed_distinct_hosts_never_certifies_coverage(self):
        cf = Client(ready_project())
        cf.result_info = {"page": 1, "count": 1, "per_page": 25, "total_count": 114}
        cf.second_deployments = [{"project_name": r.pages.PROJECT,
                                  "url": "https://secondpage." + ALIAS, "aliases": []}]
        cf.second_info = {"page": 2, "count": 1, "per_page": 25, "total_count": 114}
        state = r.collect(cf, public)
        self.assertEqual(state["historical_page2_status"], "distinct-page-observed")
        self.assertEqual(state["historical_page2_deployments_indexed"], 1)
        self.assertEqual(state["historical_page2_aliases_indexed"], 1)
        self.assertEqual(state["historical_deployments_scanned"], 2)
        self.assertEqual(state["historical_pages_scanned"], 2)
        self.assertFalse(state["historical_inventory_complete"])
        self.assertFalse(state["next_gate_ready"])
        self.assertTrue(any(path.endswith("/deployments?page=2")
                            for _, path, _ in cf.calls))
        self.assertFalse(any("per_page=" in path for _, path, _ in cf.calls
                             if "/deployments" in path))

    def test_page2_provider_failure_stays_pending_with_page1_evidence(self):
        cf = Client(ready_project())
        cf.result_info = {"page": 1, "count": 1, "per_page": 25, "total_count": 114}
        state = r.collect(cf, public)
        self.assertEqual(state["historical_page2_status"], "provider-unavailable")
        self.assertEqual(state["historical_deployments_scanned"], 1)
        self.assertEqual(state["historical_deployments_reported_total"], 114)
        self.assertFalse(state["next_gate_ready"])

    def test_page2_same_results_and_foreign_urls_never_advance_cutover(self):
        cf = Client(ready_project())
        cf.result_info = {"page": 1, "count": 1, "per_page": 25, "total_count": 114}
        cf.second_deployments = copy.deepcopy(cf.deployments)
        cf.second_info = {"page": 2, "count": 1, "per_page": 25, "total_count": 114}
        self.assertEqual(r.collect(cf, public)["historical_page2_status"], "repeated-first-page")
        cf.second_deployments[0]["url"] = "https://malicious.example"
        with self.assertRaisesRegex(r.CutoverBlocked, "Foreign historical"):
            r.collect(cf, public)
        with self.assertRaisesRegex(r.CutoverBlocked, "Unapproved"):
            r.historical_alias_hosts(cf, ready_project(), page=9)

    def test_all_reported_pages_can_be_probed_without_certifying_access(self):
        cf = Client(ready_project())
        cf.deployments = [
            {"project_name": r.pages.PROJECT,
             "url": f"https://first{i}.{ALIAS}", "aliases": []}
            for i in range(25)
        ]
        cf.result_info = {"page": 1, "count": 25, "per_page": 25, "total_count": 64}
        cf.second_deployments = [
            {"project_name": r.pages.PROJECT,
             "url": f"https://second{i}.{ALIAS}", "aliases": []}
            for i in range(25)
        ]
        cf.second_info = {"page": 2, "count": 25, "per_page": 25, "total_count": 64}
        cf.extra_pages[3] = ([
            {"project_name": r.pages.PROJECT,
             "url": f"https://third{i}.{ALIAS}", "aliases": []}
            for i in range(14)
        ], {"page": 3, "count": 14, "per_page": 25, "total_count": 64})
        observed = []
        def probe(url, method):
            # Login, canonical and alias response mocks; do not fetch real pages.
            observed.append((url, method))
            return public(url, method)
        result = r.collect(cf, probe)
        self.assertEqual(result["historical_deployments_scanned"], 64)
        self.assertEqual(result["historical_aliases_scanned"], 64)
        self.assertEqual(result["historical_pages_scanned"], 3)
        self.assertEqual(result["historical_enumeration_status"], "reported-total-observed")
        self.assertFalse(result["historical_inventory_complete"])
        self.assertFalse(result["next_gate_ready"])
        self.assertEqual(result["pages_historical_guest"], "sample-denied-404")
        self.assertTrue(any("third0." in url for url, _ in observed))
        self.assertTrue(all(method == "GET" for method, _, _ in cf.calls))
        self.assertFalse(any("per_page=" in path for _, path, _ in cf.calls
                             if "/deployments" in path))

    def test_interrupted_later_page_preserves_previously_verified_exposure(self):
        cf = Client(ready_project())
        cf.result_info = {"page": 1, "count": 1, "per_page": 25, "total_count": 114}
        cf.second_deployments = [{"project_name": r.pages.PROJECT,
                                  "url": "https://second." + ALIAS, "aliases": []}]
        cf.second_info = {"page": 2, "count": 1, "per_page": 25, "total_count": 114}
        def exposed(url, method):
            if url.startswith(r.ISSUER):
                return 200, RETURN
            if "second." + ALIAS in url:
                return 200, b"old game"
            return public(url, method)
        state = r.collect(cf, exposed)
        self.assertEqual(state["historical_enumeration_status"], "provider-unavailable")
        self.assertEqual(state["historical_deployments_scanned"], 2)
        self.assertEqual(state["pages_historical_guest"], "anonymous-content-observed")
        self.assertFalse(state["historical_inventory_complete"])

    def test_full_enumerator_rejects_repeated_or_foreign_later_pages(self):
        cf = Client(ready_project())
        cf.result_info = {"page": 1, "count": 1, "per_page": 25, "total_count": 5}
        cf.second_deployments = [{"project_name": r.pages.PROJECT,
                                  "url": "https://second." + ALIAS, "aliases": []}]
        cf.second_info = {"page": 2, "count": 1, "per_page": 25, "total_count": 5}
        cf.extra_pages[3] = (copy.deepcopy(cf.deployments),
                             {"page": 3, "count": 1, "per_page": 25, "total_count": 5})
        state = r.collect(cf, public)
        self.assertEqual(state["historical_enumeration_status"], "repeated-first-page")
        self.assertFalse(state["next_gate_ready"])
        cf.extra_pages[3] = ([{"project_name": r.pages.PROJECT,
                              "url": "https://foreign.example", "aliases": []}],
                             {"page": 3, "count": 1, "per_page": 25, "total_count": 5})
        with self.assertRaisesRegex(r.CutoverBlocked, "Foreign historical"):
            r.collect(cf, public)

    def test_deployment_list_permission_denial_is_pending_not_green_or_a_ci_crash(self):
        class DeniedListClient(Client):
            def request(self, method, path, data=None):
                if path.endswith("/deployments"):
                    raise r.pages.AdmissionError("Cloudflare GET failed (HTTP 403)")
                return super().request(method, path, data)
        state = r.collect(DeniedListClient(ready_project()), public)
        self.assertFalse(state["next_gate_ready"])
        self.assertIs(state["can_activate"], False)
        self.assertEqual(state["pages_historical_guest"], "inventory-unavailable")
        self.assertFalse(state["historical_inventory_complete"])
        self.assertEqual(state["historical_aliases_scanned"], 0)

    def test_historical_inventory_foreign_alias_and_unreachable_are_not_ready(self):
        cf = Client(ready_project())
        cf.deployments[0]["aliases"] = ["https://evil.example"]
        with self.assertRaises(r.CutoverBlocked):
            r.historical_alias_hosts(cf, ready_project())
        cf.deployments[0]["aliases"] = ["https://old-branch." + ALIAS]
        self.assertEqual(r.history_guest_status(["old123." + ALIAS],
                         lambda url, method: (503, b"")), "unverified-or-unavailable")
        self.assertEqual(r.history_guest_status([]), "not-verified")

    def test_guest_counts_per_host_without_exposing_aliases(self):
        hosts = ["first." + ALIAS, "second." + ALIAS, "third." + ALIAS]
        def probe(url, method):
            if "first." in url:
                return (200 if url.endswith("/") else 404), b""
            if "second." in url:
                return 404, b""
            return 302, b""
        status, counts = r.history_guest_assessment(hosts, probe)
        self.assertEqual(status, "anonymous-content-observed")
        self.assertEqual(counts, {"exposed": 1, "denied": 1, "unverified": 1})
        self.assertNotIn(ALIAS, json.dumps(counts))
        self.assertEqual(r.history_guest_status(hosts, probe), status)
        self.assertEqual(r.history_guest_assessment([]), ("not-verified",
                         {"exposed": 0, "denied": 0, "unverified": 0}))

    def test_readiness_reports_count_totals_for_real_sample_paths(self):
        cf = Client(ready_project())
        def probe(url, method):
            if "old123." + ALIAS in url:
                return 200, b"old public game"
            return public(url, method)
        state = r.collect(cf, probe)
        self.assertEqual(state["historical_aliases_exposed"], 1)
        self.assertEqual(state["historical_aliases_denied"], 1)
        self.assertEqual(state["historical_aliases_unverified"], 0)
        self.assertEqual(sum(state["historical_aliases_" + suffix]
                             for suffix in ("exposed", "denied", "unverified")),
                         state["historical_aliases_scanned"])
        self.assertFalse(state["next_gate_ready"])

    def test_access_readonly_metadata_is_separate_from_guest_and_signin(self):
        class FakeAccess:
            account = "f" * 32
            def __init__(self, missing=None, fail=False):
                self.missing = missing
                self.fail = fail
                self.calls = []
            def get(self, path):
                self.calls.append(path)
                if self.fail:
                    raise r.access.ReadinessError("Sensitive provider message")
                hosts = ["staradvs-staging.pages.dev", "*.staradvs-staging.pages.dev",
                         "staging.staradvs.shadowops.dpdns.org"]
                apps = [
                    {"id": f"00000000-0000-4000-8000-{i:012d}", "type": "self_hosted",
                     "destinations": [{"type": "public", "uri": host}]}
                    for i, host in enumerate(hosts, 1) if host != self.missing
                ]
                if path.endswith("/access/apps"):
                    return {"result": apps, "result_info": {"page": 1,
                        "count": len(apps), "total_count": len(apps), "total_pages": 1}}
                if path.endswith("/policies"):
                    policies = [{"decision": "allow", "include": [
                        {"email": {"email": "operator@private.invalid"}}]}]
                    return {"result": policies, "result_info": {"page": 1,
                        "count": 1, "total_count": 1, "total_pages": 1}}
                raise AssertionError("Unexpected Access endpoint")
        client = FakeAccess()
        configured = r.collect(Client(ready_project()), public, access_client=client)
        self.assertEqual(configured["cloudflare_access"], "restricted-policy-candidate")
        self.assertEqual(len(client.calls), 4)
        self.assertTrue(all(v == "restricted-policy-candidate"
                            for v in configured["cloudflare_access_scopes"].values()))
        self.assertFalse(configured["next_gate_ready"])
        self.assertFalse(configured["can_activate"])
        self.assertNotIn("operator@private.invalid", json.dumps(configured))
        missing = r.collect(Client(ready_project()), public,
                            access_client=FakeAccess(missing="staradvs-staging.pages.dev"))
        self.assertEqual(missing["cloudflare_access"], "remediation-required")
        self.assertEqual(missing["cloudflare_access_scopes"]["main"], "missing")
        error = r.collect(Client(ready_project()), public,
                          access_client=FakeAccess(fail=True))
        self.assertEqual(error["cloudflare_access"], "inventory-unavailable")
        self.assertFalse(error["next_gate_ready"])
        self.assertNotIn("Sensitive provider message", json.dumps(error))

    def test_workflow_is_read_only_never_admits_a_cloud_write(self):
        path = ROOT / ".github/workflows/staradvs-identity-readiness.yml"
        flow = path.read_text()
        self.assertIn("staradvs_identity_readiness.py inspect", flow)
        self.assertIn("github.event_name == 'push'", flow)
        self.assertIn("github.ref == 'refs/heads/main'", flow)
        self.assertIn("environment:", flow)
        self.assertIn("test_staradvs_identity_readiness.py", flow)
        self.assertIn("CLOUDFLARE_ACCESS_READ_TOKEN", flow)
        self.assertNotIn("CLOUDFLARE_ACCESS_WRITE_TOKEN", flow)
        self.assertNotIn("pages deploy", flow)
        self.assertNotIn("wrangler", flow)
        self.assertNotIn("secrets.SOC", flow)
        self.assertNotIn("provision", flow.lower())


if __name__ == "__main__":
    unittest.main()
