import sys
import unittest
from unittest.mock import patch
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_staging_publish as pub
import snooker_pages_readiness as readiness
from snooker_pages_provision import ProvisionError

ACCOUNT = "a"*32
P = f"/accounts/{ACCOUNT}/pages/projects/{readiness.PROJECT}"
ZONE = "/zones?" + urlencode({"name": readiness.ZONE, "account.id": ACCOUNT})
DNS = "/zones/z-one/dns_records?" + urlencode({"name": readiness.HOST, "per_page": 100})
DOM = P + "/domains/" + readiness.HOST
PROOF = "soc1_" + "Q"*43

class Fake:
    account = ACCOUNT
    def __init__(self, *, private=True, unknown_binding=False):
        flags = ["global_fetch_strictly_public"]
        self.project = {
            "name": readiness.PROJECT, "production_branch": "main",
            "subdomain": "snooker-staging.pages.dev", "source": None, "domains": [],
            "latest_deployment": {"url": "https://release.snooker-staging.pages.dev"},
            "canonical_deployment": {"url": "https://snooker-staging.pages.dev"},
            "deployment_configs": {
                "production": {"fail_open": not private, "compatibility_flags": flags,
                               "env_vars": {"UNKNOWN": {"type": "plain_text"}} if unknown_binding else {}},
                "preview": {"fail_open": False, "compatibility_flags": flags,
                            "env_vars": {}},
            },
        }
        self.domain = None
        self.dns = []
        self.writes = []

    def get(self, path):
        if path == ZONE: return [{"name": readiness.ZONE, "id": "z-one"}]
        if path == P: return self.project
        if path == DOM: return self.domain
        if path == DNS: return list(self.dns)
        raise AssertionError(path)

    def write(self, method, path, value):
        self.writes.append((method, path))
        if method == "PATCH":
            production = value["deployment_configs"]["production"]
            if set(production) != {"env_vars"}:
                raise AssertionError("Secret binding must PATCH only its single env var")
            if set(production["env_vars"]) != {pub.KEY}:
                raise AssertionError("Only the dedicated Snooker credential may be bound")
            self.project["deployment_configs"]["production"]["env_vars"] = production["env_vars"]
            return self.project
        if path == P + "/domains":
            self.domain = {"name": readiness.HOST, "status": "active"}
            self.project["domains"] = [readiness.HOST, "snooker-staging.pages.dev"]
            return self.domain
        if path == "/zones/z-one/dns_records":
            self.dns.append({"name": readiness.HOST, "type": "CNAME", "proxied": True,
                             "content": "snooker-staging.pages.dev"})
            return self.dns[0]
        raise AssertionError(path)

class PublishTests(unittest.TestCase):
    def test_isolated_proof_only_binds_to_private_production(self):
        cloud = Fake()
        pub.bind(cloud, PROOF)
        self.assertEqual(cloud.writes, [("PATCH", P)])
        cfg = cloud.project["deployment_configs"]
        self.assertEqual(set(cfg["production"]["env_vars"]), {pub.KEY})
        self.assertEqual(cfg["preview"]["env_vars"], {})
        self.assertIs(cfg["production"]["fail_open"], False)

    def test_binding_block_preflight_reports_only_fixed_stage(self):
        for cloud, stage in (
            (Fake(private=False), "preflight-project"),
            (Fake(unknown_binding=True), "preflight-production-vars"),
        ):
            with self.subTest(stage=stage), self.assertRaises(pub.BindingBlocked) as ctx:
                pub.bind(cloud, PROOF)
            self.assertEqual(ctx.exception.stage, stage)
            self.assertEqual(cloud.writes, [])
            self.assertNotIn(PROOF, str(ctx.exception))

    def test_binding_cloudflare_http_error_reports_safe_status_not_response(self):
        class Rejected(Fake):
            def write(self, method, path, value):
                self.writes.append((method, path))
                raise ProvisionError("Cloudflare write rejected (HTTP 400)")
        cloud = Rejected()
        with self.assertRaises(pub.BindingBlocked) as ctx:
            pub.bind(cloud, PROOF)
        self.assertEqual(ctx.exception.stage, "patch-http-400")
        self.assertEqual(cloud.writes, [("PATCH", P)])
        self.assertNotIn(PROOF, str(ctx.exception))

    def test_provider_numeric_code_is_bounded_and_secret_free(self):
        from snooker_pages_provision import safe_provider_code
        self.assertEqual(
            safe_provider_code(b'{"errors":[{"code":8000013,"message":"secret=VERY_SECRET"}]}'),
            "8000013",
        )
        for raw in (b'{"errors":[{"code":false}]}',
                    b'{"errors":[{"code":"8000013"}]}',
                    b'{"errors":[{"code":1},{"code":2}]}',
                    b'{"errors":[{"code":0}]}',
                    b'{"errors":[{"code":1000000000}]}',
                    b'secret=VERY_SECRET'):
            with self.subTest(raw=raw):
                self.assertIsNone(safe_provider_code(raw))

        class Rejected(Fake):
            def write(self, method, path, value):
                raise ProvisionError("Cloudflare write rejected (HTTP 400) API 8000013")
        with self.assertRaises(pub.BindingBlocked) as ctx:
            pub.bind(Rejected(), PROOF)
        self.assertEqual(ctx.exception.stage, "patch-http-400")
        self.assertEqual(ctx.exception.provider_code, "8000013")
        self.assertNotIn(PROOF, str(ctx.exception))

    def test_binding_unknown_provider_error_is_redacted(self):
        class Rejected(Fake):
            def write(self, method, path, value):
                raise ProvisionError("password=VERY_SECRET")
        with self.assertRaises(pub.BindingBlocked) as ctx:
            pub.bind(Rejected(), PROOF)
        self.assertEqual(ctx.exception.stage, "patch-rejected")
        self.assertNotIn("VERY_SECRET", str(ctx.exception))

    def test_binding_postpatch_inventory_is_verified(self):
        class BadConvergence(Fake):
            def write(self, method, path, value):
                self.writes.append((method, path))
                # Simulate a provider claiming success without persisting
                # the isolated secret; no deployment may follow.
                return self.project
        cloud = BadConvergence()
        with self.assertRaises(pub.BindingBlocked) as ctx:
            pub.bind(cloud, PROOF)
        self.assertEqual(ctx.exception.stage, "postpatch-binding")
        self.assertEqual(cloud.writes, [("PATCH", P)])

    def test_unknown_binding_or_fail_open_denies_without_writes(self):
        for cloud in (Fake(private=False), Fake(unknown_binding=True)):
            with self.subTest(cloud=cloud.__dict__), self.assertRaises(ProvisionError):
                pub.bind(cloud, PROOF)
            self.assertEqual(cloud.writes, [])
        with self.assertRaises(ProvisionError):
            pub.bind(Fake(), "soc1_not-a-real-proof")

    def test_domain_creation_denies_public_alias_and_requires_bound_proof(self):
        cloud = Fake()
        with self.assertRaises(ProvisionError):
            pub.attach_domain(cloud, lambda _:404)
        self.assertEqual(cloud.writes, [])
        pub.bind(cloud, PROOF)
        cloud.writes.clear()
        with self.assertRaises(ProvisionError):
            pub.attach_domain(cloud, lambda _:200)
        self.assertEqual(cloud.writes, [])
        pub.attach_domain(cloud, lambda _:404)
        self.assertEqual(cloud.writes, [("POST", P+"/domains"), ("POST", "/zones/z-one/dns_records")])
        cloud.writes.clear()
        pub.attach_domain(cloud, lambda _:404)
        self.assertEqual(cloud.writes, [])

    def test_foreign_dns_can_never_be_overwritten(self):
        cloud = Fake()
        pub.bind(cloud, PROOF)
        cloud.writes.clear()
        cloud.dns = [{"name": readiness.HOST, "type": "CNAME", "proxied": True,
                      "content": "foreign.pages.dev"}]
        with self.assertRaises((readiness.InventoryError, ProvisionError)):
            pub.attach_domain(cloud, lambda _:404)
        self.assertEqual(cloud.writes, [])

    def test_issuer_login_must_advertise_exact_snooker_origin(self):
        pub.issuer_ready(lambda _: b"ready https://staging.snooker.shadowops.dpdns.org/?shadowops=central")
        for body in (b"login football", b"redirect https://staging.snooker.shadowops.dpdns.org.evil/"):
            with self.assertRaises(ProvisionError):
                pub.issuer_ready(lambda _:body)

    def test_guest_smoke_requires_both_alias_and_custom_host_denial(self):
        aliases = pub.actual_alias_hosts(Fake().project)
        self.assertEqual(set(aliases), {"snooker-staging.pages.dev", "release.snooker-staging.pages.dev"})
        pub.smoke_guest(lambda u:404 if "pages.dev" in u else 401, aliases=aliases)
        with self.assertRaises(ProvisionError):
            pub.smoke_guest(lambda u:200, aliases=aliases)
        with self.assertRaises(ProvisionError):
            pub.smoke_guest(lambda u:404)

    def test_guest_http_probe_preserves_redirect_status_without_following_location(self):
        class RedirectResponse:
            def open(self, request, timeout):
                self.assertion_url = request.full_url
                self.assertion_timeout = timeout
                # Cloudflare's actual 302 must be observed as 302; a default
                # urllib opener would follow Location and often report 200.
                raise pub.urllib.error.HTTPError(
                    request.full_url, 302, "Found",
                    {"Location": "https://unexpected.example/login"}, None)

        opener = RedirectResponse()
        url = "https://" + readiness.HOST + "/"
        with patch.object(pub.urllib.request, "build_opener", return_value=opener) as make:
            self.assertEqual(pub.probe(url), 302)
        self.assertEqual(opener.assertion_url, url)
        self.assertEqual(opener.assertion_timeout, 15)
        handler = make.call_args.args[0]
        self.assertIsInstance(handler, pub._NoRedirect)
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {},
                                                   "https://unexpected.example/login"))

    def test_redirected_login_is_a_guest_denial_failure_not_success(self):
        aliases = pub.actual_alias_hosts(Fake().project)
        status = lambda url: 404 if "pages.dev" in url else 302
        with self.assertRaises(pub.GuestDenialBlocked) as captured:
            pub.smoke_guest(status, aliases=aliases)
        self.assertEqual(captured.exception.stage, "custom-root")
        self.assertEqual(captured.exception.observed, "302")

    def test_guest_failure_reports_exact_route_class_and_only_http_status(self):
        aliases = pub.actual_alias_hosts(Fake().project)
        cases = [
            (lambda u: 200 if "pages.dev" in u and u.endswith("/") else
                (404 if "pages.dev" in u else 401), "alias-root", "200"),
            (lambda u: 404 if "pages.dev" in u or u.endswith("/") else 401,
                "custom-root", "404"),
            (lambda u: 404 if "pages.dev" in u else
                (503 if "/assets/" in u else 401), "custom-asset", "503"),
        ]
        for probe, stage, observed in cases:
            with self.subTest(stage=stage), self.assertRaises(pub.GuestDenialBlocked) as ctx:
                pub.smoke_guest(probe, aliases=aliases)
            self.assertEqual(ctx.exception.stage, stage)
            self.assertEqual(ctx.exception.observed, observed)
            self.assertNotIn("https://", str(ctx.exception))

    def test_guest_transport_failure_is_bounded_and_redacted(self):
        def unavailable(_):
            raise pub.ProvisionError("PRIVATE_DNS_OR_CREDENTIAL")
        with self.assertRaises(pub.GuestDenialBlocked) as ctx:
            pub.smoke_guest(unavailable, aliases=["snooker-staging.pages.dev"])
        self.assertEqual(ctx.exception.stage, "alias-root")
        self.assertEqual(ctx.exception.observed, "unavailable")
        self.assertNotIn("PRIVATE", str(ctx.exception))

    def test_guest_audit_is_read_only_for_existing_domain(self):
        cloud = Fake()
        pub.bind(cloud, PROOF)
        cloud.writes.clear()
        cloud.domain = {"name": readiness.HOST, "status": "active"}
        cloud.dns = [{"name": readiness.HOST, "type": "CNAME", "proxied": True,
                      "content": "snooker-staging.pages.dev"}]
        # The publicly observable smoke only invokes read_status.
        pub.smoke_guest(lambda url: 404 if "pages.dev" in url else 401,
                        aliases=pub.actual_alias_hosts(pub.require_private(cloud)))
        self.assertEqual(cloud.writes, [])


    def test_canonical_production_release_matches_exact_main_sha_without_writes(self):
        source_sha = "a" * 40
        cloud = Fake()
        production = cloud.project["canonical_deployment"]
        production.update({
            "environment": "production", "is_skipped": False,
            "latest_stage": {"status": "success"},
            "deployment_trigger": {
                "type": "ad_hoc",
                "metadata": {"branch": "main", "commit_dirty": False,
                             "commit_hash": source_sha},
            },
        })
        # A newer preview must never be mistaken for production.
        cloud.project["latest_deployment"]["deployment_trigger"] = {
            "type": "ad_hoc",
            "metadata": {"branch": "preview", "commit_dirty": False,
                         "commit_hash": "b" * 40},
        }
        self.assertEqual(pub.audit_canonical_release(cloud, source_sha), source_sha)
        self.assertEqual(cloud.writes, [], "release audit performs no Cloudflare writes")

    def test_canonical_release_audit_identifies_stale_or_ambiguous_production(self):
        source_sha = "a" * 40
        for variant, stage in (
            ("missing", "canonical-missing"),
            ("preview", "canonical-invalid"),
            ("dirty", "canonical-invalid"),
            ("failed", "canonical-invalid"),
            ("unrecognized", "canonical-invalid"),
            ("badsha", "canonical-invalid"),
            ("stale", "source-mismatch"),
        ):
            cloud = Fake()
            candidate = {
                "environment": "production", "is_skipped": False,
                "latest_stage": {"status": "success"},
                "deployment_trigger": {"type": "ad_hoc", "metadata": {
                    "branch": "main", "commit_dirty": False, "commit_hash": source_sha,
                }},
            }
            if variant == "missing":
                cloud.project["canonical_deployment"] = None
            else:
                if variant == "preview": candidate["environment"] = "preview"
                if variant == "dirty": candidate["deployment_trigger"]["metadata"]["commit_dirty"] = True
                if variant == "failed": candidate["latest_stage"]["status"] = "failure"
                if variant == "unrecognized": candidate["deployment_trigger"]["type"] = "foreign"
                if variant == "badsha": candidate["deployment_trigger"]["metadata"]["commit_hash"] = "BAD"
                if variant == "stale": candidate["deployment_trigger"]["metadata"]["commit_hash"] = "b" * 40
                cloud.project["canonical_deployment"] = candidate
            with self.subTest(variant=variant), self.assertRaises(pub.ReleaseAlignmentBlocked) as error:
                pub.audit_canonical_release(cloud, source_sha)
            self.assertEqual(error.exception.stage, stage)
            self.assertEqual(error.exception.deployed_sha, "b" * 40 if variant == "stale" else None)
            self.assertEqual(cloud.writes, [])
            self.assertNotIn("https://", str(error.exception))

    def test_canonical_audit_rejects_bad_expected_sha_and_open_pages(self):
        for sha in ("", "main", "f" * 39, "F" * 40):
            with self.subTest(sha=sha), self.assertRaises(pub.ReleaseAlignmentBlocked):
                pub.audit_canonical_release(Fake(), sha)
        with self.assertRaises(ProvisionError):
            pub.audit_canonical_release(Fake(private=False), "a" * 40)

    def test_foreign_or_missing_deployment_alias_blocks_domain_writes(self):
        for candidate in ("https://foreign.pages.dev", "http://release.snooker-staging.pages.dev",
                          "https://release.snooker-staging.pages.dev.evil.test", None):
            cloud = Fake()
            pub.bind(cloud, PROOF)
            cloud.writes.clear()
            if candidate is None:
                cloud.project.pop("latest_deployment")
                cloud.project.pop("canonical_deployment")
            else:
                cloud.project["latest_deployment"]["url"] = candidate
            with self.subTest(candidate=candidate), self.assertRaises(ProvisionError):
                pub.attach_domain(cloud, lambda _:404)
            self.assertEqual(cloud.writes, [])
