"""Mocked, no-network observation contract for the Chronicles R2 bucket."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_r2_cache_probe as r2


class FakeCloudflare:
    account = "test-account"

    def __init__(self, domains):
        self.domains = domains
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        assert path == "/accounts/test-account/r2/buckets/chronicles/domains/custom"
        return 200, {"domains": self.domains}


DOMAIN = {"domain": "assets.chronicles.shadowops.dpdns.org", "enabled": True,
          "status": {"ownership": "active", "ssl": "active"}}


class R2CacheProbeTests(unittest.TestCase):
    def test_public_https_origin_and_cors(self):
        urls = []

        def head(url):
            urls.append(url)
            return 200, {"content-type": "image/webp", "access-control-allow-origin": "*",
                         "cache-control": "public, max-age=14400"}

        cf = FakeCloudflare([DOMAIN])
        result = r2.inspect(cf, head)
        self.assertEqual(result["asset"], "ok")
        self.assertEqual(result["cors"], "ok")
        self.assertEqual(result["cache"], "mutable-safe")
        self.assertEqual(urls, ["https://assets.chronicles.shadowops.dpdns.org/sprites/ash-goblin.webp"])
        self.assertEqual(len(cf.paths), 1)

    def test_no_public_domain_never_guesses_r2_dev(self):
        result = r2.inspect(FakeCloudflare([]), lambda _: self.fail("unexpected HEAD"))
        self.assertEqual(result, {"domain": "pending", "asset": "unverified"})

    def test_inactive_domain_is_not_public_evidence(self):
        result = r2.inspect(FakeCloudflare([{**DOMAIN, "enabled": False}]),
                            lambda _: self.fail("unexpected HEAD"))
        self.assertEqual(result["domain"], "pending")

    def test_foreign_ambiguous_and_malformed_domain_fails_closed(self):
        for domains in (
            [DOMAIN, DOMAIN],
            [{**DOMAIN, "domain": "external.example.org"}],
            [{"enabled": True, "domain": DOMAIN["domain"]}],
            [{"enabled": True}],
        ):
            with self.subTest(domains=domains):
                with self.assertRaises(r2.InventoryError):
                    r2.inspect(FakeCloudflare(domains), lambda _: self.fail("unexpected HEAD"))

    def test_detects_bad_mime_cors_unsafe_mutable_ttl_and_404(self):
        cf = FakeCloudflare([DOMAIN])
        result = r2.inspect(cf, lambda _: (200, {
            "content-type": "text/html",
            "cache-control": "public, max-age=31536000, immutable",
        }))
        self.assertEqual(result["asset"], "wrong-content-type")
        self.assertEqual(result["cors"], "missing-or-denied")
        self.assertEqual(result["cache"], "unsafe-immutable-mutable-key")
        self.assertEqual(r2.inspect(cf, lambda _: (404, {}))["asset"], "http-404")

    def test_probe_does_not_mutate_cloudflare(self):
        source = pathlib.Path(r2.__file__).read_text()
        for operation in ('method="POST"', 'method="PUT"', 'method="PATCH"',
                          'method="DELETE"', "terraform apply", "subprocess.run"):
            self.assertNotIn(operation, source)


if __name__ == "__main__":
    unittest.main()
