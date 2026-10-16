"""Mocked Cloudflare custody observation; never mutate a real account."""
import pathlib
import sys
import unittest
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import cloudflare_control_plane as c


class FakeCF:
    account = "test-account"

    def __init__(self, *, missing_zone=False, duplicate_dns=False, missing_tunnel=False,
                 missing_chess_pages=False, bad_branch=False):
        self.calls = []
        self.missing_zone = missing_zone
        self.duplicate_dns = duplicate_dns
        self.missing_tunnel = missing_tunnel
        self.missing_chess_pages = missing_chess_pages
        self.bad_branch = bad_branch

    def get(self, path, *, allow_missing=False):
        self.calls.append(path)
        if path.startswith("/zones?"):
            return 200, [] if self.missing_zone else [{"name": c.ZONE, "id": "test-zone"}]
        if path.startswith("/zones/test-zone/dns_records?"):
            host = parse_qs(urlparse(path).query)["name"][0]
            if host.startswith(("staging.chess-studio.", "api-staging.chess-studio.")):
                row = {"name": host, "type": "CNAME", "proxied": True}
                return 200, [row, row] if self.duplicate_dns else [row]
            return 200, []
        if "/cfd_tunnel?" in path:
            return 200, [] if self.missing_tunnel else [{"name": c.TUNNEL, "id": "tunnel-test"}]
        if "/pages/projects/chess-studio-staging/domains/" in path:
            return 200, {"name": c.PROJECTS["chess-studio-staging"], "status": "active"}
        if path.endswith("/pages/projects/chess-studio-staging"):
            if self.missing_chess_pages:
                raise c.InventoryError("existing Pages project missing")
            return 200, {"name": "chess-studio-staging",
                         "production_branch": "dev" if self.bad_branch else "main"}
        if path.endswith("/pages/projects/chronicles-staging"):
            self.assert_missing_allowed(allow_missing)
            return 404, None
        raise AssertionError("Unexpected CF request " + path)

    def assert_missing_allowed(self, value):
        assert value is True


class CloudflareInventoryTests(unittest.TestCase):
    def test_existing_chess_resources_and_pending_chronicles(self):
        f = FakeCF()
        result = c.inspect(f)
        self.assertEqual(result["tunnel:chess-studio-staging"], "present")
        self.assertEqual(result["pages:chess-studio-staging"], "active")
        self.assertEqual(result["pages:chronicles-staging"], "pending")
        self.assertEqual(result["dns:staging.chronicles.shadowops.dpdns.org"], "absent")
        self.assertEqual(len(f.calls), len(c.HOSTS) + len(c.PROJECTS) + 3)

    def test_fails_closed_on_ambiguous_or_invalid_resources(self):
        for change in (
            {"missing_zone": True}, {"duplicate_dns": True}, {"missing_tunnel": True},
            {"missing_chess_pages": True}, {"bad_branch": True},
        ):
            with self.subTest(change=change):
                with self.assertRaises(c.InventoryError):
                    c.inspect(FakeCF(**change))

    def test_no_control_plane_mutators(self):
        source = pathlib.Path(c.__file__).read_text()
        for operation in ('method="POST"', 'method="PUT"', 'method="PATCH"', 'method="DELETE"',
                          "terraform apply", "subprocess.run(", "gh secret", "ssh -i"):
            self.assertNotIn(operation, source)

    def test_missing_secret_cannot_authenticate(self):
        for env in ({}, {"CLOUDFLARE_API_TOKEN": "test"}, {"CLOUDFLARE_ACCOUNT_ID": "test"}):
            with self.assertRaises(c.InventoryError):
                c.CloudflareReadClient(env)


if __name__ == "__main__":
    unittest.main()
