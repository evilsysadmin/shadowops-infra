"""No protected launch if an old public GitHub Pages copy can be reached."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bridgesquad_legacy_pages_guard as guard


class PublicLegacyTests(unittest.TestCase):
    def test_disabled_pages_and_strict_public_404_permit_promotion(self):
        urls = []
        def public(url):
            urls.append(url)
            return 404, b"<title>Page not found</title>"
        result = guard.inspect(pages=lambda: (404, b'{"message":"Not Found"}'),
                               public=public)
        self.assertEqual(result["legacy_github_pages"], "disabled")
        self.assertEqual(tuple(urls), guard.ROUTES)

    def test_no_assumption_when_api_status_is_unknown_or_enabled(self):
        for status in (0, 200, 301, 302, 401, 403, 429, 500, 503):
            with self.subTest(status=status), self.assertRaises(guard.Refused):
                guard.inspect(pages=lambda: (status, b""),
                              public=lambda url: (404, b""))
        with self.assertRaises(guard.Refused):
            guard.inspect(pages=lambda: (404, b"X" * (guard.MAX + 1)),
                          public=lambda url: (404, b""))

    def test_still_public_even_under_redirect_or_200_and_404_html_leak(self):
        for status, body in ((200, b"game"),
                             (301, b""), (302, b""), (403, b""),
                             (503, b""), (404, b"<canvas>game</canvas>"),
                             (404, b"<title>Matthias Bridge Squad</title>"),
                             (404, b"SHADOWOPS.MBS.PROGRESS")):
            with self.subTest(status=status, body=body), self.assertRaises(guard.Refused):
                guard.inspect(pages=lambda: (404, b'{"message":"Not Found"}'),
                              public=lambda url: (status, body))

    def test_network_errors_fail_closed_and_no_unapproved_fetch(self):
        with self.assertRaises(guard.Refused):
            guard._read("https://example.org")
        with self.assertRaises(guard.Refused):
            guard._read(guard.API)
        with mock.patch.dict(guard.os.environ, {"GH_TOKEN": ""}):
            self.assertEqual(guard.main(["inspect"]), 1)
        self.assertEqual(guard.main(["wrong"]), 2)


if __name__ == "__main__":
    unittest.main()
