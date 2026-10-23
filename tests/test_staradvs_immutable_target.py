import hashlib
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_immutable_target as target
import staradvs_pages as pages

SHA = "a" * 40
PATH = "/assets/index-123.js"
JS = b'console.log("persistent old Pages deploy");'
ORIGIN = "https://facecafe.staradvs-staging.pages.dev"


def manifest(js=JS):
    return {
        "environment": "staging",
        "build": SHA,
        "entry_js": {"path": PATH, "sha256": hashlib.sha256(js).hexdigest()},
    }


def inspect(html=b'<script type="module" src="/assets/index-123.js"></script>',
            release=None, js=JS, url=ORIGIN):
    contents = {
        "/release.json": json.dumps(manifest() if release is None else release).encode(),
        "/": html,
        PATH: js,
    }
    def fake_get(origin, path, mime, maximum):
        if origin != ORIGIN or path not in contents:
            raise AssertionError("Unexpected or foreign network request")
        return contents[path]
    with patch.object(target, "fetch_bytes", side_effect=fake_get) as get:
        result = target.verify_immutable_target({"url": url}, SHA)
    return result, get.call_args_list


class ImmutableTargetContractTests(unittest.TestCase):
    def test_exact_sha_manifest_html_and_real_js_digest_must_agree(self):
        origin, calls = inspect()
        self.assertEqual(origin, ORIGIN)
        self.assertEqual([args.args[1] for args in calls], [
            "/release.json", "/", PATH,
        ])
        self.assertEqual([args.args[2] for args in calls], ["json", "html", "javascript"])

    def test_reject_mutable_aliases_foreign_hosts_redirects_and_url_injection(self):
        for invalid in [
            "https://staradvs-staging.pages.dev",
            "https://main.staradvs-staging.pages.dev",
            "https://staging.staradvs.shadowops.dpdns.org",
            "https://facecafe.other-pages.pages.dev",
            "https://facecafe.staradvs-staging.pages.dev.evil.test",
            "http://facecafe.staradvs-staging.pages.dev",
            "https://evil@facecafe.staradvs-staging.pages.dev",
            "https://facecafe.staradvs-staging.pages.dev:443",
            "https://facecafe.staradvs-staging.pages.dev?x=1",
            "https://facecafe.staradvs-staging.pages.dev/assets",
            None,
        ]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(pages.AdmissionError):
                    target.immutable_origin(invalid)

    def test_mismatched_historical_source_sha_is_not_a_candidate(self):
        wrong = {**manifest(), "build": "b" * 40}
        with self.assertRaisesRegex(pages.AdmissionError, "differs from attested"):
            inspect(release=wrong)
        wrong_env = {**manifest(), "environment": "production"}
        with self.assertRaisesRegex(pages.AdmissionError, "differs from attested"):
            inspect(release=wrong_env)

    def test_html_bundle_disagreement_or_mismatched_downloaded_js_is_rejected(self):
        with self.assertRaisesRegex(pages.AdmissionError, "entrypoint mismatch"):
            inspect(html=b'<script src="/assets/index-other.js"></script>')
        with self.assertRaisesRegex(pages.AdmissionError, "served JS differs"):
            inspect(js=b"rewritten stale or malicious cached bytes")

    def test_manifest_must_have_strict_entry_path_and_sha256(self):
        bad = [
            {**manifest(), "entry_js": {}},
            {**manifest(), "entry_js": {"path": "https://evil.test/assets/index.js",
                                        "sha256": hashlib.sha256(JS).hexdigest()}},
            {**manifest(), "entry_js": {"path": "/assets/../other.js",
                                        "sha256": hashlib.sha256(JS).hexdigest()}},
            {**manifest(), "entry_js": {"path": PATH, "sha256": "0" * 63}},
        ]
        for data in bad:
            with self.subTest(entry=data["entry_js"]):
                with self.assertRaisesRegex(pages.AdmissionError, "metadata unsafe|lacks JS proof"):
                    inspect(release=data)

    def test_redirects_are_explicitly_forbidden(self):
        self.assertIsNone(target.NoRedirects().redirect_request(
            object(), None, 302, "Found", {}, "https://foreign.test/"
        ))


if __name__ == "__main__":
    unittest.main()
