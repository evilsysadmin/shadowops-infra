import copy
from email.message import Message
import hashlib
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import football_keeper_public as keeper


def webp_bytes(label: str) -> bytes:
    return b"RIFF" + len(label).to_bytes(4, "little") + b"WEBP" + label.encode()


def fixture():
    content = {name: webp_bytes(team) for team, name in keeper.FILENAMES.items()}
    meta = {
        "version": 1,
        "enabled": True,
        "bucket": "football",
        "prefix": "atlases/v1/",
        "quality_contract": "football-keeper-catch-v1",
        "cdn_base": keeper.PUBLIC_BASE,
        "cell": {"width": 128, "height": 144},
        "columns": 8,
        "rows": 1,
        "entries": [
            {
                "team": team,
                "file": name,
                "sha256": hashlib.sha256(content[name]).hexdigest(),
            }
            for team, name in keeper.FILENAMES.items()
        ],
    }
    return meta, content


class Reply:
    def __init__(self, url, payload, *, status=200, mime="image/webp",
                 cors=keeper.STAGING_ORIGIN, final_url=None):
        self.status = status
        self.url = final_url or url
        self.payload = payload
        self.headers = Message()
        self.headers["Content-Type"] = mime
        if cors is not None:
            self.headers["Access-Control-Allow-Origin"] = cors

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, n):
        return self.payload[:n]


class KeeperPublicContract(unittest.TestCase):
    def test_two_exact_webps_are_verified_using_staging_origin(self):
        meta, content = fixture()
        requests = []

        def opener(request, timeout):
            self.assertEqual(timeout, 18)
            self.assertEqual(request.get_header("Origin"), keeper.STAGING_ORIGIN)
            self.assertEqual(request.get_header("Cache-control"), "no-cache")
            requests.append(request.full_url)
            return Reply(request.full_url, content[request.full_url.rsplit("/", 1)[-1]])

        self.assertTrue(keeper.verify_manifest(meta, opener=opener))
        self.assertEqual(set(requests), {
            keeper.PUBLIC_BASE + "/" + name for name in keeper.FILENAMES.values()
        })

    def test_wrong_cors_http_mime_redirect_hash_and_oversize_fail_closed(self):
        for fault in ["cors", "http", "mime", "redirect", "hash", "oversize"]:
            with self.subTest(fault=fault):
                meta, content = fixture()
                def opener(request, timeout):
                    name = request.full_url.rsplit("/", 1)[-1]
                    kwargs = {}
                    if fault == "cors":
                        kwargs["cors"] = "https://attacker.invalid"
                    if fault == "http":
                        kwargs["status"] = 404
                    if fault == "mime":
                        kwargs["mime"] = "text/html"
                    if fault == "redirect":
                        kwargs["final_url"] = "https://attacker.invalid/payload"
                    raw = content[name]
                    if fault == "hash":
                        raw = webp_bytes("tampered")
                    if fault == "oversize":
                        raw = b"RIFF" + b"x" * (keeper.MAX_WEBP_BYTES + 4)
                    return Reply(request.full_url, raw, **kwargs)
                with self.assertRaises(keeper.KeeperR2Error):
                    keeper.verify_manifest(meta, opener=opener)

    def test_metadata_forgery_and_duplicate_team_are_rejected_without_network(self):
        for key, wrong in [
            ("bucket", "chess-studio-assets"),
            ("prefix", "football/atlases/v1/"),
            ("cdn_base", "https://attacker.invalid/atlases/v1"),
            ("columns", 7),
            ("quality_contract", "unknown"),
        ]:
            with self.subTest(key=key):
                meta, _ = fixture()
                meta[key] = wrong
                with self.assertRaises(keeper.KeeperR2Error):
                    keeper.verify_manifest(meta, opener=self.fail)
        meta, _ = fixture()
        meta["entries"][1]["team"] = "fc_matthias"
        with self.assertRaises(keeper.KeeperR2Error):
            keeper.verify_manifest(meta, opener=self.fail)

    def test_disabled_feature_does_not_require_remote_downloads(self):
        meta, _ = fixture()
        meta["enabled"] = False
        self.assertFalse(keeper.verify_manifest(meta, opener=self.fail))
        meta["enabled"] = "false"
        with self.assertRaises(keeper.KeeperR2Error):
            keeper.verify_manifest(meta, opener=self.fail)


if __name__ == "__main__":
    unittest.main()
