"""Verify historic Cloudflare Pages deployment bytes over immutable HTTPS URL.

Read-only. Reject Pages aliases, external domains, redirects and non-HTTPS URLs.
An independently served historical bundle must agree with its staging release.json.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

import staradvs_pages as pages

HASH_HOST = re.compile(r"^[a-f0-9]{8,40}\." + re.escape(pages.PROJECT) + r"\.pages\.dev$")
ENTRY_PATH = re.compile(r"^/assets/[A-Za-z0-9._-]+\.js$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")


def immutable_origin(url: object) -> str:
    if not isinstance(url, str):
        raise pages.AdmissionError("Historical Pages immutable URL is missing")
    try:
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname
                or not HASH_HOST.fullmatch(parsed.hostname)
                or parsed.netloc != parsed.hostname
                or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment
                or parsed.username or parsed.password or parsed.port):
            raise pages.AdmissionError("Historical Pages URL is not a fixed immutable staging deployment")
    except ValueError:
        raise pages.AdmissionError("Historical Pages deployment URL malformed") from None
    return "https://" + parsed.hostname


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def fetch_bytes(origin: str, path: str, mime: str, maximum: int) -> bytes:
    if not origin.startswith("https://") or not path.startswith("/") or ".." in path:
        raise pages.AdmissionError("Unsafe historic asset request")
    req = urllib.request.Request(origin + path, headers={
        "User-Agent": "Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Cache-Control": "no-cache",
    })
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirects(),
    )
    try:
        with opener.open(req, timeout=20) as response:
            if response.status != 200 or response.geturl() != origin + path:
                raise pages.AdmissionError("Historic Pages origin returned redirect or non-200")
            if mime not in response.headers.get("Content-Type", "").lower():
                raise pages.AdmissionError("Historic Pages asset has wrong MIME type")
            content = response.read(maximum + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise pages.AdmissionError("Historic Pages asset unavailable (" + type(exc).__name__ + ")") from None
    if not content or len(content) > maximum:
        raise pages.AdmissionError("Historic Pages asset absent or oversized")
    return content


def verify_immutable_target(detail: object, sha: str) -> str:
    if not isinstance(detail, dict) or not pages.SHA_PATTERN.fullmatch(sha):
        raise pages.AdmissionError("Historical deployment identity is invalid")
    origin = immutable_origin(detail.get("url"))
    raw = fetch_bytes(origin, "/release.json", "json", 65536)
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeError):
        raise pages.AdmissionError("Historic Pages release manifest invalid JSON") from None
    if (not isinstance(obj, dict) or obj.get("environment") != "staging"
            or obj.get("build") != sha):
        raise pages.AdmissionError("Historic Pages release differs from attested source SHA")
    entry = obj.get("entry_js")
    if not isinstance(entry, dict):
        raise pages.AdmissionError("Historic Pages release lacks JS proof")
    path, digest = entry.get("path"), entry.get("sha256")
    if (not isinstance(path, str) or not ENTRY_PATH.fullmatch(path)
            or not isinstance(digest, str) or not DIGEST.fullmatch(digest)):
        raise pages.AdmissionError("Historic Pages release JS metadata unsafe")
    html = fetch_bytes(origin, "/", "html", 700000)
    if pages.entrypoint_path(html) != path:
        raise pages.AdmissionError("Historic Pages HTML and release JS entrypoint mismatch")
    js = fetch_bytes(origin, path, "javascript", 16_000_000)
    if hashlib.sha256(js).hexdigest() != digest:
        raise pages.AdmissionError("Historic Pages served JS differs from attested digest")
    print("STARADVS_RECOVERY_IMMUTABLE_TARGET_OK sha=" + sha)
    return origin
