#!/usr/bin/env python3
"""Controlled Chronicles media copy: legacy public CDN -> dedicated Chronicles R2.

No Chess Studio credentials, deletes, overwrites or source-manifest activation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request

import chronicles_r2_media_probe as media
import chronicles_source_ci as source
from chronicles_r2_private_inventory import (
    _account_id, _verified_domain, cloudflare_get, InventoryError,
)

BUCKET = "chronicles"
PREFIX = "chronicles/"
LEGACY_HOST = "assets.chess-studio.shadowops.dpdns.org"
S3_KEYS = ("CHRONICLES_R2_MEDIA_ACCESS_KEY_ID", "CHRONICLES_R2_MEDIA_SECRET_ACCESS_KEY")
MAX_PREFIX_BYTES = 24_000_000
PINS_BY_ID = dict(zip(
    ("chronicles.music.firstVerse", "chronicles.music.secondVerse",
     "chronicles.tactics.party.master", "chronicles.tactics.party.runtime"),
    media.PINS,
))


class PublicationError(RuntimeError):
    """Sanitized failure; never include provider response bodies or credentials."""


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def url(host, key):
    return "https://" + host + "/" + urllib.parse.quote(key, safe="/-._~")


def validate_manifest(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16_384:
        raise PublicationError("Source manifest missing, linked or oversized")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError, UnicodeError):
        raise PublicationError("Malformed source manifest") from None
    if (not isinstance(doc, dict) or doc.get("version") != 1
            or doc.get("baseUrl") != "https://" + LEGACY_HOST
            or not isinstance(doc.get("assets"), dict)
            or set(doc["assets"]) != set(PINS_BY_ID)):
        raise PublicationError("Source manifest differs from four pinned assets")
    for logical, asset in PINS_BY_ID.items():
        if doc["assets"][logical] != {
            "bytes": asset.size, "contentType": asset.mime,
            "key": asset.key, "sha256": asset.sha256,
            "url": "https://" + LEGACY_HOST + "/" + asset.key,
        }:
            raise PublicationError("Source asset pin or URL changed")
    return media.PINS


def fixed_get(target, size, *, token="", json_response=False):
    headers = {"User-Agent": "shadowops-chronicles-r2-media-copy/1"}
    if token:
        headers.update({
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
    req = urllib.request.Request(target, method="GET", headers=headers)
    try:
        with urllib.request.build_opener(NoRedirects()).open(req, timeout=30) as response:
            if response.status != 200 or response.geturl() != target:
                raise PublicationError("Unexpected source URL or HTTP status")
            if json_response and response.headers.get_content_type() != "application/json":
                raise PublicationError("Unexpected GitHub admission MIME")
            data = response.read(size + 1)
    except PublicationError:
        raise
    except (OSError, ValueError):
        raise PublicationError("Pinned public source unavailable") from None
    if len(data) > size:
        raise PublicationError("Public source exceeded pinned size budget")
    return data


def prepare(fetch=fixed_get):
    pack = {}
    for asset in media.PINS:
        body = fetch(url(LEGACY_HOST, asset.key), asset.size)
        if len(body) != asset.size or hashlib.sha256(body).hexdigest() != asset.sha256:
            raise PublicationError("Legacy media source hash/size mismatch")
        pack[asset] = body
    return pack


def admit(source_sha, token):
    if not source.SHA.fullmatch(source_sha) or not token:
        raise PublicationError("Exact source SHA and read token required")
    endpoint = "https://api.github.com/repos/" + source.SOURCE + "/commits/main"
    try:
        doc = json.loads(fixed_get(endpoint, 15_000, token=token, json_response=True))
        if not isinstance(doc, dict) or doc.get("sha") != source_sha:
            raise PublicationError("Chronicles main SHA changed")
        if source.inspect(source_sha, token) != "ready":
            raise PublicationError("Chronicles main source CI is not green")
    except (ValueError, source.AdmissionError):
        raise PublicationError("Source CI admission unavailable") from None


def verify_domain(environ):
    account, token = (environ.get("CHRONICLES_R2_ACCOUNT_ID", ""),
                      environ.get("CHRONICLES_R2_READ_TOKEN", ""))
    if not token:
        raise PublicationError("Dedicated domain read-only token required")
    try:
        _account_id(account)
        _verified_domain(cloudflare_get(token, account, "domains", None))
    except InventoryError:
        raise PublicationError("Chronicles R2 custom domain not verified") from None


def create_client(environ):
    account = environ.get("CHRONICLES_R2_ACCOUNT_ID", "")
    try:
        _account_id(account)
    except InventoryError:
        raise PublicationError("Invalid Chronicles R2 account") from None
    if any(not environ.get(k) for k in S3_KEYS):
        raise PublicationError("Dedicated media-only S3 credentials required")
    if any(environ[k] == environ.get("CHRONICLES_R2_READ_TOKEN", "") for k in S3_KEYS):
        raise PublicationError("Media S3 credentials must differ from read token")
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise PublicationError("Pinned boto3 required for publication") from None
    return boto3.client(
        "s3", endpoint_url=f"https://{account}.r2.cloudflarestorage.com",
        region_name="auto", aws_access_key_id=environ[S3_KEYS[0]],
        aws_secret_access_key=environ[S3_KEYS[1]],
        config=Config(retries={"mode": "standard", "total_max_attempts": 1}),
    )


def inventory(client):
    try:
        page = client.list_objects_v2(Bucket=BUCKET, Prefix=PREFIX, MaxKeys=1000)
    except Exception:
        raise PublicationError("Chronicles media prefix inventory unavailable") from None
    if (not isinstance(page, dict) or page.get("IsTruncated") is not False
            or not isinstance(page.get("Contents", []), list)):
        raise PublicationError("Media prefix inventory incomplete")
    allowed = {asset.key for asset in media.PINS}
    found = {}
    for row in page.get("Contents", []):
        key = row.get("Key") if isinstance(row, dict) else None
        size = row.get("Size") if isinstance(row, dict) else None
        if key not in allowed or key in found or type(size) is not int or size < 0:
            raise PublicationError("Unexpected/duplicate object in media prefix")
        found[key] = size
    if sum(found.values()) > MAX_PREFIX_BYTES:
        raise PublicationError("Media prefix exceeds approved budget")
    return found


def cache(asset):
    return ("public, max-age=31536000, immutable" if asset.versioned
            else "public, max-age=3600")


def readback(client, asset, expected):
    try:
        obj = client.get_object(Bucket=BUCKET, Key=asset.key)
        stream = obj.get("Body")
        if (obj.get("ContentType") != asset.mime
                or obj.get("CacheControl") != cache(asset)
                or obj.get("ContentLength") != asset.size or not hasattr(stream, "read")):
            raise PublicationError("Chronicles media object metadata mismatch")
        try:
            data = stream.read(asset.size + 1)
        finally:
            if hasattr(stream, "close"):
                stream.close()
    except PublicationError:
        raise
    except Exception:
        raise PublicationError("Chronicles media readback unavailable") from None
    if data != expected:
        raise PublicationError("Chronicles media readback hash/size mismatch")


def public_verify(asset, fetch=media.request):
    try:
        status, headers, body = fetch("GET", asset)
        media.validate(status, headers, asset, body)
    except (media.ProbeError, urllib.error.URLError, TimeoutError, OSError):
        raise PublicationError("Public Chronicles media edge verification failed") from None


def collision(exc):
    data = getattr(exc, "response", None)
    return (isinstance(data, dict) and isinstance(data.get("Error"), dict)
            and str(data["Error"].get("Code")) in ("PreconditionFailed", "412"))


def publish(client, pack, source_sha, token):
    admit(source_sha, token)
    existing = inventory(client)
    missing_bytes = 0
    for asset, raw in pack.items():
        if asset.key in existing:
            if existing[asset.key] != asset.size:
                raise PublicationError("Existing key size conflicts with source pin")
            readback(client, asset, raw)
            public_verify(asset)
        else:
            missing_bytes += len(raw)
    if sum(existing.values()) + missing_bytes > MAX_PREFIX_BYTES:
        raise PublicationError("Media prefix byte budget exceeded")
    admit(source_sha, token)  # All checks before any new writes.
    created = 0
    for asset, raw in pack.items():
        if asset.key in existing:
            continue
        try:
            client.put_object(
                Bucket=BUCKET, Key=asset.key, Body=raw, ContentLength=asset.size,
                ContentType=asset.mime, CacheControl=cache(asset), IfNoneMatch="*",
            )
        except Exception as exc:
            if not collision(exc):
                raise PublicationError("Uncertain conditional PUT; re-inventory before retry") from None
        readback(client, asset, raw)
        public_verify(asset)
        created += 1
    return {"objects": len(pack), "created": created, "reused": len(pack)-created,
            "bytes": sum(len(raw) for raw in pack.values()), "source_sha": source_sha}


def candidate(pack):
    return {"schema": 1, "activation": "manual-pr-required", "assets": {
        logical: {"url": url(media.HOST, asset.key), "key": asset.key,
                  "bytes": asset.size, "sha256": asset.sha256, "contentType": asset.mime}
        for logical, asset in PINS_BY_ID.items() if asset in pack
    }}


def main(argv=None, environ=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "publish"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--confirm-bucket", default="")
    parser.add_argument("--candidate", type=Path)
    opts = parser.parse_args(argv)
    environ = os.environ if environ is None else environ
    try:
        validate_manifest(opts.manifest)
        if not source.SHA.fullmatch(opts.source_sha):
            raise PublicationError("Exact 40-digit source SHA required")
        pack = prepare()
        if opts.action == "plan":
            print("CHRONICLES_MEDIA_COPY_PLAN " + json.dumps({
                "objects": len(pack), "bytes": sum(map(len, pack.values())),
                "writes": 0, "source_sha": opts.source_sha,
            }, sort_keys=True))
            return 0
        if opts.confirm_bucket != BUCKET:
            raise PublicationError("Explicit confirm-bucket chronicles required")
        verify_domain(environ)
        client = create_client(environ)
        result = publish(client, pack, opts.source_sha, environ.get("GH_TOKEN", ""))
        media.probe()  # All four target URLs still need CDN integrity proof.
        if opts.candidate:
            opts.candidate.write_text(json.dumps(candidate(pack), indent=2) + "\n")
        print("CHRONICLES_MEDIA_COPY_VERIFIED " + json.dumps(result, sort_keys=True))
        return 0
    except (PublicationError, InventoryError, media.ProbeError, OSError) as exc:
        print("CHRONICLES_MEDIA_COPY_BLOCKED " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("CHRONICLES_MEDIA_COPY_BLOCKED unexpected failure", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
