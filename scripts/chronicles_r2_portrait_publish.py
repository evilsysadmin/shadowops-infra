#!/usr/bin/env python3
"""Explicit, immutable Chronicles portrait publication to its EXISTING R2 bucket.

Dry-run requires no secrets or network. The publish path requires green exact
Chronicles main CI, bucket-scoped S3 credentials and a read-only Cloudflare
domain credential. No DNS/Pages writes, deletions or pointer activation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

import chronicles_source_ci as source
from chronicles_r2_private_inventory import (
    _account_id, _verified_domain, cloudflare_get, InventoryError,
)

BUCKET = "chronicles"
HOST = "assets.chronicles.shadowops.dpdns.org"
PREFIX = "portraits/"
ORIGIN = "https://staging.chronicles.shadowops.dpdns.org"
CACHE_CONTROL = "public, max-age=31536000, immutable"
MAX_FILE = 256 * 1024
MAX_PACK = 4 * 1024 * 1024
MAX_BUCKET_PREFIX = 32 * 1024 * 1024
MAX_PAGES = 8
ID = r"(?:matthias|rook|bishop|knight|(?:male|female)-(?:0[1-9]|10))"
KEY = re.compile(r"portraits/(" + ID + r")/awake-([0-9a-f]{16})\.webp\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
EXPECTED = {"matthias", "rook", "bishop", "knight"} | {
    "%s-%02d" % (sex, index)
    for sex in ("male", "female") for index in range(1, 11)
}
S3_KEYS = ("CHRONICLES_R2_PORTRAIT_ACCESS_KEY_ID",
           "CHRONICLES_R2_PORTRAIT_SECRET_ACCESS_KEY")


class PublicationError(RuntimeError):
    """Intentionally sanitized; never include credential/provider error bodies."""


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate(stage: Path) -> dict[str, tuple[bytes, dict]]:
    """Accept exactly 24 canonical awake WebPs and matching SHA metadata."""
    if stage.is_symlink() or not stage.is_dir():
        raise PublicationError("Source portrait stage must be a real directory")
    try:
        raw = (stage / "sha256sums.json").read_bytes()
        candidate = (stage / "manifest.candidate.json").read_bytes()
        if len(raw) > 100_000 or len(candidate) > 100_000:
            raise PublicationError("Portrait metadata exceeds bounded size")
        rows = json.loads(raw)
        manifest = json.loads(candidate)
    except (OSError, ValueError, UnicodeError) as exc:
        raise PublicationError("Missing or malformed portrait package metadata") from None
    if (type(rows) is not list or len(rows) != 24
            or not isinstance(manifest, dict) or set(manifest) != {"schema", "portraits"}
            or manifest["schema"] != 1 or not isinstance(manifest["portraits"], dict)
            or set(manifest["portraits"]) != EXPECTED):
        raise PublicationError("Exactly 24 awake portrait records required")
    found: dict[str, tuple[bytes, dict]] = {}
    ids: set[str] = set()
    total = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"key", "size", "sha256"}:
            raise PublicationError("Unexpected portrait metadata")
        key, size, checksum = row.get("key"), row.get("size"), row.get("sha256")
        match = KEY.fullmatch(key) if isinstance(key, str) else None
        if (match is None or key in found or type(size) is not int
                or not 30 <= size <= MAX_FILE
                or not isinstance(checksum, str) or not SHA.fullmatch(checksum)
                or match[2] != checksum[:16]):
            raise PublicationError("Unsafe or mismatched immutable portrait key")
        portrait_id = match[1]
        if portrait_id in ids:
            raise PublicationError("Duplicate portrait identity")
        ids.add(portrait_id)
        url = "https://" + HOST + "/" + key
        if manifest["portraits"][portrait_id] != {"awake": url}:
            raise PublicationError("Portrait manifest does not match source bytes")
        path = stage / key
        if (path.is_symlink() or any(p.is_symlink() for p in path.parents if p != stage.parent)
                or not path.is_file() or path.stat().st_size != size):
            raise PublicationError("Portrait file missing, linked or unexpectedly sized")
        data = path.read_bytes()
        if (len(data) != size or digest(data) != checksum
                or data[:4] != b"RIFF" or data[8:12] != b"WEBP"):
            raise PublicationError("Portrait WebP content does not match SHA-256 evidence")
        found[key] = (data, row)
        total += size
    if ids != EXPECTED or total > MAX_PACK:
        raise PublicationError("Portrait batch identities or total bytes invalid")
    actual = {p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file()}
    if actual != set(found) | {"sha256sums.json", "manifest.candidate.json"}:
        raise PublicationError("Portrait batch contains unexpected or missing files")
    return found


def read_main_sha(token: str) -> str:
    if not token:
        raise PublicationError("GitHub read token required for source admission")
    url = "https://api.github.com/repos/" + source.SOURCE + "/commits/main"
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.build_opener(NoRedirects()).open(req, timeout=20) as response:
            if response.status != 200 or response.geturl() != url:
                raise PublicationError("Untrusted main source response")
            sha = json.load(response).get("sha")
    except (OSError, ValueError, KeyError):
        raise PublicationError("Current Chronicles main SHA unavailable") from None
    if not isinstance(sha, str) or not source.SHA.fullmatch(sha):
        raise PublicationError("Invalid current source SHA")
    return sha


def admit(source_sha: str, token: str) -> None:
    if not source.SHA.fullmatch(source_sha):
        raise PublicationError("Exact full Chronicles source SHA required")
    if read_main_sha(token) != source_sha:
        raise PublicationError("Chronicles source SHA is no longer current main")
    try:
        if source.inspect(source_sha, token) != "ready":
            raise PublicationError("Chronicles main source CI is not all green")
    except source.AdmissionError:
        raise PublicationError("Chronicles CI source admission unavailable") from None


def validate_domain(read_token: str, account: str) -> None:
    try:
        _verified_domain(cloudflare_get(read_token, account, "domains", None))
    except InventoryError:
        raise PublicationError("Approved Chronicles R2 domain could not be verified") from None


def create_client(environ: dict):
    account = environ.get("CHRONICLES_R2_ACCOUNT_ID", "")
    try:
        _account_id(account)
    except InventoryError:
        raise PublicationError("Dedicated Chronicles account identity required") from None
    if any(not environ.get(name) for name in S3_KEYS):
        raise PublicationError("Dedicated bucket-scoped Chronicles portrait S3 keys required")
    if any(environ.get(name) == environ.get("CHRONICLES_R2_READ_TOKEN") for name in S3_KEYS):
        raise PublicationError("Read-only and publish credentials must differ")
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise PublicationError("boto3 required for manual R2 publication") from None
    return boto3.client(
        "s3", endpoint_url=f"https://{account}.r2.cloudflarestorage.com",
        region_name="auto", aws_access_key_id=environ[S3_KEYS[0]],
        aws_secret_access_key=environ[S3_KEYS[1]],
        config=Config(retries={"mode": "standard", "max_attempts": 1}),
    )


def inventory(client) -> dict[str, int]:
    result: dict[str, int] = {}
    cursor: str | None = None
    cursors: set[str] = set()
    for _ in range(MAX_PAGES):
        query = {"Bucket": BUCKET, "Prefix": PREFIX, "MaxKeys": 1000}
        if cursor:
            query["ContinuationToken"] = cursor
        try:
            page = client.list_objects_v2(**query)
        except Exception:
            raise PublicationError("R2 portrait prefix inventory unavailable") from None
        if (not isinstance(page, dict) or type(page.get("IsTruncated")) is not bool
                or not isinstance(page.get("Contents", []), list)):
            raise PublicationError("Incomplete R2 portrait inventory")
        for row in page.get("Contents", []):
            key, size = row.get("Key"), row.get("Size")
            if (not isinstance(key, str) or not KEY.fullmatch(key)
                    or type(size) is not int or size < 0 or key in result):
                raise PublicationError("Unexpected object in dedicated portrait prefix")
            result[key] = size
        if not page["IsTruncated"]:
            return result
        cursor = page.get("NextContinuationToken")
        if not isinstance(cursor, str) or not cursor or cursor in cursors:
            raise PublicationError("Ambiguous portrait inventory continuation")
        cursors.add(cursor)
    raise PublicationError("R2 portrait prefix inventory exceeds page limit")


def s3_readback(client, key: str, data: bytes) -> None:
    try:
        object_data = client.get_object(Bucket=BUCKET, Key=key)
        content_type = object_data.get("ContentType")
        cache = object_data.get("CacheControl")
        content_length = object_data.get("ContentLength")
        body = object_data.get("Body")
        if (content_type != "image/webp" or cache != CACHE_CONTROL
                or content_length != len(data) or not hasattr(body, "read")):
            raise PublicationError("R2 portrait object metadata mismatch")
        try:
            remote = body.read(len(data) + 1)
        finally:
            if hasattr(body, "close"):
                body.close()
    except PublicationError:
        raise
    except Exception:
        raise PublicationError("R2 portrait readback failed") from None
    if remote != data:
        raise PublicationError("R2 portrait content SHA mismatch")


def public_verify(key: str, data: bytes) -> None:
    req = urllib.request.Request(
        "https://" + HOST + "/" + key,
        headers={"Origin": ORIGIN, "Cache-Control": "no-cache",
                 "User-Agent": "shadowops-chronicles-portraits/1"},
    )
    try:
        with urllib.request.build_opener(NoRedirects()).open(req, timeout=20) as response:
            if (response.status != 200 or response.geturl() != req.full_url
                    or response.headers.get_content_type() != "image/webp"
                    or response.headers.get("Access-Control-Allow-Origin") not in ("*", ORIGIN)
                    or "immutable" not in response.headers.get("Cache-Control", "").lower()
                    or "max-age=31536000" not in response.headers.get("Cache-Control", "").lower()):
                raise PublicationError("Public Chronicles portrait CDN headers invalid")
            remote = response.read(len(data) + 1)
    except PublicationError:
        raise
    except (OSError, ValueError):
        raise PublicationError("Public Chronicles portrait unavailable") from None
    if remote != data:
        raise PublicationError("Public Chronicles portrait SHA-256 mismatch")


def is_collision(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    return (isinstance(response, dict)
            and isinstance(response.get("Error"), dict)
            and str(response["Error"].get("Code")) in ("PreconditionFailed", "412"))


def publish(client, pack: dict, source_sha: str, token: str) -> dict:
    # Preflight entire prefix and existing objects BEFORE any conditional write.
    admit(source_sha, token)
    existing = inventory(client)
    new_bytes = 0
    for key, (data, _) in pack.items():
        if key in existing:
            if existing[key] != len(data):
                raise PublicationError("Existing portrait key has conflicting size")
            s3_readback(client, key, data)
            public_verify(key, data)
        else:
            new_bytes += len(data)
    if sum(existing.values()) + new_bytes > MAX_BUCKET_PREFIX:
        raise PublicationError("Portrait prefix free-tier budget exceeded")
    admit(source_sha, token)  # New main during preflight means no writes.
    created = 0
    for key, (data, _) in sorted(pack.items()):
        if key in existing:
            continue
        try:
            client.put_object(
                Bucket=BUCKET, Key=key, Body=data, ContentLength=len(data),
                ContentType="image/webp", CacheControl=CACHE_CONTROL,
                IfNoneMatch="*",
            )
        except Exception as exc:
            if not is_collision(exc):
                raise PublicationError("Conditional R2 write uncertain; re-inventory before retry") from None
        # Concurrent create is safe only when identical bytes are proven.
        s3_readback(client, key, data)
        public_verify(key, data)
        created += 1
    return {"bucket": BUCKET, "sourceSha": source_sha, "objects": len(pack),
            "created": created, "reused": len(pack) - created}


def main(argv=None, environ=None) -> int:
    args = argparse.ArgumentParser()
    args.add_argument("action", choices=("plan", "publish"))
    args.add_argument("--stage", required=True, type=Path)
    args.add_argument("--source-sha", required=True)
    args.add_argument("--confirm-bucket", default="")
    opts = args.parse_args(argv)
    environ = os.environ if environ is None else environ
    try:
        pack = validate(opts.stage)
        if not source.SHA.fullmatch(opts.source_sha):
            raise PublicationError("Exact source SHA required")
        if opts.action == "plan":
            print("CHRONICLES_R2_PORTRAIT_PLAN " + json.dumps({
                "sourceSha": opts.source_sha, "bucket": BUCKET,
                "objects": len(pack), "bytes": sum(len(data) for data, _ in pack.values()),
                "writes": 0,
            }, sort_keys=True))
            return 0
        if opts.confirm_bucket != BUCKET:
            raise PublicationError("Explicit --confirm-bucket chronicles required")
        account = environ.get("CHRONICLES_R2_ACCOUNT_ID", "")
        token = environ.get("CHRONICLES_R2_READ_TOKEN", "")
        if not token:
            raise PublicationError("Dedicated read-only Chronicles Cloudflare credential required")
        validate_domain(token, account)
        client = create_client(environ)
        result = publish(client, pack, opts.source_sha, environ.get("GH_TOKEN", ""))
        print("CHRONICLES_R2_PORTRAITS_VERIFIED " + json.dumps(result, sort_keys=True))
        return 0
    except (PublicationError, InventoryError, OSError) as exc:
        print("CHRONICLES_R2_PORTRAITS_BLOCKED " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("CHRONICLES_R2_PORTRAITS_BLOCKED unexpected failure", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
