#!/usr/bin/env python3
"""Pawn Action: immutable assets to its OWN PRIVATE R2 bucket only.

Never upload to chess-studio-assets, publish CDN URLs, modify a pointer,
delete an object, change DNS/Pages or enable public bucket access.
An actual upload requires manual confirmation, current-green source evidence,
a verifiably private bucket and independent bucket-scoped S3 credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from cloudflare_control_plane import CloudflareReadClient, InventoryError
from pawn_action_private_r2 import ACCOUNT, BUCKET, inspect
from pawn_action_source_admission import AdmissionError, GithubReader, admit
import pawn_action_web_package as pkg

PREFIX = "pawn-action/releases/"
MAX_BYTES = 512 * 1024**2
MAX_PAGES = 100
S3_KEYS = ("PAWN_ACTION_PRIVATE_R2_ACCESS_KEY_ID",
           "PAWN_ACTION_PRIVATE_R2_SECRET_ACCESS_KEY")
SUPPORTED = frozenset({
    "index.html", "index.js", "index.wasm", "index.pck",
    "index.png", "index.icon.png", "index.apple-touch-icon.png",
    "index.audio.worklet.js", "index.audio.position.worklet.js",
})
REQUIRED = frozenset({"index.html", "index.js", "index.wasm", "index.pck"})
DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def _sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def entries_for(candidate: Path, sha: str) -> tuple[dict, dict]:
    manifest = pkg.validate(candidate, sha)
    files = manifest["files"]
    if (not REQUIRED.issubset(files) or not set(files).issubset(SUPPORTED)
            or not 4 <= len(files) <= len(SUPPORTED)):
        raise AdmissionError("Release contains files not supported by private delivery Worker")
    release = manifest["release"]
    if not re.fullmatch(r"[a-f0-9]{16}", release):
        raise AdmissionError("Immutable release revision is invalid")
    entries = {}
    for name, metadata in sorted(files.items()):
        key = PREFIX + release + "/" + name
        if (metadata["key"] != key or metadata["url"] != pkg.ORIGIN + "/" + name
                or not DIGEST.fullmatch(str(metadata["sha256"]))
                or type(metadata["bytes"]) is not int
                or not 0 < metadata["bytes"] <= 128 * 1024**2):
            raise AdmissionError("Protected object key, URL or content bound mismatch")
        entries[key] = (candidate / "runtime" / name, metadata)
    if (pkg.ORIGIN != "https://staging.pawnaction.shadowops.dpdns.org"
            or BUCKET != "pawn-action-staging-private"):
        raise AdmissionError("Unexpected private publish destination")
    return manifest, entries


def require_receipt(manifest: dict, receipt: dict) -> None:
    data = manifest["sourceArtifact"]
    if (not isinstance(receipt, dict)
            or receipt.get("source_sha") != manifest["sourceSha"]
            or receipt.get("run_id") != data["runId"]
            or receipt.get("artifact_id") != data["artifactId"]
            or receipt.get("artifact_digest") != data["digest"]
            or type(receipt.get("visual_artifact_id")) is not int
            or receipt["visual_artifact_id"] <= 0
            or not re.fullmatch(r"sha256:[a-f0-9]{64}",
                                str(receipt.get("visual_artifact_digest", "")))):
        raise AdmissionError("Candidate does not match exact green visual/source CI receipt")


def private(reader) -> None:
    state = inspect(reader)
    if state["private"] is not True or state["bucket"] != "owned":
        raise AdmissionError("Pawn Action R2 privacy not proven; no object write allowed")


def inventory(client) -> dict[str, int]:
    keys: dict[str, int] = {}
    cursor = None
    cursors: set[str] = set()
    for _ in range(MAX_PAGES):
        args = {"Bucket": BUCKET, "MaxKeys": 1000}
        if cursor:
            args["ContinuationToken"] = cursor
        try:
            response = client.list_objects_v2(**args)
        except Exception:
            raise AdmissionError("Private R2 inventory unavailable") from None
        if (not isinstance(response, dict)
                or type(response.get("IsTruncated")) is not bool
                or not isinstance(response.get("Contents", []), list)):
            raise AdmissionError("Incomplete private R2 inventory")
        for row in response.get("Contents", []):
            if not isinstance(row, dict):
                raise AdmissionError("Malformed private R2 inventory row")
            key, size = row.get("Key"), row.get("Size")
            if (not isinstance(row, dict) or not isinstance(key, str)
                    or not key.startswith(PREFIX)
                    or "/../" in key or key.endswith("/")
                    or type(size) is not int or size < 0 or key in keys):
                raise AdmissionError("Private bucket has malformed or foreign objects")
            keys[key] = size
        if not response["IsTruncated"]:
            return keys
        cursor = response.get("NextContinuationToken")
        if not isinstance(cursor, str) or not cursor or cursor in cursors:
            raise AdmissionError("Private R2 inventory has ambiguous cursor")
        cursors.add(cursor)
    raise AdmissionError("Private R2 inventory exceeded pagination limit")


def budget(existing: dict[str, int], entries: dict) -> dict:
    new_bytes = 0
    for key, (_, data) in entries.items():
        if key in existing:
            if existing[key] != data["bytes"]:
                raise AdmissionError("Existing private R2 object differs in size")
        else:
            new_bytes += data["bytes"]
    total = sum(existing.values()) + new_bytes
    if total > MAX_BYTES or total <= 0:
        raise AdmissionError("Private Pawn Action 512 MiB storage budget exceeded")
    return {"newBytes": new_bytes, "projectedBytes": total, "objects": len(entries)}


def verify_remote(client, key: str, metadata: dict) -> None:
    try:
        result = client.get_object(Bucket=BUCKET, Key=key)
        body = result.get("Body")
        if (body is None or not hasattr(body, "read")
                or ("ContentLength" in result
                    and result["ContentLength"] != metadata["bytes"])):
            raise AdmissionError("Private R2 object readback missing")
        h = hashlib.sha256()
        remaining = metadata["bytes"]
        try:
            while remaining:
                chunk = body.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise AdmissionError("Private R2 object truncated")
                h.update(chunk)
                remaining -= len(chunk)
            if body.read(1):
                raise AdmissionError("Private R2 object longer than expected")
        finally:
            if hasattr(body, "close"):
                body.close()
    except AdmissionError:
        raise
    except Exception:
        raise AdmissionError("Private R2 SHA256 readback unavailable") from None
    if h.hexdigest() != metadata["sha256"]:
        raise AdmissionError("Private R2 object SHA256 mismatch")


def _collision(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    return (isinstance(response, dict)
            and isinstance(response.get("Error"), dict)
            and str(response["Error"].get("Code")) in ("PreconditionFailed", "412"))


def publish(client, reader, candidate: Path, sha: str, receipt: dict) -> dict:
    manifest, entries = entries_for(candidate, sha)
    require_receipt(manifest, receipt)
    # Prehash ALL local files before any cloud write to avoid partial releases
    # when the local candidate has changed after package validation.
    for path, data in entries.values():
        if _sha_file(path) != data["sha256"]:
            raise AdmissionError("Local release changed after admission")
    private(reader)
    existing = inventory(client)
    projection = budget(existing, entries)
    # A known-existing object MUST be proven identical before any new write.
    for key, (_, data) in entries.items():
        if key in existing:
            verify_remote(client, key, data)
    created = 0
    for key, (path, data) in entries.items():
        if key in existing:
            continue
        if _sha_file(path) != data["sha256"]:
            raise AdmissionError("Local release changed immediately before upload")
        try:
            with path.open("rb") as stream:
                client.put_object(
                    Bucket=BUCKET, Key=key, Body=stream,
                    ContentLength=data["bytes"],
                    ContentType=data["contentType"], IfNoneMatch="*",
                )
        except Exception as exc:
            if not _collision(exc):
                # Unknown in-flight write outcome; never automatically retry.
                raise AdmissionError("Private R2 conditional PUT uncertain; stop and re-inventory") from None
            # Concurrent create is acceptable ONLY if readback proves exact bytes.
        verify_remote(client, key, data)
        created += 1
    # Fail even after a successful upload if the bucket became public:
    # do NOT emit a release-ready result or activate any pointer.
    private(reader)
    return {"bucket": BUCKET, "release": manifest["release"],
            "sourceSha": sha, "created": created,
            "reused": len(entries) - created, **projection}


def create_client(environ):
    account = environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    if not isinstance(account, str) or not ACCOUNT.fullmatch(account):
        raise AdmissionError("Exact Cloudflare account required")
    if any(not environ.get(key) for key in S3_KEYS):
        raise AdmissionError("Dedicated private-bucket S3 credentials required")
    if (environ.get("CLOUDFLARE_API_TOKEN") in
            (environ[S3_KEYS[0]], environ[S3_KEYS[1]])):
        raise AdmissionError("Read-only inventory credential must be distinct")
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise AdmissionError("boto3 required only for manual private upload") from None
    return boto3.client(
        "s3", endpoint_url=f"https://{account}.r2.cloudflarestorage.com",
        region_name="auto", aws_access_key_id=environ[S3_KEYS[0]],
        aws_secret_access_key=environ[S3_KEYS[1]],
        config=Config(retries={"mode": "standard", "max_attempts": 1}),
    )


def main(argv: list[str] | None = None, environ=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "apply"))
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--confirm-immutable-upload", default="")
    args = parser.parse_args(argv)
    environ = os.environ if environ is None else environ
    try:
        manifest, entries = entries_for(args.candidate, args.source_sha)
        if args.action == "plan":
            print("PAWN_ACTION_PRIVATE_R2_PLAN " + json.dumps({
                "bucket": BUCKET, "release": manifest["release"],
                "files": len(entries), "bytes": sum(m["bytes"] for _, m in entries.values()),
                "writes": 0, "destination": "private-only",
            }, sort_keys=True))
            return 0
        confirmation = PREFIX + manifest["release"]
        if args.confirm_immutable_upload != confirmation:
            raise AdmissionError("Manual private upload requires exact confirmation " + confirmation)
        # Re-admit the exact CURRENT Pawn Action main before even creating
        # Cloudflare clients; Draft source PRs are not eligible.
        receipt = admit(GithubReader(environ.get("GH_TOKEN", "")), args.source_sha)
        require_receipt(manifest, receipt)
        reader = CloudflareReadClient(environ)
        private(reader)
        client = create_client(environ)
        result = publish(client, reader, args.candidate, args.source_sha, receipt)
        print("PAWN_ACTION_PRIVATE_R2_IMMUTABLE_VERIFIED " +
              json.dumps(result, sort_keys=True))
        return 0
    except (AdmissionError, InventoryError, OSError) as exc:
        print("PAWN_ACTION_PRIVATE_R2_BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("PAWN_ACTION_PRIVATE_R2_BLOCKED: unexpected failure", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
