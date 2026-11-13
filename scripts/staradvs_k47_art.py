#!/usr/bin/env python3
"""Strict source-accredited, manual-only, immutable K-47 original GLB publisher.

No cloud writes on PR, import, plan or validation. Publish requires explicit
visual-acceptance input, source-main CI and source candidate artifact proof.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import urllib.error
import urllib.request
import zipfile

import staradvs_source_admission as source

REPO = "evilsysadmin/star-adventures"
WORKFLOW = "K-47 unified architecture · full-sector visual gate"
BUCKET = "chess-studio-assets"
PREFIX = "star-adventures/environment/"
CDN = "https://assets.chess-studio.shadowops.dpdns.org/" + PREFIX
ORIGIN = "https://staging.staradvs.shadowops.dpdns.org"
CACHE = "public, max-age=31536000, immutable"
SHA = re.compile(r"[0-9a-f]{64}\Z")
ACCOUNT = re.compile(r"[a-f0-9]{32}\Z")
SLOTS = (
    ("south-industrial-shell", ((3, 7), (4, 7), (5, 7), (6, 7), (7, 7)), (5, 0, 7)),
    ("west-archive-shell", ((0, 3), (0, 4), (0, 5)), (0, 0, 4)),
    ("east-utilities-shell", ((8, 1), (8, 2), (8, 3)), (8, 0, 2)),
)
MAX_FILE = 4 * 1024**2
MAX_ZIP = 24 * 1024**2
MAX_UNCOMPRESSED = 32 * 1024**2
MAX_BUCKET = 7_000_000_000
MAX_PREFIX = 48 * 1024**2
EXPECTED_SHOTS = {
    f"test-results/k47-full-sector-{state}-{view}-{width}.png"
    for state in ("before", "after")
    for view in ("follow", "overview")
    for width in (390, 1280)
}
EXTRA_SHOTS = {
    f"test-results/k47-full-sector-{state}-west-390.png"
    for state in ("before", "after")
}


class PublishError(ValueError):
    pass


def check(value: bool, message: str) -> None:
    if not value:
        raise PublishError(message)


def glb(data: bytes) -> None:
    check(32 <= len(data) <= MAX_FILE, "GLB outside approved file size")
    check(struct.unpack_from("<III", data) == (0x46546C67, 2, len(data)),
          "invalid embedded glTF 2.0 header")
    length, typ = struct.unpack_from("<II", data, 12)
    check(typ == 0x4E4F534A and length % 4 == 0 and
          20 + length + 8 <= len(data), "invalid embedded JSON chunk")
    try:
        j = json.loads(data[20:20 + length])
    except (ValueError, UnicodeError):
        raise PublishError("malformed glTF JSON") from None
    check(j.get("asset", {}).get("version") == "2.0" and
          isinstance(j.get("meshes"), list) and bool(j["meshes"]) and
          not j.get("extensionsRequired") and
          all("uri" not in x for x in j.get("buffers", [])) and
          all("uri" not in x for x in j.get("images", [])),
          "non-original/externally dependent GLB content")
    chunk_length, chunk_type = struct.unpack_from("<II", data, 20 + length)
    check(chunk_length > 0 and chunk_type == 0x004E4942 and
          20 + length + 8 + chunk_length == len(data),
          "GLB missing one complete embedded binary chunk")


def verify_archive(blob: bytes, source_sha: str) -> tuple[dict, dict[str, bytes]]:
    """Read bytes directly from ZIP: no extraction, symlinks or traversal."""
    check(bool(source.HEX.fullmatch(source_sha)), "full source SHA required")
    check(1000 < len(blob) <= MAX_ZIP, "unbounded source artifact ZIP")
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
        members = archive.infolist()
        names = [m.filename for m in members]
        check(len(names) == len(set(names)), "duplicated ZIP entry")
        check(sum(m.file_size for m in members) <= MAX_UNCOMPRESSED,
              "unbounded extracted artifact")
        for m in members:
            check(not m.is_dir() and not m.flag_bits & 1
                  and not (m.external_attr >> 16) & 0o170000 == 0o120000
                  and ".." not in m.filename.split("/")
                  and not m.filename.startswith("/") and "\\" not in m.filename,
                  "unsafe ZIP entry")
        check(EXPECTED_SHOTS.issubset(set(names)), "required real visual captures missing")
        allowed_starts = ("test-results/k47-full-sector-", "tests/fixtures/k47-",
                          "k47-art-candidate/assets/")
        allowed_fixed = {"k47-art-candidate/manifest.candidate.json",
                         "k47-art-candidate/receipt.json"}
        check(all(name in allowed_fixed or
                  name.startswith(allowed_starts) for name in names),
              "unexpected artifact path")
        for snap in EXPECTED_SHOTS:
            png = archive.read(snap)
            width = int(snap.rsplit("-", 1)[-1].split(".")[0])
            check(len(png) > 24 and png[:8] == b"\x89PNG\r\n\x1a\n" and
                  struct.unpack_from(">II", png, 16) == (width, 850),
                  "real Chromium screenshot is malformed")
        raw_manifest = archive.read("k47-art-candidate/manifest.candidate.json")
        manifest = json.loads(raw_manifest)
        receipt = json.loads(archive.read("k47-art-candidate/receipt.json"))
        check(receipt.get("schemaVersion") == 1 and
              receipt.get("sourceSha") == source_sha and
              receipt.get("published") is False and
              receipt.get("modelCount") == 3 and
              SHA.fullmatch(str(receipt.get("manifestSha256"))) and
              hashlib.sha256(raw_manifest).hexdigest() == receipt["manifestSha256"],
              "source receipt/manifest SHA mismatch")
        check(manifest.get("schemaVersion") == 1 and
              manifest.get("scene") == "meridian.surface" and
              isinstance(manifest.get("slots"), list) and len(manifest["slots"]) == 3,
              "original 3-slot manifest missing")
        entries = {}
        expected_metadata = []
        for slot, (logical_id, cells, anchor) in zip(manifest["slots"], SLOTS):
            check(slot.get("id") == logical_id and
                  slot.get("footprint") == [list(c) for c in cells] and
                  slot.get("anchor") == list(anchor) and
                  slot.get("status") == "published",
                  "slot mismatch with canonical blocked geometry")
            asset = slot.get("asset")
            check(isinstance(asset, dict) and
                  asset.get("license") == "original" and
                  "original" in str(asset.get("source", "")).lower() and
                  SHA.fullmatch(str(asset.get("sha256"))) and
                  type(asset.get("bytes")) is int and
                  32 <= asset["bytes"] <= MAX_FILE,
                  "unapproved model provenance, checksum or size")
            filename = logical_id + "-" + asset["sha256"][:16] + ".glb"
            key = PREFIX + filename
            name = "k47-art-candidate/assets/" + filename
            check(asset.get("url") == CDN + filename and name in names,
                  "immutable CDN path does not match model hash")
            data = archive.read(name)
            check(len(data) == asset["bytes"] and
                  hashlib.sha256(data).hexdigest() == asset["sha256"],
                  "candidate GLB bytes differ from pinned manifest")
            glb(data)
            entries[key] = data
            expected_metadata.append({
                "key": "assets/" + filename, "sha256": asset["sha256"],
                "bytes": asset["bytes"], "id": logical_id,
            })
        check(receipt.get("sha256sums") == expected_metadata and
              receipt.get("bytes") == sum(map(len, entries.values())),
              "receipt model list differs from exact bytes")
        actual_assets = {x for x in names if x.startswith("k47-art-candidate/assets/")}
        check(actual_assets == {"k47-art-candidate/assets/" +
              name.removeprefix(PREFIX) for name in entries},
              "unexpected published model in candidate artifact")
        return manifest, entries
    except (zipfile.BadZipFile, KeyError, UnicodeError, TypeError, ValueError, struct.error) as exc:
        if isinstance(exc, PublishError):
            raise
        raise PublishError("invalid or incomplete source artifact: " +
                           type(exc).__name__) from None


def discover(source_sha: str, token: str) -> dict:
    """Admit current source main and only an exactly matching successful push run."""
    check(bool(source.HEX.fullmatch(source_sha)), "exact full source SHA required")
    reader = source.GithubReader(token)
    source.admit(reader, source_sha)
    response = reader.get("/repos/" + REPO + "/actions/runs?"
                          + "branch=main&head_sha=" + source_sha + "&per_page=60")
    runs = response.get("workflow_runs")
    check(isinstance(runs, list), "cannot inspect source workflow")
    candidates = [r for r in runs if r.get("name") == WORKFLOW and
                  r.get("head_sha") == source_sha and r.get("event") == "push" and
                  r.get("status") == "completed" and r.get("conclusion") == "success"]
    check(bool(candidates), "no successful original-art main visual gate")
    run = max(candidates, key=lambda r: r["id"])
    payload = reader.get(f"/repos/{REPO}/actions/runs/{run['id']}/artifacts?per_page=100")
    rows = payload.get("artifacts")
    check(isinstance(rows, list), "source artifact list unavailable")
    match = [a for a in rows if a.get("name") == "k47-three-building-sector-" + source_sha
             and a.get("expired") is False]
    check(len(match) == 1, "exact unexpired source GLB artifact required")
    a = match[0]
    check(type(a.get("id")) is int and a["id"] > 0 and
          re.fullmatch(r"sha256:[0-9a-f]{64}", str(a.get("digest"))),
          "source artifact digest not authenticated")
    return {"runId": run["id"], "artifactId": a["id"],
            "artifactDigest": a["digest"], "sourceSha": source_sha}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def public_probe(entries: dict[str, bytes]) -> list[str]:
    """Read the public CDN without credentials; distinguish 404 from corruption.

    Missing immutable keys are an expected NOT-YET-PUBLISHED state. A wrong
    checksum, CORS, cache policy, content type, redirect or other HTTP failure
    is NEVER treated as proof of publication or as a safe missing object.
    """
    opener = urllib.request.build_opener(NoRedirect)
    missing: list[str] = []
    for key, blob in sorted(entries.items()):
        check(key.startswith(PREFIX) and len(blob) <= MAX_FILE,
              "outside approved K-47 CDN probe scope")
        url = "https://assets.chess-studio.shadowops.dpdns.org/" + key
        req = urllib.request.Request(url, headers={
            "Origin": ORIGIN, "Cache-Control": "no-cache",
            "User-Agent": "ShadowOps-K47-verified-art/1",
        })
        try:
            with opener.open(req, timeout=25) as resp:
                check(resp.status == 200 and resp.geturl() == url and
                      resp.headers.get_content_type() == "model/gltf-binary" and
                      "immutable" in resp.headers.get("Cache-Control", "").lower() and
                      resp.headers.get("Access-Control-Allow-Origin", "") in ("*", ORIGIN),
                      "K-47 public GLB HTTP/CORS/immutability headers not verified")
                data = resp.read(len(blob) + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                missing.append(key)
                continue
            raise PublishError("K-47 public CDN returned unexpected HTTP status") from None
        except PublishError:
            # Integrity failures are NOT network outages: surface their
            # precise reason so a corrupted public object can never masquerade
            # as an ordinary CDN availability problem.
            raise
        except (OSError, ValueError):
            raise PublishError("K-47 public CDN verification unavailable") from None
        check(data == blob, "K-47 public CDN model SHA mismatch")
    return missing


def public_verify(entries: dict[str, bytes]) -> None:
    check(not public_probe(entries),
          "K-47 public CDN missing one or more immutable objects")


def public_activation_evidence(source_sha: str, manifest: dict,
                               entries: dict[str, bytes]) -> dict:
    """Only call after public_probe verified ALL bytes and headers."""
    check(bool(source.HEX.fullmatch(source_sha)) and len(entries) == 3,
          "incomplete original model public proof")
    return {
        "schemaVersion": 1,
        "sourceSha": source_sha,
        "cdnPublicBytesVerified": True,
        "verifiedModelCount": len(entries),
        "models": [{
            "url": "https://assets.chess-studio.shadowops.dpdns.org/" + key,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "bytes": len(blob),
        } for key, blob in sorted(entries.items())],
        "manifest": manifest,
        "humanVisualApproval": False,
        "activationDone": False,
        "note": "Exact public byte proof only; activation requires a separately reviewed source PR.",
    }


def publisher_client():
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    check(bool(ACCOUNT.fullmatch(account)), "verified Cloudflare account required")
    key = os.environ.get("STARADVS_R2_ACCESS_KEY_ID", "")
    secret = os.environ.get("STARADVS_R2_SECRET_ACCESS_KEY", "")
    check(bool(key and secret), "dedicated Star Adventures R2 credentials required")
    try:
        import boto3
    except ImportError:
        raise PublishError("pinned boto3 required only for explicit publication") from None
    return boto3.client(
        "s3", endpoint_url=f"https://{account}.r2.cloudflarestorage.com",
        region_name="auto", aws_access_key_id=key, aws_secret_access_key=secret)


def publish(source_sha: str, manifest: dict, entries: dict[str, bytes]):
    # Separate main/CI recheck immediately before opening any cloud writes.
    source.admit(source.GithubReader(os.environ.get("GH_TOKEN", "")), source_sha)
    client = publisher_client()
    objects: dict[str, int] = {}
    marker = None
    for _ in range(100):
        kwargs = {"Bucket": BUCKET, "MaxKeys": 1000}
        if marker:
            kwargs["ContinuationToken"] = marker
        try:
            page = client.list_objects_v2(**kwargs)
        except Exception:
            raise PublishError("cannot establish complete shared R2 inventory") from None
        check(isinstance(page, dict) and type(page.get("IsTruncated")) is bool,
              "incomplete R2 capacity evidence")
        for item in page.get("Contents", []):
            name, size = item.get("Key"), item.get("Size")
            check(isinstance(name, str) and name not in objects and
                  type(size) is int and size >= 0, "bad shared bucket inventory")
            objects[name] = size
        if not page["IsTruncated"]:
            break
        new_marker = page.get("NextContinuationToken")
        check(isinstance(new_marker, str) and new_marker != marker and new_marker,
              "ambiguous R2 inventory continuation")
        marker = new_marker
    else:
        raise PublishError("shared R2 inventory exceeds bounded pages")
    additions = sum(len(blob) for key, blob in entries.items() if key not in objects)
    check(sum(objects.values()) + additions <= MAX_BUCKET and
          sum(size for key, size in objects.items() if key.startswith(PREFIX)) +
          additions <= MAX_PREFIX,
          "R2 shared/K47 prefix free-tier budget exceeded")
    for key, blob in entries.items():
        if key in objects:
            check(objects[key] == len(blob), "immutable R2 key has different size")
        else:
            try:
                client.put_object(Bucket=BUCKET, Key=key, Body=blob,
                                  ContentType="model/gltf-binary",
                                  CacheControl=CACHE, IfNoneMatch="*")
            except Exception:
                raise PublishError("R2 immutable create-once rejected") from None
        try:
            obj = client.get_object(Bucket=BUCKET, Key=key)
            stream = obj["Body"]
            try:
                body = stream.read(len(blob) + 1)
            finally:
                stream.close()
            check(obj.get("ContentType") == "model/gltf-binary" and
                  obj.get("CacheControl") == CACHE and
                  body == blob, "R2 object readback differs from approved original")
        except PublishError:
            raise
        except Exception:
            raise PublishError("R2 object readback not verifiable") from None
    # Independent public HTTPS/CDN bytes verification is required before a
    # receipt can authorize the game's separate manifest activation PR.
    public_verify(entries)
    return {
        "schemaVersion": 1, "sourceSha": source_sha,
        "verifiedKeys": list(entries), "verifiedModelCount": 3,
        "publicCdnsVerified": True, "activationDone": False,
        "manifest": manifest,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=("discover", "validate", "probe", "publish"))
    p.add_argument("--source-sha", required=True)
    p.add_argument("--artifact", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--confirm", default="")
    args = p.parse_args()
    try:
        if args.action == "discover":
            result = discover(args.source_sha, os.environ.get("GH_TOKEN", ""))
            if args.out:
                args.out.write_text(json.dumps(result, indent=2) + "\n")
            print("K47_SOURCE_ARTIFACT_ADMITTED " + json.dumps(result))
            return 0
        check(args.artifact is not None and args.artifact.is_file(),
              "exact source archive required")
        manifest, entries = verify_archive(args.artifact.read_bytes(), args.source_sha)
        print("K47_ART_CANDIDATE_VERIFIED " + json.dumps({
            "sourceSha": args.source_sha, "glbs": len(entries),
            "bytes": sum(map(len, entries.values())), "writes": 0}))
        if args.action == "probe":
            check(args.out is not None and not args.out.exists(),
                  "fresh CDN proof destination required")
            missing = public_probe(entries)
            if missing:
                print("K47_PUBLIC_CDN_PENDING " + json.dumps({
                    "sourceSha": args.source_sha, "missing": len(missing),
                    "verified": len(entries) - len(missing),
                    "activationDone": False, "writes": 0,
                }, sort_keys=True))
                return 0
            evidence = public_activation_evidence(args.source_sha, manifest, entries)
            args.out.write_text(json.dumps(evidence, indent=2) + "\n")
            print("K47_PUBLIC_CDN_BYTES_VERIFIED " + json.dumps({
                "sourceSha": args.source_sha, "models": len(entries),
                "activationDone": False, "writes": 0,
            }, sort_keys=True))
            return 0
        if args.action == "publish":
            check(args.confirm == "K47-VISUAL-APPROVED",
                  "explicit approved visual release authorization required")
            receipt = publish(args.source_sha, manifest, entries)
            check(args.out is not None and not args.out.exists(),
                  "fresh receipt destination required")
            args.out.write_text(json.dumps(receipt, indent=2) + "\n")
            print("K47_PUBLIC_R2_ORIGINALS_VERIFIED source_sha=" + args.source_sha)
        return 0
    except (PublishError, source.SourceAdmissionError, OSError, UnicodeError) as exc:
        print("K47_R2_PUBLICATION_BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
