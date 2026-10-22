"""Offline Chronicle watch: transient failure suppression and issue lifecycle."""
from pathlib import Path
import datetime as dt
import io
import struct
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_staging_watch as watch

SHA = "a" * 40
OLD = dt.datetime(2026, 10, 20, 10, 0, tzinfo=dt.timezone.utc)
NOW = OLD + dt.timedelta(hours=2)


def gh(path, token, *, method="GET", payload=None):
    if path.endswith("/commits/main"):
        return {"sha": SHA, "commit": {"committer": {"date": OLD.isoformat()}}}
    if "/actions/artifacts?" in path:
        return {"artifacts": []}
    return {"id": 123}


def url(address, token=""):
    if address.endswith("/health"):
        return {"ok": True}
    if address.endswith("/ready"):
        return {"ok": True, "storage": "mongo"}
    return {"build": SHA}


class WatchTest(unittest.TestCase):
    def setUp(self):
        # Existing unit tests use a synthetic HTTP manifest; keep the public
        # HTML + asset probe deterministic without making network requests.
        mocked = patch.object(watch.pages, "probe_react_preview", return_value="ok")
        self.game_probe = mocked.start()
        self.addCleanup(mocked.stop)
        self.real_model_probe = watch.probe_public_glb
        model = patch.object(watch, "probe_public_glb", return_value="ok")
        self.model_probe = model.start()
        self.addCleanup(model.stop)

    def test_canonical_model_glb_header_is_checked_from_exact_public_origin(self):
        class Response:
            def __init__(self, req, header, *, status=200, destination=None,
                         mime="model/gltf-binary", content_range="bytes 0-11/128"):
                self.status = status
                self.destination = req.full_url if destination is None else destination
                self.headers = {"Content-Type": mime, "Content-Range": content_range}
                self.body = io.BytesIO(header)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return self.destination
            def read(self, count):
                self.assert_count = count
                return self.body.read(count)

        good = struct.pack("<4sII", b"glTF", 2, 128)
        requests = []
        def open_good(req, timeout):
            requests.append((req, timeout))
            return Response(req, good, status=206)
        # Real network disabled. Exercise the header verifier itself rather
        # than the per-test high-level health mock.
        with patch.object(watch, "probe_public_glb", wraps=self.real_model_probe):
            with patch.object(watch, "open_no_redirect", side_effect=open_good):
                self.assertEqual(watch.probe_public_glb(), "ok")
        req, timeout = requests[0]
        self.assertEqual(req.full_url, watch.ORIGIN + "/models/matthias-home-canonical.glb")
        self.assertEqual(timeout, 10)
        self.assertEqual(req.get_header("Range"), "bytes=0-11")
        self.assertIsNone(req.get_header("Authorization"))
        self.assertIsNone(req.get_header("Cookie"))

        cases = [
            (good, 206, None, "model/gltf-binary", "bytes 0-11/128", "ok"),
            (good, 206, None, "model/gltf-binary", "bytes 20-31/128", "invalid"),
            (b"<html>oops!!", 200, None, "text/html", "", "invalid"),
            (b'{"error":2}', 200, None, "application/json", "", "invalid"),
            (struct.pack("<4sII", b"glTF", 1, 128), 200, None, "application/octet-stream", "", "invalid"),
            (struct.pack("<4sII", b"glTF", 2, 8), 200, None, "application/octet-stream", "", "invalid"),
            (struct.pack("<4sII", b"WRNG", 2, 128), 200, None, "application/octet-stream", "", "invalid"),
            (good[:7], 200, None, "application/octet-stream", "", "invalid"),
            (good, 200, "https://foreign.invalid/model.glb", "model/gltf-binary", "", "invalid"),
            (good, 301, None, "model/gltf-binary", "", "invalid"),
        ]
        for header, status, dest, mime, byte_range, expected in cases:
            with self.subTest(status=status,expected=expected,header=header[:4],mime=mime):
                def serve(req, timeout):
                    return Response(req, header, status=status,
                                    destination=dest, mime=mime, content_range=byte_range)
                with patch.object(watch, "probe_public_glb", wraps=self.real_model_probe):
                    with patch.object(watch, "open_no_redirect", side_effect=serve):
                        self.assertEqual(watch.probe_public_glb(), expected)

    def test_public_glb_advertised_size_matches_exact_http_range(self):
        class Response:
            def __init__(self, req, *, status, range_header=None, content_length=None):
                self.status = status
                self.url = req.full_url
                self.headers = {"Content-Type": "model/gltf-binary"}
                if range_header is not None:
                    self.headers["Content-Range"] = range_header
                if content_length is not None:
                    self.headers["Content-Length"] = content_length
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return self.url
            def read(self, count):
                self.assert_read_size = count
                return struct.pack("<4sII", b"glTF", 2, 128)

        cases = [
            (206, "bytes 0-11/128", "12", "ok"),
            (206, "bytes 0-11/128", None, "ok"),
            (206, "bytes 0-11/129", "12", "invalid"),
            (206, "bytes 0-11/127", "12", "invalid"),
            (206, "bytes 0-11/*", "12", "invalid"),
            (206, "bytes 0-11/not-a-size", "12", "invalid"),
            (206, "bytes 0-11/128 junk", "12", "invalid"),
            (206, "bytes 0-11/128", "13", "invalid"),
            (206, "bytes 0-11/128", "not-a-length", "invalid"),
            (200, None, "128", "invalid"),  # only the first 12 bytes actually arrived
            (200, None, None, "invalid"),  # chunked 200 must also finish the body
            (200, None, "127", "invalid"),
            (200, None, "129", "invalid"),
            (200, None, "bad", "invalid"),
        ]
        for status, range_header, length, expected in cases:
            with self.subTest(status=status, range_header=range_header,
                              content_length=length):
                def serve(req, timeout):
                    self.assertEqual(timeout, 10)
                    return Response(req, status=status, range_header=range_header,
                                    content_length=length)
                with patch.object(watch, "probe_public_glb", wraps=self.real_model_probe):
                    with patch.object(watch, "open_no_redirect", side_effect=serve):
                        self.assertEqual(watch.probe_public_glb(), expected)

    def test_public_glb_200_streaming_fallback_verifies_real_size_to_eof(self):
        header = struct.pack("<4sII", b"glTF", 2, 128)
        results = [
            (header + b"\x00" * 116, None, "ok"),
            (header + b"\x00" * 116, "128", "ok"),
            (header + b"\x00" * 115, None, "invalid"),
            (header + b"\x00" * 117, None, "invalid"),
            (header + b"\x00" * 115, "128", "invalid"),
            (header + b"\x00" * 117, "128", "invalid"),
            (header + b"\x00" * 116, "127", "invalid"),
        ]
        class Response:
            status = 200
            def __init__(self, req, payload, length):
                self.url = req.full_url
                self.headers = {"Content-Type": "model/gltf-binary"}
                if length is not None:
                    self.headers["Content-Length"] = length
                self.body = io.BytesIO(payload)
                self.read_sizes = []
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return self.url
            def read(self, n):
                self.read_sizes.append(n)
                return self.body.read(n)
        for payload, length, expected in results:
            with self.subTest(length=length, payload_size=len(payload)):
                seen = []
                def serve(req, timeout):
                    response = Response(req, payload, length)
                    seen.append(response)
                    return response
                with patch.object(watch, "probe_public_glb", wraps=self.real_model_probe):
                    with patch.object(watch, "open_no_redirect", side_effect=serve):
                        self.assertEqual(watch.probe_public_glb(), expected)
                self.assertEqual(seen[0].read_sizes[0], 12)
                self.assertTrue(all(n <= 64 * 1024 for n in seen[0].read_sizes))

    def test_public_glb_unbounded_large_200_response_is_inconclusive_and_bounded(self):
        header = struct.pack("<4sII", b"glTF", 2,
                             watch.MAX_PUBLIC_GLB_FALLBACK_BYTES + 1)
        class Response:
            status = 200
            headers = {"Content-Type": "model/gltf-binary"}
            def __init__(self, req):
                self.url = req.full_url
                self.body = io.BytesIO(header)
                self.calls = 0
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return self.url
            def read(self, count):
                self.calls += 1
                return self.body.read(count)
        opened = []
        def serve(req, timeout):
            response = Response(req)
            opened.append(response)
            return response
        with patch.object(watch, "probe_public_glb", wraps=self.real_model_probe):
            with patch.object(watch, "open_no_redirect", side_effect=serve):
                self.assertEqual(watch.probe_public_glb(), "unavailable")
        self.assertEqual(opened[0].calls, 1, "Oversize body must never be fetched")

    def test_canonical_model_edge_vs_structural_classification(self):
        for result in ("invalid", "http_404", "http_403"):
            with self.subTest(result=result):
                self.assertEqual(watch.pages_failure_key(result), "pages-game")
        for result in ("http_429", "http_503", "http_522", "unavailable"):
            with self.subTest(result=result):
                self.assertEqual(watch.pages_failure_key(result), "pages-edge")
        with patch.object(watch, "probe_public_glb", wraps=self.real_model_probe):
            for exc, expected in (
                (urllib.error.HTTPError("https://example.invalid", 404, "not found", {}, None), "http_404"),
                (urllib.error.HTTPError("https://example.invalid", 503, "unavailable", {}, None), "http_503"),
                (urllib.error.URLError("timeout"), "unavailable"),
            ):
                with self.subTest(expected=expected):
                    with patch.object(watch, "open_no_redirect", side_effect=exc):
                        self.assertEqual(watch.probe_public_glb(), expected)

    @patch.object(watch, "source_ci_status", return_value=("pending", None))
    def test_missing_public_glb_is_detected_before_source_ci_ready(self, _):
        self.model_probe.return_value = "invalid"
        self.assertEqual(set(watch.failures("t", get=url, gh=gh, now=NOW)), {"pages-model"})
        self.model_probe.return_value = "http_503"
        self.assertEqual(set(watch.failures("t", get=url, gh=gh, now=NOW)), {"pages-model-edge"})
        self.model_probe.return_value = "ok"
        self.assertEqual(watch.failures("t", get=url, gh=gh, now=NOW), {})

    def test_glb_edge_requires_three_samples_but_corruption_only_two(self):
        for samples, expected, pauses in (
            ([{"pages-model": "corrupt"}, {"pages-model": "corrupt"}],
             {"pages-model": "corrupt"}, [90]),
            ([{"pages-model-edge": "503"}, {"pages-model-edge": "503"}, {}],
             {}, [90, 90]),
            ([{"pages-model-edge": "503"}, {"pages-model": "corrupt"},
              {"pages-model": "corrupt"}], {"pages-model": "corrupt"}, [90, 90]),
        ):
            with self.subTest(expected=expected):
                items = iter(samples)
                elapsed = []
                observed = watch.confirmed_failures(
                    "t", probe=lambda _: next(items), pause=elapsed.append
                )
                self.assertEqual(observed, expected)
                self.assertEqual(elapsed, pauses)

    def test_advanced_source_main_suppresses_only_obsolete_sha_drift(self):
        newer = "b" * 40
        seen = []
        def advancing_gh(path, token, **kwargs):
            if path.endswith("/commits/main"):
                seen.append("main")
                return {"sha": SHA if len(seen) == 1 else newer}
            return gh(path, token, **kwargs)
        def older_pages(address, token=""):
            if "/release.json?" in address:
                return {"build": newer}
            return url(address, token)
        with patch.object(watch, "source_ci_status", return_value=("ready", OLD)):
            with patch.object(watch.receipts, "evidence_ok", return_value=False):
                with patch.object(watch.receipts, "public_api_revision_state",
                                  return_value="different"):
                    self.game_probe.return_value = "js_mime"
                    bad = watch.failures(
                        "t", get=older_pages, gh=advancing_gh, now=NOW)
        # Pages JS truly is broken, but the release-lag evidence was collected
        # against an old source SHA, which is no longer the protected main.
        self.assertEqual(set(bad), {"pages-game"})
        self.assertEqual(seen, ["main", "main"])

    def test_stable_source_main_keeps_valid_deployment_drift_alerts(self):
        calls = []
        def stable_gh(path, token, **kwargs):
            if path.endswith("/commits/main"):
                calls.append(path)
            return gh(path, token, **kwargs)
        def older_pages(address, token=""):
            if "/release.json?" in address:
                return {"build": "b" * 40}
            return url(address, token)
        with patch.object(watch, "source_ci_status", return_value=("ready", OLD)):
            with patch.object(watch.receipts, "evidence_ok", return_value=False):
                with patch.object(watch.receipts, "public_api_revision_state",
                                  return_value="different"):
                    bad = watch.failures(
                        "t", get=older_pages, gh=stable_gh, now=NOW)
        self.assertEqual(set(bad),
                         {"frontend-lag", "backend-lag", "api-revision"})
        self.assertEqual(len(calls), 2)

    def test_no_extra_source_main_read_during_green_ci_grace_or_pending(self):
        for ci_status in (("pending", None),
                          ("ready", NOW - dt.timedelta(minutes=5))):
            with self.subTest(ci_status=ci_status):
                seen = []
                def tracked_gh(path, token, **kwargs):
                    if path.endswith("/commits/main"):
                        seen.append(path)
                    return gh(path, token, **kwargs)
                with patch.object(watch, "source_ci_status", return_value=ci_status):
                    self.assertEqual(watch.failures(
                        "t", get=url, gh=tracked_gh, now=NOW), {})
                self.assertEqual(len(seen), 1)

    def test_unverifiable_latest_source_sha_fails_closed_before_drift_alert(self):
        for value in (None, "not-a-sha", {"sha": "short"}):
            with self.subTest(value=value):
                reads = []
                def malformed_gh(path, token, **kwargs):
                    if path.endswith("/commits/main"):
                        reads.append(path)
                        return {"sha": SHA} if len(reads) == 1 else value
                    return gh(path, token, **kwargs)
                with patch.object(watch, "source_ci_status",
                                  return_value=("ready", OLD)):
                    with patch.object(watch.receipts, "evidence_ok",
                                      return_value=False):
                        with self.assertRaisesRegex(RuntimeError,
                                                   "Cannot revalidate protected"):
                            watch.failures("t", get=url, gh=malformed_gh, now=NOW)
                self.assertEqual(len(reads), 2)

    def test_ci_grace_starts_when_last_verified_workflow_finished(self):
        source = {
            "sha": SHA,
            "commit": {"committer": {"date": OLD.isoformat()}},
        }
        # The commit is 2h old, but all three required jobs only finished 5m
        # ago. It would be a false staging drift to alert immediately.
        recently_green = NOW - dt.timedelta(minutes=5)
        with patch.object(watch, "source_ci_status",
                          return_value=("ready", recently_green)):
            with patch.object(watch.receipts, "evidence_ok") as evidence:
                with patch.object(watch.receipts, "public_api_revision_state") as live:
                    def gh_recent(path, token, **kwargs):
                        if path.endswith("/commits/main"):
                            return source
                        self.fail("Not admitted to older-than-grace deployment probes")
                    self.assertEqual(watch.failures("t", get=url, gh=gh_recent, now=NOW), {})
                    evidence.assert_not_called()
                    live.assert_not_called()

    def test_source_ci_status_trusts_existing_gate_and_latest_run_time(self):
        workflow_ids = list(watch.ci.REQUIRED)
        base = dt.datetime(2026, 10, 20, 10, 30, tzinfo=dt.timezone.utc)
        def source_run(wid, stamp, **changes):
            name, path = watch.ci.REQUIRED[wid]
            row = {
                "id": wid, "workflow_id": wid, "name": name,
                "path": path, "head_sha": SHA, "event": "push",
                "head_branch": "main",
                "repository": {"full_name": watch.ci.SOURCE},
                "status": "completed", "conclusion": "success",
                "updated_at": stamp.isoformat(),
            }
            row.update(changes)
            return row

        rows = [
            source_run(workflow_ids[0], base),
            source_run(workflow_ids[1], base + dt.timedelta(minutes=2)),
            source_run(workflow_ids[2], base + dt.timedelta(minutes=4)),
        ]
        def fake_payload(runs):
            return {"total_count": len(runs), "workflow_runs": runs}
        with patch.object(watch.ci, "github_runs", return_value=fake_payload(rows)) as fetch:
            self.assertEqual(watch.source_ci_status(SHA, "test-token"),
                             ("ready", base + dt.timedelta(minutes=4)))
            fetch.assert_called_once_with(SHA, "test-token")

        # A later successful rerun controls the next eligibility timestamp.
        newer = source_run(workflow_ids[0], base + dt.timedelta(minutes=8),
                           id=workflow_ids[0] + 1000000000)
        with patch.object(watch.ci, "github_runs", return_value=fake_payload(rows + [newer])):
            self.assertEqual(watch.source_ci_status(SHA, "test-token"),
                             ("ready", base + dt.timedelta(minutes=8)))

        # Missing workflow, unfinished workflow and untrusted workflow source
        # must never masquerade as a completed ready release.
        with patch.object(watch.ci, "github_runs", return_value=fake_payload(rows[:-1])):
            self.assertEqual(watch.source_ci_status(SHA, "test-token"), ("pending", None))
        pending = list(rows)
        pending[1] = source_run(workflow_ids[1], base, status="in_progress", conclusion=None)
        with patch.object(watch.ci, "github_runs", return_value=fake_payload(pending)):
            self.assertEqual(watch.source_ci_status(SHA, "test-token"), ("pending", None))
        foreign = list(rows)
        foreign[1] = source_run(workflow_ids[1], base, head_branch="feature")
        with patch.object(watch.ci, "github_runs", return_value=fake_payload(foreign)):
            with self.assertRaises(watch.ci.AdmissionError):
                watch.source_ci_status(SHA, "test-token")

    def test_ready_workflows_require_trustworthy_timestamp(self):
        workflow_ids = list(watch.ci.REQUIRED)
        def rows_with(value):
            rows = []
            for wid in workflow_ids:
                name, path = watch.ci.REQUIRED[wid]
                rows.append({
                    "id": wid, "workflow_id": wid, "name": name, "path": path,
                    "head_sha": SHA, "head_branch": "main", "event": "push",
                    "repository": {"full_name": watch.ci.SOURCE},
                    "status": "completed", "conclusion": "success",
                    "updated_at": value,
                })
            return {"total_count": 3, "workflow_runs": rows}
        for stamp in (None, "", "nonsense", "2026-10-20T10:00:00"):
            with self.subTest(stamp=stamp):
                with patch.object(watch.ci, "github_runs", return_value=rows_with(stamp)):
                    with self.assertRaises(RuntimeError):
                        watch.source_ci_status(SHA, "test-token")

    def test_json_reader_requires_exact_final_https_url_and_status(self):
        url = watch.ORIGIN + "/release.json?watch=123"

        class Response:
            headers = {"Content-Type": "application/json; charset=utf-8"}
            def __init__(self, request, *, final=None, status=200):
                self.body = io.BytesIO(b'{"build": "' + SHA.encode() + b'"}')
                self.final = request.full_url if final is None else final
                self.status = status

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return self.final

            def read(self, amount=-1):
                return self.body.read(amount)

        requested = []
        def mock_open(req, timeout):
            requested.append(req)
            self.assertEqual(timeout, 15)
            return Response(req)

        with patch.object(watch, "open_no_redirect", side_effect=mock_open):
            self.assertEqual(watch.get_url(url), {"build": SHA})
        self.assertEqual(requested[0].full_url, url)
        self.assertIsNone(requested[0].get_header("Authorization"))

        for destination in (
            "https://unrelated.invalid/release.json?watch=123",
            watch.ORIGIN + "/login",
            watch.ORIGIN + "/release.json?watch=elsewhere",
            "http://staging.chronicles.shadowops.dpdns.org/release.json?watch=123",
        ):
            with self.subTest(destination=destination):
                def redirect(req, timeout):
                    return Response(req, final=destination)
                with patch.object(watch, "open_no_redirect", side_effect=redirect):
                    with self.assertRaisesRegex(ValueError, "redirect"):
                        watch.get_url(url)

        for status in (204, 302, 418, 503):
            with self.subTest(status=status):
                with patch.object(watch, "open_no_redirect",
                                  side_effect=lambda req, timeout: Response(req, status=status)):
                    with self.assertRaisesRegex(ValueError, "status"):
                        watch.get_url(url)

    def test_public_json_rejects_non_json_mime_and_oversized_payload(self):
        origin = watch.ORIGIN + "/release.json?watch=124"

        class Response:
            status = 200

            def __init__(self, req, content, mime):
                self.req = req
                self.stream = io.BytesIO(content)
                self.headers = {"Content-Type": mime}
                self.read_sizes = []

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return self.req.full_url

            def read(self, amount=-1):
                self.read_sizes.append(amount)
                return self.stream.read(amount)

        good = b'{"build": "' + SHA.encode() + b'"}'
        for mime in ("text/html", "text/plain", "application/javascript", "",
                     "application/octet-stream"):
            with self.subTest(mime=mime):
                with patch.object(watch, "open_no_redirect",
                                  side_effect=lambda req, timeout: Response(req, good, mime)):
                    with self.assertRaisesRegex(ValueError, "content type"):
                        watch.get_url(origin)

        huge = good + b" " * watch.MAX_PUBLIC_JSON_BYTES
        response = None
        def open_huge(req, timeout):
            nonlocal response
            response = Response(req, huge, "application/json")
            return response
        with patch.object(watch, "open_no_redirect", side_effect=open_huge):
            with self.assertRaisesRegex(ValueError, "Oversized"):
                watch.get_url(origin)
        self.assertEqual(response.read_sizes, [watch.MAX_PUBLIC_JSON_BYTES + 1])

        for mime in ("application/json", "application/problem+json",
                     "application/json; charset=utf-8"):
            with self.subTest(mime=mime):
                with patch.object(watch, "open_no_redirect",
                                  side_effect=lambda req, timeout: Response(req, good, mime)):
                    self.assertEqual(watch.get_url(origin), {"build": SHA})

    def test_github_issue_listing_is_not_capped_like_public_health_json(self):
        origin = ("https://api.github.com/repos/" + watch.INFRA +
                  "/issues?state=open&per_page=100&page=1")
        body = b'[{"body":"' + b"x" * (watch.MAX_PUBLIC_JSON_BYTES + 1) + b'"}]'

        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __init__(self, request):
                self.request = request
                self.stream = io.BytesIO(body)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return self.request.full_url

            def read(self, amount=-1):
                return self.stream.read(amount)

        with patch.object(watch, "open_no_redirect",
                          side_effect=lambda req, timeout: Response(req)):
            rows = watch.get_url(origin, "read-only-token")
        self.assertEqual(len(rows[0]["body"]), watch.MAX_PUBLIC_JSON_BYTES + 1)

    def test_redirected_github_json_cannot_substitute_issue_listing(self):
        api_url = "https://api.github.com/repos/" + watch.INFRA + "/issues?state=open"
        class Redirected:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return "https://github.com/login"
            def read(self, size=-1):
                return b"[]"
        with patch.object(watch, "open_no_redirect", return_value=Redirected()):
            with self.assertRaisesRegex(ValueError, "redirect"):
                watch.get_url(api_url, "read-only-token")

    def test_no_redirect_transport_blocks_cross_origin_auth_before_following(self):
        request = watch.urllib.request.Request(
            "https://api.github.com/repos/" + watch.INFRA + "/issues",
            headers={"Authorization": "Bearer TEST-SECRET"},
        )
        seen = []

        class Opener:
            def open(self, req, timeout):
                seen.append((req, timeout))
                return object()

        def builder(*handlers):
            self.assertEqual(len(handlers), 1)
            blocker = handlers[0]
            self.assertIsInstance(blocker, watch.RejectHttpRedirects)
            # 301/302/303/307/308 must ALL refuse a second request carrying
            # Authorization, even to the same origin.
            for code in (301, 302, 303, 307, 308):
                self.assertIsNone(blocker.redirect_request(
                    request, None, code, "redirect", {"Location": "https://evil.invalid/"},
                    "https://evil.invalid/"
                ))
            return Opener()

        with patch.object(watch.urllib.request, "build_opener", side_effect=builder):
            watch.open_no_redirect(request, timeout=20)
        self.assertEqual(len(seen), 1)
        self.assertIs(seen[0][0], request)
        self.assertEqual(seen[0][1], 20)
        self.assertIn("Bearer TEST-SECRET", request.get_header("Authorization"))
        with self.assertRaisesRegex(ValueError, "requires HTTPS"):
            watch.open_no_redirect(
                watch.urllib.request.Request("http://api.github.com/"),
                timeout=20
            )

    def test_github_write_uses_protected_transport_and_rejects_bad_response(self):
        class Response:
            def __init__(self, req, *, status=200, redirected=False):
                self.req = req
                self.status = status
                self.redirected = redirected

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return "https://evil.invalid/hijack" if self.redirected else self.req.full_url

            def read(self, size=-1):
                return b'{"number": 42}'

        for method, status in (("POST", 201), ("PATCH", 200)):
            seen = []
            def open_mock(req, *, timeout):
                seen.append((req, timeout))
                return Response(req, status=status)
            with patch.object(watch, "open_no_redirect", side_effect=open_mock):
                result = watch.github(
                    "repos/" + watch.INFRA + "/issues",
                    "TEST-SECRET", method=method,
                    payload={"body": "incident"},
                )
            self.assertEqual(result, {"number": 42})
            self.assertEqual(seen[0][1], 20)
            req = seen[0][0]
            self.assertEqual(req.get_header("Authorization"), "Bearer TEST-SECRET")
            self.assertEqual(req.get_method(), method)
            self.assertEqual(req.full_url, "https://api.github.com/repos/" +
                             watch.INFRA + "/issues")
            with patch.object(watch, "open_no_redirect",
                              side_effect=lambda req, *, timeout: Response(
                                  req, status=status, redirected=True
                              )):
                with self.assertRaisesRegex(ValueError, "redirect"):
                    watch.github(
                        "repos/" + watch.INFRA + "/issues", "TEST-SECRET",
                        method=method, payload={"body": "incident"}
                    )
        with patch.object(watch, "open_no_redirect",
                          side_effect=lambda req, *, timeout: Response(req, status=503)):
            with self.assertRaisesRegex(ValueError, "status"):
                watch.github(
                    "repos/" + watch.INFRA + "/issues", "TEST-SECRET",
                    method="PATCH", payload={"body": "incident"}
                )

    @patch.object(watch, "source_ci_status", return_value=("pending", None))
    def test_api_health_and_readiness_payload_contract_is_required(self, _):
        baseline = watch.failures("t", get=url, gh=gh, now=NOW)
        self.assertEqual(baseline, {})
        cases = (
            ("/health", {"detail": "gateway error"}),
            ("/health", {"ok": False}),
            ("/health", {"ok": 1}),
            ("/health", []),
            ("/health", None),
            ("/ready", {"detail": "db unavailable"}),
            ("/ready", {"ok": False, "storage": "mongo"}),
            ("/ready", {"ok": 1, "storage": "mongo"}),
            ("/ready", {"ok": True}),
            ("/ready", {"ok": True, "storage": "redis"}),
            ("/ready", ["ok"]),
        )
        for suffix, payload in cases:
            with self.subTest(route=suffix, payload=payload):
                def response(address, token=""):
                    if address.endswith(suffix):
                        return payload
                    return url(address, token)
                self.assertEqual(set(watch.failures(
                    "t", get=response, gh=gh, now=NOW)), {"api-health"})

    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch, "source_ci_status", return_value=("ready", OLD))
    def test_false_healthy_ready_payload_suppresses_revision_probe(self, _, __):
        def response(address, token=""):
            if address.endswith("/ready"):
                return {"ok": True, "storage": "not-mongo"}
            return url(address, token)
        with patch.object(watch.receipts, "public_api_revision_state") as live:
            bad = watch.failures("t", get=response, gh=gh, now=NOW)
            self.assertEqual(set(bad), {"api-health"})
            live.assert_not_called()

    @patch.object(watch, "source_ci_status", return_value=("pending", None))
    def test_api_https_429_5xx_timeouts_are_transient_not_contract_failures(self, _):
        def fails(exc):
            def get(address, token=""):
                if address.endswith("/health") or address.endswith("/ready"):
                    raise exc
                return url(address, token)
            return watch.failures("t", get=get, gh=gh, now=NOW)

        for status in (429, 500, 503, 522, 599):
            for endpoint in ("/health", "/ready"):
                with self.subTest(status=status, endpoint=endpoint):
                    err = urllib.error.HTTPError(
                        "https://example.invalid" + endpoint, status, "edge", {}, None
                    )
                    self.assertEqual(set(fails(err)), {"api-health-edge"})
        for exc in (TimeoutError("timeout"), urllib.error.URLError("offline"),
                    ConnectionError("connection reset")):
            with self.subTest(error=type(exc).__name__):
                self.assertEqual(set(fails(exc)), {"api-health-edge"})
        for status in (400, 401, 403, 404):
            with self.subTest(status=status):
                err = urllib.error.HTTPError(
                    "https://example.invalid/ready", status, "bad route", {}, None
                )
                self.assertEqual(set(fails(err)), {"api-health"})
        self.assertEqual(set(fails(ValueError("HTML served for JSON"))), {"api-health"})

    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch, "source_ci_status", return_value=("ready", OLD))
    def test_api_edge_error_does_not_probe_api_release_revision(self, _, __):
        def get(address, token=""):
            if address.endswith("/ready"):
                raise urllib.error.HTTPError(address, 503, "edge", {}, None)
            return url(address, token)
        with patch.object(watch.receipts, "public_api_revision_state") as revision:
            self.assertEqual(set(watch.failures("t", get=get, gh=gh, now=NOW)),
                             {"api-health-edge"})
            revision.assert_not_called()

    def test_transient_api_transport_requires_three_observations(self):
        cases = (
            ({}, {}),
            ({"api-health-edge": "503"}, {"api-health-edge": "503"}),
            ({"api-health": "bad ready JSON"}, {"api-health": "bad ready JSON"}),
        )
        for third, expected in cases:
            with self.subTest(third=third):
                samples = [
                    {"api-health-edge": "503"},
                    {"api-health-edge": "timeout"},
                    third,
                ]
                pauses = []
                self.assertEqual(
                    watch.confirmed_failures(
                        "t", probe=lambda _: samples.pop(0), pause=pauses.append
                    ),
                    expected,
                )
                self.assertEqual(pauses, [90, 90])
                self.assertEqual(samples, [])

    def test_structural_api_failure_needs_only_two_observations(self):
        samples = [{"api-health": "bad JSON"}, {"api-health": "still bad JSON"}]
        pauses = []
        self.assertEqual(
            watch.confirmed_failures(
                "t", probe=lambda _: samples.pop(0), pause=pauses.append
            ),
            {"api-health": "still bad JSON"},
        )
        self.assertEqual(pauses, [90])

    def test_mixed_api_edge_and_structural_needs_third_probe(self):
        samples = [
            {"api-health-edge": "503"},
            {"api-health": "invalid readiness"},
            {"api-health-edge": "timeout"},
        ]
        pauses = []
        self.assertEqual(
            watch.confirmed_failures(
                "t", probe=lambda _: samples.pop(0), pause=pauses.append
            ),
            {"api-health-edge": "timeout"},
        )
        self.assertEqual(pauses, [90, 90])

    def test_transient_api_recovery_does_not_erase_confirmed_pages_outage(self):
        samples = [
            {"api-health-edge": "503", "pages-game": "JS missing"},
            {"api-health-edge": "503", "pages-game": "JS missing"},
            {},
        ]
        pauses = []
        self.assertEqual(
            watch.confirmed_failures(
                "t", probe=lambda _: samples.pop(0), pause=pauses.append
            ),
            {"pages-game": "JS missing"},
        )
        self.assertEqual(pauses, [90, 90])

    @patch.object(watch, "source_ci_status", return_value=("pending", None))
    def test_game_entry_is_checked_even_while_source_ci_is_pending(self, _):
        self.game_probe.return_value = "js_content"
        bad = watch.failures("t", get=url, gh=gh, now=NOW)
        self.assertEqual(set(bad), {"pages-game"})
        self.game_probe.assert_called_once_with(
            path="/", assets=b"/assets/", manifest_path=None
        )

    @patch.object(watch.receipts, "public_api_revision_state", return_value="match")
    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch, "source_ci_status", return_value=("ready", OLD))
    def test_manifest_and_api_healthy_cannot_hide_broken_game_assets(self, _, __, ___):
        for state in ("html_missing", "js_reference", "js_mime",
                      "css_reference", "css_content", "http_404"):
            with self.subTest(state=state):
                self.game_probe.return_value = state
                self.assertEqual(set(watch.failures("t", get=url, gh=gh, now=NOW)),
                                 {"pages-game"})
        for state in ("http_429", "http_500", "http_503", "http_522",
                      "unavailable", "http_error"):
            with self.subTest(state=state):
                self.game_probe.return_value = state
                self.assertEqual(set(watch.failures("t", get=url, gh=gh, now=NOW)),
                                 {"pages-edge"})
        self.game_probe.return_value = "ok"
        self.assertEqual(watch.failures("t", get=url, gh=gh, now=NOW), {})

    @patch.object(watch, "source_ci_status", return_value=("pending", None))
    def test_watchdog_cannot_probe_a_different_pages_environment(self, _):
        with patch.object(watch.pages, "HOST", "chronicles.shadowops.dpdns.org"):
            with self.assertRaisesRegex(RuntimeError, "pinned staging origin"):
                watch.failures("t", get=url, gh=gh, now=NOW)
        self.game_probe.assert_not_called()

    @patch.object(watch.receipts, "public_api_revision_state", return_value="match")
    @patch.object(watch, "source_ci_status", return_value=("ready", OLD))
    def test_fully_green_but_missing_api_receipt_is_reported_after_grace(self, _, __):
        bad = watch.failures("t", get=url, gh=gh, now=NOW)
        self.assertEqual(set(bad), {"backend-lag"})

    @patch.object(watch, "source_ci_status", return_value=("pending", None))
    def test_new_unfinished_source_does_not_cause_version_drift_alert(self, _):
        self.assertEqual(watch.failures("t", get=url, gh=gh, now=NOW), {})

    @patch.object(watch, "source_ci_status", return_value=("ready", OLD))
    def test_recent_green_source_uses_grace_window(self, _):
        recent = OLD + dt.timedelta(minutes=20)
        self.assertEqual(watch.failures("t", get=url, gh=gh, now=recent), {})

    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch, "source_ci_status", return_value=("ready", OLD))
    def test_live_api_sha_must_match_even_when_health_and_receipt_pass(self, _, __):
        with patch.object(watch.receipts, "public_api_revision_state", return_value="match") as live:
            self.assertEqual(watch.failures("t", get=url, gh=gh, now=NOW), {})
            live.assert_called_once_with(SHA)
        with patch.object(watch.receipts, "public_api_revision_state", return_value="different"):
            self.assertEqual(set(watch.failures("t", get=url, gh=gh, now=NOW)), {"api-revision"})
        with patch.object(watch.receipts, "public_api_revision_state", return_value="unknown"):
            self.assertEqual(set(watch.failures("t", get=url, gh=gh, now=NOW)), {"api-revision"})

    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch, "source_ci_status", return_value=("ready", OLD))
    def test_bad_api_health_does_not_duplicate_revision_alarm(self, _, __):
        def degraded(address, token=""):
            if address.endswith("/health"):
                raise ValueError("HTTP health is degraded")
            return url(address)
        with patch.object(watch.receipts, "public_api_revision_state") as live:
            self.assertEqual(set(watch.failures("t", get=degraded, gh=gh, now=NOW)),
                             {"api-health"})
            live.assert_not_called()

    @patch.object(watch, "source_ci_status", return_value=("ready", OLD))
    def test_live_revision_is_not_probed_before_green_source_grace(self, _):
        with patch.object(watch.receipts, "public_api_revision_state") as live:
            self.assertEqual(watch.failures("t", get=url, gh=gh,
                                            now=OLD + dt.timedelta(minutes=20)), {})
            live.assert_not_called()

    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch, "source_ci_status", return_value=("ready", OLD))
    def test_unexpected_revision_state_fails_inconclusive_not_ok(self, _, __):
        with patch.object(watch.receipts, "public_api_revision_state", return_value="invalid"):
            with self.assertRaisesRegex(RuntimeError, "Unexpected public API revision state"):
                watch.failures("t", get=url, gh=gh, now=NOW)

    def test_watch_pages_failure_buckets_are_allowlisted_and_redacted(self):
        structural = ("html_missing", "js_reference", "css_content",
                      "js_mime", "http_403", "http_404")
        transient = ("http_429", "http_500", "http_503", "http_522",
                     "http_599", "http_error", "unavailable")
        for result in structural:
            with self.subTest(result=result):
                self.assertEqual(watch.pages_failure_key(result), "pages-game")
        for result in transient:
            with self.subTest(result=result):
                self.assertEqual(watch.pages_failure_key(result), "pages-edge")
        self.assertIsNone(watch.pages_failure_key("ok"))

    def test_structural_game_failure_alerts_after_two_samples(self):
        samples = [{"pages-game": "broken"}, {"pages-game": "broken"}]
        paused = []
        def probe(_token):
            return samples.pop(0)
        bad = watch.confirmed_failures("t", probe=probe, pause=paused.append)
        self.assertEqual(bad, {"pages-game": "broken"})
        self.assertEqual(paused, [90])
        self.assertEqual(samples, [])

    def test_one_off_cdn_failure_is_suppressed_by_second_sample(self):
        samples = [{"pages-edge": "edge"}, {}]
        paused = []
        bad = watch.confirmed_failures(
            "t", probe=lambda _: samples.pop(0), pause=paused.append)
        self.assertEqual(bad, {})
        self.assertEqual(paused, [90])

    def test_cdn_failure_must_survive_three_samples_before_alert(self):
        for third, expected in [
            ({}, {}),
            ({"pages-edge": "still down"}, {"pages-edge": "still down"}),
            ({"pages-game": "HTML fallback"}, {"pages-game": "HTML fallback"}),
        ]:
            with self.subTest(third=third):
                samples = [{"pages-edge": "edge"}, {"pages-edge": "edge"}, third]
                paused = []
                bad = watch.confirmed_failures(
                    "t", probe=lambda _: samples.pop(0), pause=paused.append)
                self.assertEqual(bad, expected)
                self.assertEqual(paused, [90, 90])
                self.assertEqual(samples, [])

    def test_mixed_cdn_and_structural_failure_uses_third_sample(self):
        samples = [
            {"pages-edge": "network"}, {"pages-game": "bad MIME"},
            {"pages-edge": "still broken"},
        ]
        paused = []
        self.assertEqual(watch.confirmed_failures(
            "t", probe=lambda _: samples.pop(0), pause=paused.append),
            {"pages-edge": "still broken"})
        self.assertEqual(paused, [90, 90])

    def test_edge_recovery_does_not_hide_persistent_unrelated_health_failure(self):
        samples = [
            {"pages-edge": "transient", "api-health": "API down"},
            {"pages-edge": "transient", "api-health": "API down"},
            {},
        ]
        paused = []
        bad = watch.confirmed_failures(
            "t", probe=lambda _: samples.pop(0), pause=paused.append)
        self.assertEqual(bad, {"api-health": "API down"})
        self.assertEqual(paused, [90, 90])

    def test_no_initial_failure_never_sleeps_or_rechecks(self):
        calls = []
        def probe(_token):
            calls.append("probe")
            return {}
        self.assertEqual(watch.confirmed_failures(
            "t", probe=probe,
            pause=lambda _: self.fail("Should not pause on healthy first sample")), {})
        self.assertEqual(calls, ["probe"])

    @patch.object(watch, "source_ci_status", return_value=("pending", None))
    def test_manifest_5xx_and_network_failures_are_edge_not_broken_json(self, _):
        def sample(failure):
            def get(address, token=""):
                if "/release.json?" in address:
                    raise failure
                return url(address)
            return watch.failures("t", get=get, gh=gh, now=NOW)

        for code in (429, 500, 503, 522, 599):
            with self.subTest(status=code):
                err = urllib.error.HTTPError("https://example.invalid", code, "fault", {}, None)
                self.assertEqual(set(sample(err)), {"pages-manifest-edge"})
        for err in (TimeoutError("timed out"), urllib.error.URLError("offline"),
                    ConnectionError("reset")):
            with self.subTest(error=type(err).__name__):
                self.assertEqual(set(sample(err)), {"pages-manifest-edge"})

        for code in (400, 403, 404):
            with self.subTest(status=code):
                err = urllib.error.HTTPError("https://example.invalid", code, "fault", {}, None)
                self.assertEqual(set(sample(err)), {"pages-manifest"})
        self.assertEqual(set(sample(ValueError("invalid JSON"))), {"pages-manifest"})

    @patch.object(watch, "source_ci_status", return_value=("pending", None))
    def test_invalid_or_wrong_shape_manifest_is_structural(self, _):
        for manifest in ([], None, {}, {"build": "not-a-sha"}, {"build": 12}):
            with self.subTest(manifest=manifest):
                def get(address, token=""):
                    return manifest if "/release.json?" in address else url(address)
                self.assertEqual(set(watch.failures("t", get=get, gh=gh, now=NOW)),
                                 {"pages-manifest"})

    @patch.object(watch.receipts, "public_api_revision_state", return_value="match")
    @patch.object(watch.receipts, "evidence_ok", return_value=True)
    @patch.object(watch, "source_ci_status", return_value=("ready", OLD))
    def test_lost_manifest_does_not_invent_frontend_sha_lag(self, _, __, ___):
        for outcome, key in ((TimeoutError("edge"), "pages-manifest-edge"),
                             (ValueError("JSON corrupt"), "pages-manifest")):
            with self.subTest(key=key):
                def get(address, token=""):
                    if "/release.json?" in address:
                        raise outcome
                    return url(address)
                bad = watch.failures("t", get=get, gh=gh, now=NOW)
                self.assertEqual(set(bad), {key})
                self.assertNotIn("frontend-lag", bad)
        def older(address, token=""):
            return {"build": "b" * 40} if "/release.json?" in address else url(address)
        self.assertEqual(set(watch.failures("t", get=older, gh=gh, now=NOW)),
                         {"frontend-lag"})

    def test_manifest_invalid_json_needs_only_two_observations(self):
        samples = [
            {"pages-manifest": "invalid JSON"},
            {"pages-manifest": "still invalid JSON"},
        ]
        pauses = []
        bad = watch.confirmed_failures(
            "t", probe=lambda _: samples.pop(0), pause=pauses.append)
        self.assertEqual(bad, {"pages-manifest": "still invalid JSON"})
        self.assertEqual(pauses, [90])
        self.assertEqual(samples, [])

    def test_manifest_cdn_503_recovers_without_issue_on_third_sample(self):
        samples = [
            {"pages-manifest-edge": "503"},
            {"pages-manifest-edge": "503"},
            {},
        ]
        pauses = []
        self.assertEqual(watch.confirmed_failures(
            "t", probe=lambda _: samples.pop(0), pause=pauses.append), {})
        self.assertEqual(pauses, [90, 90])

    def test_manifest_cdn_failure_persists_or_turns_into_corrupt_json(self):
        for third, expected in (
            ({"pages-manifest-edge": "522"}, {"pages-manifest-edge": "522"}),
            ({"pages-manifest": "invalid JSON"}, {"pages-manifest": "invalid JSON"}),
        ):
            with self.subTest(third=third):
                samples = [
                    {"pages-manifest-edge": "503"},
                    {"pages-manifest": "wrong JSON"},
                    third,
                ]
                pauses = []
                bad = watch.confirmed_failures(
                    "t", probe=lambda _: samples.pop(0), pause=pauses.append)
                self.assertEqual(bad, expected)
                self.assertEqual(pauses, [90, 90])

    def test_manifest_edge_third_probe_keeps_independent_structural_game_alarm(self):
        samples = [
            {"pages-game": "missing entry", "pages-manifest-edge": "timeout"},
            {"pages-game": "still missing", "pages-manifest-edge": "503"},
            {},
        ]
        pauses = []
        bad = watch.confirmed_failures(
            "t", probe=lambda _: samples.pop(0), pause=pauses.append)
        self.assertEqual(bad, {"pages-game": "still missing"})
        self.assertEqual(pauses, [90, 90])

    def test_manifest_edge_recovery_preserves_persistent_api_health(self):
        samples = [
            {"pages-manifest-edge": "503", "api-health": "down"},
            {"pages-manifest-edge": "503", "api-health": "down"},
            {},
        ]
        pauses = []
        bad = watch.confirmed_failures(
            "t", probe=lambda _: samples.pop(0), pause=pauses.append)
        self.assertEqual(bad, {"api-health": "down"})
        self.assertEqual(pauses, [90, 90])

    def test_issue_is_idempotent_and_diagnosis_updates_on_changed_causes(self):
        open_issues = []
        writes = []

        def api(path, token, *, method="GET", payload=None):
            if path.endswith("/issues?state=open&per_page=100&page=1"):
                return open_issues
            writes.append((method, path, payload))
            if method == "POST":
                open_issues.append({
                    "number": 42, "title": watch.TITLE, "body": payload["body"]
                })
            elif method == "PATCH" and payload.get("state") == "closed":
                open_issues.clear()
            elif method == "PATCH":
                open_issues[0]["body"] = payload["body"]
            return {"number": 42}

        first = {"api-health": "API no disponible"}
        self.assertEqual(watch.manage_issue("t", first, gh=api),
                         "CHRONICLES_STAGING_WATCH_ISSUE_OPENED")
        self.assertEqual(len([x for x in writes if x[0] == "POST"]), 1)
        self.assertIn("api-health", open_issues[0]["body"])
        self.assertEqual(watch.manage_issue("t", first, gh=api),
                         "CHRONICLES_STAGING_WATCH_ALREADY_OPEN")
        self.assertEqual(len(writes), 1, "identical watchdog run is not a write")

        # Human notes outside the managed section belong to the operator.
        open_issues[0]["body"] += "\n\nOperator note: ticket ABC"
        replacement = {"pages-manifest-edge": "CDN 503"}
        self.assertEqual(watch.manage_issue("t", replacement, gh=api),
                         "CHRONICLES_STAGING_WATCH_UPDATED")
        body = open_issues[0]["body"]
        self.assertIn("pages-manifest-edge", body)
        self.assertNotIn("**api-health**", body)
        self.assertIn("Operator note: ticket ABC", body)
        self.assertEqual(len([x for x in writes if x[0] == "PATCH"]), 1)
        self.assertEqual(writes[-1][2].keys(), {"body"})
        self.assertEqual(watch.manage_issue("t", replacement, gh=api),
                         "CHRONICLES_STAGING_WATCH_ALREADY_OPEN")
        self.assertEqual(len(writes), 2)

        # Swapping multiple issue causes changes only the managed text.
        self.assertEqual(watch.manage_issue("t", {
            "pages-game": "JS inválido", "api-health": "API caída"
        }, gh=api), "CHRONICLES_STAGING_WATCH_UPDATED")
        self.assertIn("Operator note: ticket ABC", open_issues[0]["body"])
        self.assertIn("**pages-game**", open_issues[0]["body"])
        self.assertIn("**api-health**", open_issues[0]["body"])

        self.assertEqual(watch.manage_issue(
            "t", {}, gh=api, probe=lambda _: {},
            pause=lambda seconds: self.assertEqual(seconds, 90)),
            "CHRONICLES_STAGING_WATCH_RECOVERED")
        self.assertEqual(writes[-1][2],
                         {"state": "closed", "state_reason": "completed"})
        self.assertEqual(watch.manage_issue("t", {}, gh=api),
                         "CHRONICLES_STAGING_WATCH_OK")

    def test_one_healthy_sample_does_not_close_unstable_open_incident(self):
        body = watch.diagnostic_body({"pages-edge": "CDN caída"})
        issue = {"number": 42, "title": watch.TITLE, "body": body}
        calls, sleeps = [], []
        def api(path, token, *, method="GET", payload=None):
            calls.append((method, path, payload))
            if method != "GET":
                self.fail("Issue must not be mutated after failed recovery confirmation")
            return [issue]
        samples = iter(({}, {"pages-edge": "continúa fallando"}))
        result = watch.manage_issue(
            "t", {}, gh=api, probe=lambda _: next(samples),
            pause=sleeps.append)
        self.assertEqual(result, "CHRONICLES_STAGING_WATCH_RECOVERY_UNCONFIRMED")
        self.assertEqual(sleeps, [90])
        self.assertEqual(len(calls), 1)
        self.assertEqual(issue["body"], body)

    def test_two_healthy_samples_close_the_same_existing_issue(self):
        issue = {"number": 42, "title": watch.TITLE, "body": "operator notes"}
        calls, sleeps, probes = [], [], []
        def api(path, token, *, method="GET", payload=None):
            calls.append((method, path, payload))
            if method == "GET":
                return [issue]
            self.assertEqual(payload, {"state": "closed", "state_reason": "completed"})
            self.assertTrue(path.endswith("/issues/42"))
            return {"number": 42}
        def probe(token):
            probes.append(token)
            return {}
        self.assertEqual(watch.manage_issue("t", {}, gh=api,
                probe=probe, pause=sleeps.append),
                "CHRONICLES_STAGING_WATCH_RECOVERED")
        self.assertEqual(probes, ["t", "t"])
        self.assertEqual(sleeps, [90])
        self.assertEqual([action for action, _, _ in calls], ["GET", "PATCH"])

    def test_recovery_short_circuits_if_first_new_sample_is_unhealthy(self):
        calls, probes, pauses = [], [], []
        def api(path, token, *, method="GET", payload=None):
            calls.append(method)
            if method != "GET":
                self.fail("Failed recovery must never close the incident")
            return [{"number": 42, "title": watch.TITLE, "body": "on call"}]
        def probe(token):
            probes.append(token)
            return {"pages-game": "broken"}
        self.assertEqual(watch.manage_issue("t", {}, gh=api,
                probe=probe, pause=pauses.append),
                "CHRONICLES_STAGING_WATCH_RECOVERY_UNCONFIRMED")
        self.assertEqual(probes, ["t"])
        self.assertEqual(pauses, [])
        self.assertEqual(calls, ["GET"])

    def test_no_open_incident_needs_no_recovery_delay_or_extra_probe(self):
        calls = []
        def api(path, token, *, method="GET", payload=None):
            calls.append(method)
            return []
        self.assertEqual(watch.manage_issue(
            "t", {}, gh=api,
            probe=lambda _: self.fail("no probe without incident"),
            pause=lambda _: self.fail("no sleep without incident")),
            "CHRONICLES_STAGING_WATCH_OK")
        self.assertEqual(calls, ["GET"])

    def test_unverifiable_recovery_never_closes_existing_incident(self):
        calls = []
        def api(path, token, *, method="GET", payload=None):
            calls.append(method)
            if method != "GET":
                self.fail("Never close when recovery recheck cannot complete")
            return [{"number": 42, "title": watch.TITLE, "body": "manual"}]
        with self.assertRaisesRegex(RuntimeError, "cannot prove recovery"):
            watch.manage_issue("t", {}, gh=api,
                probe=lambda _: (_ for _ in ()).throw(RuntimeError("cannot prove recovery")),
                pause=lambda _: None)
        self.assertEqual(calls, ["GET"])

    def test_diagnosis_sorted_deterministically_does_not_spam_issue(self):
        first = watch.diagnostic_body({
            "pages-game": "JS incorrecto", "api-health": "API caída"
        })
        second = watch.diagnostic_body({
            "api-health": "API caída", "pages-game": "JS incorrecto"
        })
        self.assertEqual(first, second)
        self.assertLess(first.index("**api-health**"), first.index("**pages-game**"))
        self.assertEqual(first.count(watch.ISSUE_DIAGNOSTIC_START), 1)
        self.assertEqual(first.count(watch.ISSUE_DIAGNOSTIC_END), 1)
        self.assertNotIn("2026-", first)

    def test_old_automation_body_migrates_without_losing_operator_notes(self):
        legacy = (
            "Detectado en comprobaciones consecutivas. Estado público, sin datos de usuarios.\n\n"
            "- **api-health**: caída anterior\n\n" + watch.ISSUE_LEGACY_FOOTER +
            "\n\nNota manual: revisar túnel OCI"
        )
        upgraded = watch.updated_issue_body(
            legacy, watch.diagnostic_body({"pages-game": "JS erróneo"})
        )
        self.assertIn("**pages-game**", upgraded)
        self.assertNotIn("**api-health**", upgraded)
        self.assertIn("Nota manual: revisar túnel OCI", upgraded)
        self.assertEqual(upgraded.count(watch.ISSUE_DIAGNOSTIC_START), 1)
        self.assertEqual(watch.updated_issue_body(upgraded, watch.diagnostic_body(
            {"pages-game": "JS erróneo"})), upgraded)

    def test_unknown_issue_body_is_preserved_as_operator_text(self):
        old = "Investigación de SRE con información manual"
        managed = watch.updated_issue_body(old,
                          watch.diagnostic_body({"api-health": "API caída"}))
        self.assertTrue(managed.startswith(watch.ISSUE_DIAGNOSTIC_START))
        self.assertTrue(managed.endswith(old))
        self.assertEqual(watch.updated_issue_body(
            managed, watch.diagnostic_body({"api-health": "API caída"})), managed)

    def test_malformed_markers_fail_closed_instead_of_overwriting_notes(self):
        old = watch.ISSUE_DIAGNOSTIC_START + "\ntexto editado a mano"
        for broken in (old, watch.ISSUE_DIAGNOSTIC_END,
                       old + watch.ISSUE_DIAGNOSTIC_END +
                       watch.ISSUE_DIAGNOSTIC_START + watch.ISSUE_DIAGNOSTIC_END):
            with self.subTest(body=broken):
                with self.assertRaisesRegex(RuntimeError, "diagnostic boundaries"):
                    watch.updated_issue_body(
                        broken, watch.diagnostic_body({"pages-game": "down"}))

    def test_existing_issue_rejects_corrupt_metadata_and_ignores_pull_requests(self):
        def gh(data):
            return lambda path, token, **kwargs: data
        self.assertIsNone(watch.existing_issue("t", gh=gh([{
            "number": 1, "title": watch.TITLE, "pull_request": {"url": "pr"}
        }])))
        for data in ({"items": "not-list"},
                     [{"number": "bad", "title": watch.TITLE, "body": ""}],
                     [{"number": 1, "title": watch.TITLE, "body": 123}],
                     ["invalid issue row"]):
            with self.subTest(data=data):
                with self.assertRaisesRegex(RuntimeError, "Malformed"):
                    watch.existing_issue("t", gh=gh(data))

    def test_existing_issue_is_found_past_first_100_issues_and_prs(self):
        calls = []
        first_page = [
            {"number": i, "title": f"unrelated-{i}", "body": ""}
            for i in range(1, 96)
        ] + [
            {"number": i, "title": watch.TITLE, "body": "PR only",
             "pull_request": {"url": "https://example.invalid/pr"}}
            for i in range(96, 101)
        ]
        original = {"number": 194, "title": watch.TITLE,
                    "body": watch.diagnostic_body({"api-health": "down"})}
        def api(path, token, *, method="GET", payload=None):
            calls.append((method, path, payload))
            if path.endswith("&page=1"):
                return first_page
            if path.endswith("&page=2"):
                return [original]
            self.fail("Pagination must stop after short second page")
        self.assertEqual(watch.existing_issue("t", gh=api), original)
        self.assertEqual([x[1].split("&page=")[-1] for x in calls], ["1", "2"])
        self.assertEqual(watch.manage_issue("t", {"api-health": "down"}, gh=api),
                         "CHRONICLES_STAGING_WATCH_ALREADY_OPEN")
        self.assertEqual(len([x for x in calls if x[0] != "GET"]), 0)

    def test_unrelated_full_page_followed_by_empty_page_proves_absence(self):
        calls = []
        first_page = [
            {"number": i, "title": "not-a-watchdog-incident", "body": ""}
            for i in range(1, 101)
        ]
        def api(path, token, *, method="GET", payload=None):
            calls.append((method, path))
            if path.endswith("&page=1"):
                return first_page
            if path.endswith("&page=2"):
                return []
            if method == "POST":
                self.fail("POST must only occur after complete enumeration")
            self.fail("Unexpected page")
        self.assertIsNone(watch.existing_issue("t", gh=api))
        self.assertEqual(len(calls), 2)

    def test_duplicate_open_watchdog_incidents_fail_closed(self):
        one = {"number": 20, "title": watch.TITLE, "body": "A"}
        two = {"number": 300, "title": watch.TITLE, "body": "B"}
        def api(path, token, *, method="GET", payload=None):
            if path.endswith("&page=1"):
                return [one] + [
                    {"number": i, "title": "other", "body": ""}
                    for i in range(101, 200)
                ]
            if path.endswith("&page=2"):
                return [two]
            self.fail("Unexpected page")
        with self.assertRaisesRegex(RuntimeError, "Multiple open"):
            watch.existing_issue("t", gh=api)
        with self.assertRaisesRegex(RuntimeError, "Multiple open"):
            watch.manage_issue("t", {"pages-game": "down"}, gh=api)

    def test_unproven_pagination_completeness_fails_closed(self):
        calls = []
        full_page = [
            {"number": i, "title": "other", "body": ""}
            for i in range(100)
        ]
        def api(path, token, *, method="GET", payload=None):
            self.assertEqual(method, "GET", "No mutation when listing is incomplete")
            calls.append(path)
            return full_page
        with self.assertRaisesRegex(RuntimeError, "pagination limit"):
            watch.manage_issue("t", {"api-health": "down"}, gh=api)
        self.assertEqual(len(calls), watch.MAX_ISSUE_PAGES)
        self.assertTrue(calls[-1].endswith("&page=" + str(watch.MAX_ISSUE_PAGES)))

    def test_malformed_later_issue_page_or_transport_error_never_creates_issue(self):
        first_page = [
            {"number": i, "title": "other", "body": ""}
            for i in range(100)
        ]
        for last in ({"items": []}, first_page + [{"number": 999}],
                     RuntimeError("GitHub API unavailable")):
            with self.subTest(last=str(type(last))):
                calls = []
                def api(path, token, *, method="GET", payload=None):
                    self.assertEqual(method, "GET")
                    calls.append(path)
                    if path.endswith("&page=1"):
                        return first_page
                    if isinstance(last, Exception):
                        raise last
                    return last
                with self.assertRaises(RuntimeError):
                    watch.manage_issue("t", {"api-health": "down"}, gh=api)
                self.assertEqual(len(calls), 2)

    def test_mixed_signal_intersection_filters_transient_failure(self):
        first = {"api-health": "down", "frontend-lag": "lag"}
        second = {"api-health": "down", "pages-manifest": "temporarily broken"}
        persistent = {k: second[k] for k in first.keys() & second.keys()}
        self.assertEqual(persistent, {"api-health": "down"})


if __name__ == "__main__":
    unittest.main()
