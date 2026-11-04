"""Offline safety contracts for capacity-driven Football staging GC."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import football_delivery as delivery
import football_r2_gc as gc
import football_r2_auto_gc as auto

A, B, C = "a" * 16, "b" * 16, "c" * 16
SHA = "d" * 40
INCOMING = "e" * 16
CANONICAL_ENV = {"FOOTBALL_AUTO_GC": "1", "GITHUB_EVENT_NAME": "schedule",
                 "GITHUB_REF": "refs/heads/main",
                 "GITHUB_REPOSITORY": "evilsysadmin/shadowops-infra"}


def objects_and_live():
    def release(rid):
        return {gc.ROOT + rid + "/" + item: 7 for item in gc.REQUIRED}
    objects = {"other-product/protected": 20, **release(A), **release(B), **release(C)}
    live = {"release": A, "source_sha": SHA,
            "files": {name: {"bytes": 7} for name in gc.REQUIRED}}
    return objects, live


def deployment(sha, url, when="2026-11-03T12:00:00Z"):
    return {"environment": "production", "latest_stage": {"status": "success"},
            "deployment_trigger": {"metadata": {"branch": "main", "commit_hash": sha}},
            "created_on": when, "url": url}


class AutomaticFootballGC(unittest.TestCase):
    def test_only_owned_main_publisher_may_auto_delete(self):
        for bad in (
            {"FOOTBALL_AUTO_GC": "0"},
            {"GITHUB_REF": "refs/pull/447/merge"},
            {"GITHUB_REPOSITORY": "evil/fork"},
            {"GITHUB_EVENT_NAME": "pull_request"},
        ):
            with patch.dict(os.environ, {**CANONICAL_ENV, **bad}):
                with self.assertRaises(auto.AutoGCError):
                    auto.permitted()
        with patch.dict(os.environ, CANONICAL_ENV):
            auto.permitted()

    def test_bounded_history_chooses_latest_verified_previous_deployment(self):
        objects, live = objects_and_live()
        bad_url = "https://bad.football-staging-aha.pages.dev"
        good_url = "https://536e3bf2.football-staging-aha.pages.dev"
        rows = [deployment("f" * 40, bad_url, "2026-11-04T08:00:00Z"),
                deployment(SHA, "https://active.football-staging-aha.pages.dev", "2026-11-04T07:00:00Z"),
                deployment("1" * 40, good_url, "2026-11-03T06:00:00Z")]
        def candidate(url):
            if url == bad_url:
                raise auto.AutoGCError("not actually accessible")
            return {"release": B, "source_sha": "1" * 40,
                    "files": {name: {"bytes": 7} for name in gc.REQUIRED}}
        self.assertEqual(auto.pick_rollback(objects, live, history=lambda: [
            (z["created_on"], z["deployment_trigger"]["metadata"]["commit_hash"], z["url"])
            for z in rows], fetch_release=candidate,
            artifact_release=lambda sha: (_ for _ in ()).throw(auto.AutoGCError('not verified'))) ["release"], B)
        with self.assertRaises(auto.AutoGCError):
            auto.pick_rollback(objects, live, history=lambda: [], fetch_release=candidate)

    def test_history_uses_only_successful_exact_main_pages_records(self):
        url = "https://536e3bf2.football-staging-aha.pages.dev"
        good = deployment("f" * 40, url)
        other = copy.deepcopy(good)
        other["environment"] = "preview"
        failed = copy.deepcopy(good)
        failed["latest_stage"]["status"] = "failure"
        wrong_branch = copy.deepcopy(good)
        wrong_branch["deployment_trigger"]["metadata"]["branch"] = "dev"
        with patch.object(auto.pages, "project_path", return_value="/owned"):
            rows = auto.successful_history(lambda method, path: (200, [other, good, failed, wrong_branch]))
        self.assertEqual(rows, [(good["created_on"], "f" * 40, url)])
        with patch.object(auto.pages, "project_path", return_value="/owned"):
            with self.assertRaises(auto.AutoGCError):
                auto.successful_history(lambda method, path: (200, {"wrong": 1}))

    def test_immutable_pages_url_is_owned_and_redirects_are_forbidden(self):
        for url in ("http://536e3bf2.football-staging-aha.pages.dev",
                    "https://example.com",
                    "https://536e3bf2.football-staging-aha.pages.dev/foreign",
                    "https://536e3bf2.football-staging-aha.pages.dev:8443"):
            with self.assertRaises((auto.AutoGCError, ValueError)):
                auto.read_immutable_manifest(url)
        release = {"application": "football-of-matthias", "environment": "staging",
                   "authentication": delivery.AUTHENTICATION, "source_sha": SHA,
                   "runtime": {"version": 1, "release": A, "sourceSha": SHA,
                               "index": f"{delivery.CDN}/{gc.ROOT}{A}/index.html"},
                   "files": {name: {"bytes": 7} for name in gc.REQUIRED}}
        class Response(io.BytesIO):
            status = 200
            def geturl(self):
                return "https://536e3bf2.football-staging-aha.pages.dev/release.json"
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()
        with (
            patch.object(auto.pages, "dns_target", return_value="football-staging-aha.pages.dev"),
            patch.object(auto.urllib.request, "urlopen", return_value=Response(json.dumps(release).encode())),
        ):
            self.assertEqual(auto.read_immutable_manifest(
                "https://536e3bf2.football-staging-aha.pages.dev")["release"], A)

    def test_auto_gc_is_not_invoked_without_capacity_pressure(self):
        objects, live = objects_and_live()
        deleted = []
        with (
            patch.dict(os.environ, CANONICAL_ENV),
            patch.object(delivery, "github") as github,
        ):
            changed = auto.reclaim_if_needed("0" * 32, {gc.ROOT + INCOMING + "/index.js": 7},
                                            source_sha=SHA, inventory=lambda a: objects,
                                            rollback_picker=lambda o, l: {"release": B, "files": {}},
                                            delete_object=deleted.append)
            self.assertFalse(changed)
            self.assertEqual(deleted, [])
            github.assert_not_called()

    def test_auto_gc_reclaims_only_if_new_candidate_will_fit(self):
        original, live = objects_and_live()
        objects = dict(original)
        # Smaller test-specific cap ensures the incoming runtime requires GC.
        additions = {gc.ROOT + INCOMING + "/index.wasm": 10}
        with (
            patch.dict(os.environ, CANONICAL_ENV),
            patch.object(delivery, "FOOTBALL_BUDGET", 86),
            patch.object(delivery, "github", return_value={"sha": SHA}),
            patch.object(auto, "verify_rollback_payload") as verify,
        ):
            self.assertTrue(auto.reclaim_if_needed(
                "0" * 32, additions, source_sha=SHA,
                inventory=lambda a: dict(objects), live_reader=lambda: live,
                rollback_picker=lambda o, l: {"release": B, "files": {
                    name: {"bytes": 7, "sha256": "0" * 64}
                    for name in gc.REQUIRED}},
                delete_object=lambda key: objects.pop(key)))
            self.assertEqual(verify.call_count, 2)
        self.assertEqual(objects["other-product/protected"], 20)
        self.assertTrue(all(gc.ROOT + rid + "/index.js" in objects for rid in (A, B)))
        self.assertFalse(any(key.startswith(gc.ROOT + C + "/") for key in objects))

    def test_no_delete_when_pressure_cannot_be_resolved_or_main_changes(self):
        objects, live = objects_and_live()
        deleted = []
        with (
            patch.dict(os.environ, CANONICAL_ENV),
            patch.object(delivery, "FOOTBALL_BUDGET", 40),
            patch.object(delivery, "github", return_value={"sha": SHA}),
        ):
            with self.assertRaises(auto.AutoGCError):
                auto.reclaim_if_needed("0" * 32, {gc.ROOT + INCOMING + "/index.wasm": 100},
                                       source_sha=SHA, inventory=lambda a: objects,
                                       live_reader=lambda: live, rollback_picker=lambda o, l: {"release": B, "files": {}},
                                       delete_object=deleted.append)
        with (
            patch.dict(os.environ, CANONICAL_ENV),
            patch.object(delivery, "FOOTBALL_BUDGET", 50),
            patch.object(delivery, "github", return_value={"sha": "f" * 40}),
        ):
            with self.assertRaises(auto.AutoGCError):
                auto.reclaim_if_needed("0" * 32, {gc.ROOT + INCOMING + "/index.wasm": 7},
                                       source_sha=SHA, inventory=lambda a: objects,
                                       live_reader=lambda: live, rollback_picker=lambda o, l: {"release": B, "files": {}},
                                       delete_object=deleted.append)
        self.assertEqual(deleted, [])

    def test_read_only_probe_can_never_delete_objects(self):
        objects, live = objects_and_live()
        with (
            patch.dict(os.environ, CANONICAL_ENV),
            patch.object(auto.pages, "required", return_value="0" * 32),
            patch.object(delivery, "inventory", return_value=objects),
            patch.object(gc, "live_pointer", return_value=live),
            patch.object(auto, "pick_rollback", return_value={
                "release": B, "source_sha": SHA,
                "files": {name: {"bytes": 7, "sha256": "0" * 64}
                          for name in gc.REQUIRED},
            }),
            patch.object(gc, "r2_delete") as no_delete,
        ):
            auto.read_only_probe()
            no_delete.assert_not_called()


    def test_ci_attested_historical_artifact_and_404_fallback(self):
        import tempfile
        import zipfile
        from test_football_delivery import fixture, SHA as HIST_SHA
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            verified = fixture(root)
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
                for item in root.rglob("*"):
                    if item.is_file():
                        archive.write(item, item.relative_to(root).as_posix())
            blob = output.getvalue()
        digest = "sha256:" + auto.hashlib.sha256(blob).hexdigest()
        def reader(path):
            if "/workflows/" in path:
                return {"workflow_runs": [{"id": 7, "head_sha": HIST_SHA,
                                           "head_branch": "main", "event": "push",
                                           "status": "completed", "conclusion": "success"}]}
            if "/jobs?" in path:
                return {"jobs": [{"name": name, "conclusion": "success",
                                  "completed_at": "today"} for name in (
                        "Football · required visual gate",
                        "Real Chromium · Godot Web boot",
                        "Manager · deterministic career and save isolation",
                        "validate")]}
            if "/artifacts?" in path:
                return {"artifacts": [{"id": 77, "name": "football-staging-" + HIST_SHA,
                                      "expired": False, "digest": digest}]}
            raise AssertionError(path)
        prior = auto.attested_source_release(HIST_SHA, github=reader,
                                              download=lambda ident: blob)
        self.assertEqual(prior["release"], verified["runtime"]["release"])
        with self.assertRaises(auto.AutoGCError):
            auto.attested_source_release(HIST_SHA, github=reader,
                                         download=lambda ident: blob + b"tampered")
        objects, live = objects_and_live()
        objects.update({gc.ROOT + prior["release"] + "/" + name: entry["bytes"]
                        for name, entry in prior["files"].items()})
        def not_available(url):
            raise auto.AutoGCError("Historical Pages release HTTP 404")
        rows = lambda: [("2026-11-03T10:00:00Z", HIST_SHA,
                         "https://536e3bf2.football-staging-aha.pages.dev")]
        self.assertEqual(auto.pick_rollback(objects, live, history=rows,
                                             fetch_release=not_available,
                                             artifact_release=lambda sha: prior)["release"],
                         prior["release"])
        with self.assertRaises(auto.AutoGCError):
            auto.pick_rollback(objects, live, history=rows,
                               fetch_release=not_available,
                               artifact_release=lambda sha: dict(prior, source_sha="0"*40))


if __name__ == "__main__":
    unittest.main()
