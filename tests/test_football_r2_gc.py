"""Contracts for manual, exact-plan Football R2 release garbage collection."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import football_delivery as delivery
import football_r2_gc as gc

A, B, C = "a" * 16, "b" * 16, "c" * 16
SHA = "d" * 40


def files(rid):
    return {gc.ROOT + rid + "/" + name: 7 for name in gc.REQUIRED}


def example():
    objects = {"another-game/stable": 123,
               "football/atlases/v1/keep.webp": 42,
               **files(A), **files(B), **files(C)}
    live = {"release": A, "source_sha": SHA,
            "files": {name: {"bytes": 7} for name in gc.REQUIRED}}
    return objects, live


class FootballR2GC(unittest.TestCase):
    def test_public_release_identity_and_manifest_are_required(self):
        objects, live = example()
        release = {"application": "football-of-matthias", "environment": "staging",
                   "authentication": delivery.AUTHENTICATION, "source_sha": SHA,
                   "runtime": {"version": 1, "release": A, "sourceSha": SHA,
                               "index": f"{delivery.CDN}/{gc.ROOT}{A}/index.html"},
                   "files": live["files"]}
        self.assertEqual(gc.live_pointer(lambda: release), live)
        for fault in ("missing", "auth", "source", "index", "files"):
            wrong = copy.deepcopy(release)
            if fault == "missing":
                wrong = None
            if fault == "auth":
                wrong["authentication"] = {"required": False}
            if fault == "source":
                wrong["source_sha"] = "0" * 40
            if fault == "index":
                wrong["runtime"]["index"] = "https://foreign/unsafe"
            if fault == "files":
                wrong["files"].pop("index.wasm")
            with self.subTest(fault=fault), self.assertRaises(gc.GCError):
                gc.live_pointer(lambda: wrong)

    def test_only_owned_obsolete_releases_are_reclaimable(self):
        objects, live = example()
        plan = gc.make_plan(objects, live, B)
        self.assertEqual({k for k, _ in plan["delete"]}, set(files(C)))
        self.assertEqual(plan["reclaim_bytes"], 28)
        self.assertEqual(plan["rollback"], B)
        self.assertEqual(plan["active"], A)
        self.assertEqual(len(plan["digest"]), 64)
        self.assertEqual(len(plan["releases"]), 3)
        self.assertNotIn("another-game/stable", dict(plan["delete"]))
        self.assertNotIn("football/atlases/v1/keep.webp", dict(plan["delete"]))
        self.assertEqual(gc.make_plan(objects, live)["delete"], [])
        with self.assertRaises(gc.GCError):
            gc.make_plan(objects, live, A)
        with self.assertRaises(gc.GCError):
            gc.make_plan(objects, live, "f" * 16)

    def test_missing_or_inconsistent_live_and_rollback_fail_closed(self):
        objects, live = example()
        for victim in (gc.ROOT + A + "/index.wasm", gc.ROOT + B + "/index.pck"):
            broken = dict(objects)
            broken.pop(victim)
            with self.subTest(victim=victim), self.assertRaises(gc.GCError):
                gc.make_plan(broken, live, B)
        corrupt = dict(objects)
        corrupt[gc.ROOT + A + "/index.wasm"] = 999
        with self.assertRaises(gc.GCError):
            gc.make_plan(corrupt, live, B)

    def test_unknown_release_keys_refuse_the_entire_gc(self):
        objects, live = example()
        for name in ("../../secret", "not-a-hash/index.wasm",
                     A + "/../secret", A, A + "/sub//file"):
            broken = dict(objects)
            broken[gc.ROOT + name] = 123
            with self.subTest(name=name), self.assertRaises(gc.GCError):
                gc.make_plan(broken, live, B)

    def test_exact_snapshot_and_digest_must_match_before_any_delete(self):
        objects, live = example()
        plan = gc.make_plan(objects, live, B)
        removed = []
        with self.assertRaises(gc.GCError):
            gc.delete_plan(plan, objects, live, "f" * 64,
                           refresh_inventory=lambda: objects,
                           refresh_live=lambda: live,
                           delete_object=removed.append)
        changed = dict(objects)
        changed["foreign/new"] = 1
        with self.assertRaises(gc.GCError):
            gc.delete_plan(plan, objects, live, plan["digest"],
                           refresh_inventory=lambda: changed,
                           refresh_live=lambda: live,
                           delete_object=removed.append)
        changed_live = dict(live, release=B)
        with self.assertRaises(gc.GCError):
            gc.delete_plan(plan, objects, live, plan["digest"],
                           refresh_inventory=lambda: objects,
                           refresh_live=lambda: changed_live,
                           delete_object=removed.append)
        self.assertEqual(removed, [])

    def test_successful_gc_preserves_active_rollback_and_foreign(self):
        original, live = example()
        objects = dict(original)
        plan = gc.make_plan(original, live, B)
        reclaimed = gc.delete_plan(
            plan, original, live, plan["digest"], refresh_live=lambda: live,
            refresh_inventory=lambda: dict(objects),
            delete_object=lambda key: objects.pop(key))
        self.assertEqual(reclaimed, 28)
        self.assertEqual(objects, {k: v for k, v in original.items() if k not in files(C)})

    def test_stop_immediately_if_live_pointer_changes_mid_gc(self):
        objects, live = example()
        plan = gc.make_plan(objects, live, B)
        live_reads = [0]
        removed = []
        def refresh():
            live_reads[0] += 1
            return live if live_reads[0] < 3 else dict(live, source_sha="e" * 40)
        with self.assertRaises(gc.GCError):
            gc.delete_plan(plan, objects, live, plan["digest"],
                           refresh_live=refresh, refresh_inventory=lambda: objects,
                           delete_object=removed.append)
        self.assertEqual(len(removed), 1)

    def test_delete_targets_only_exact_object_keys_in_owned_prefix(self):
        calls = []
        def request(method, path):
            calls.append((method, path))
            return {"result": {"key": gc.ROOT + C + "/index.js"}}
        with patch.object(delivery, "r2_request", side_effect=request):
            gc.r2_delete("0" * 32, gc.ROOT + C + "/index.js")
            with self.assertRaises(gc.GCError):
                gc.r2_delete("0" * 32, "chronicles/releases/index.js")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "DELETE")
        self.assertIn("/r2/buckets/chess-studio-assets/objects/" + gc.ROOT, calls[0][1])
        with patch.object(delivery, "r2_request", return_value={"result": {"key": "foreign"}}):
            with self.assertRaises(gc.GCError):
                gc.r2_delete("0" * 32, gc.ROOT + C + "/index.js")

    def test_not_callable_automatically_from_pr_or_schedule(self):
        for event, ref in (("push", "refs/heads/main"),
                           ("schedule", "refs/heads/main"),
                           ("workflow_dispatch", "refs/pull/3/merge")):
            with patch.dict("os.environ", {"GITHUB_EVENT_NAME": event, "GITHUB_REF": ref}):
                with self.assertRaises(gc.GCError):
                    gc.run("plan")


if __name__ == "__main__":
    unittest.main()
