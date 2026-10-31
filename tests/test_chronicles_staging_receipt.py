"""Offline cross-service staging evidence parity and fail-closed identity checks."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_staging_receipt as receipts

SHA = "a" * 40
OTHER = "b" * 40


def proof(kind, sha=SHA):
    return {"name": receipts.TRUSTED[kind][0] + sha,
            "expired": False,
            "workflow_run": {"id": 123, "head_branch": "main"}}


def run(kind, **changes):
    doc = {"id": 123, "status": "completed", "conclusion": "success",
           "path": receipts.TRUSTED[kind][1], "head_branch": "main",
           "event": "workflow_dispatch",
           "repository": {"full_name": receipts.INFRA}}
    doc.update(changes)
    return doc


class ReceiptParityTests(unittest.TestCase):
    def test_both_services_admit_only_their_own_verified_provenance(self):
        for kind, foreign in (("api", "pages"), ("pages", "api")):
            with self.subTest(kind=kind):
                read = []
                def fetch(run_id):
                    read.append(run_id)
                    return run(kind)
                self.assertTrue(receipts.trusted_staging_receipt(
                    SHA, {"artifacts": [proof(kind)]}, fetch, kind=kind))
                self.assertEqual(read, [123])
                self.assertFalse(receipts.trusted_staging_receipt(
                    SHA, {"artifacts": [proof(foreign)]},
                    lambda _: self.fail("Must not fetch foreign artifact run"),
                    kind=kind))
                self.assertFalse(receipts.trusted_staging_receipt(
                    SHA, {"artifacts": [proof(kind)]},
                    lambda _: run(foreign), kind=kind))

    def test_all_provenance_mismatches_are_rejected_for_both(self):
        for kind in receipts.TRUSTED:
            for change in (
                {"id": 456}, {"id": True}, {"status": "in_progress"},
                {"conclusion": "failure"}, {"path": "other.yml"},
                {"head_branch": "feature"}, {"event": "pull_request"},
                {"repository": {"full_name": "foreign/repo"}},
                {"repository": "not-an-object"},
            ):
                with self.subTest(kind=kind, run=change):
                    self.assertFalse(receipts.trusted_staging_receipt(
                        SHA, {"artifacts": [proof(kind)]},
                        lambda _: run(kind, **change), kind=kind))
            for change in (
                {"expired": True}, {"name": "wrong"},
                {"workflow_run": {"id": 0, "head_branch": "main"}},
                {"workflow_run": {"id": True, "head_branch": "main"}},
                {"workflow_run": {"id": 123, "head_branch": "other"}},
            ):
                with self.subTest(kind=kind, artifact=change):
                    self.assertFalse(receipts.trusted_staging_receipt(
                        SHA, {"artifacts": [{**proof(kind), **change}]},
                        lambda _: self.fail("Untrusted artifact must not fetch"),
                        kind=kind))

    def test_malformed_evidence_fails_closed_in_both_services(self):
        for kind in receipts.TRUSTED:
            for sha, listing in (
                ("main", {"artifacts": [proof(kind)]}),
                (SHA, {}), (SHA, {"artifacts": "invalid"}),
                (SHA, {"artifacts": [proof(kind)]}),
            ):
                with self.subTest(kind=kind, sha=sha, listing=listing):
                    with self.assertRaises(receipts.ReceiptError):
                        receipts.trusted_staging_receipt(sha, listing,
                            lambda _: "not-a-run", kind=kind)
        with self.assertRaises(receipts.ReceiptError):
            receipts.trusted_staging_receipt(
                SHA, {"artifacts": [proof("api")]}, lambda _: run("api"), kind="foreign")

    def test_api_pages_public_entrypoints_reuse_shared_verdict(self):
        import chronicles_api_before_pages as api
        import chronicles_pages_verified_receipt as pages
        for name, fn in (("api", api.evidence_ok), ("pages", pages.receipt_ok)):
            with self.subTest(name=name):
                self.assertTrue(fn(
                    SHA, {"artifacts": [proof(name)]}, lambda _: run(name)))
                self.assertFalse(fn(
                    SHA, {"artifacts": [proof(name)]}, lambda _: run(name, conclusion="failure")))
                with self.assertRaises(api.GateError):
                    fn(SHA, {}, lambda _: self.fail("No read without listing"))


if __name__ == "__main__":
    unittest.main()
