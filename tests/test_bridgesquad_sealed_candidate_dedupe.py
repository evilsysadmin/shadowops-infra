"""Contract tests for scheduled private release handoff deduplication."""
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bridgesquad_sealed_candidate_dedupe as seal

GAME = "a" * 40
INFRA = "b" * 40
RUN = 321
ITEM = {
    "id": 987,
    "name": f"bridgesquad-sealed-{GAME}-{INFRA}",
    "expired": False,
    "size_in_bytes": 48210,
    "digest": "sha256:" + "c" * 64,
    "workflow_run": {
        "id": RUN, "head_sha": INFRA, "head_branch": "main",
    },
}
RUN_DETAIL = {
    "id": RUN, "head_sha": INFRA, "head_branch": "main",
    "name": seal.WORKFLOW, "event": "push",
    "status": "completed", "conclusion": "success",
}
ARTS = f"/repos/{seal.REPO}/actions/artifacts?per_page=100&page=1"
RUN_URI = f"/repos/{seal.REPO}/actions/runs/{RUN}"


class FakeReader:
    def __init__(self, contents):
        self.contents = contents
        self.calls = []

    def get(self, uri):
        self.calls.append(uri)
        return self.contents[uri]


def fixture():
    return {ARTS: {"artifacts": [copy.deepcopy(ITEM)]},
            RUN_URI: copy.deepcopy(RUN_DETAIL)}


class SealedCandidateDedupeTests(unittest.TestCase):
    def test_successful_exact_main_release_skips_duplicate_upload(self):
        reader = FakeReader(fixture())
        self.assertTrue(seal.already_sealed(reader, GAME, INFRA))
        self.assertEqual(reader.calls, [ARTS, RUN_URI])
        self.assertEqual(reader.contents[ARTS]["artifacts"][0]["name"],
                         f"bridgesquad-sealed-{GAME}-{INFRA}")

    def test_new_game_or_infra_sha_never_skips(self):
        for game, infra in ((GAME, "d"*40), ("e"*40, INFRA)):
            with self.subTest(game=game, infra=infra):
                reader = FakeReader(fixture())
                self.assertFalse(seal.already_sealed(reader, game, infra))
                self.assertEqual(reader.calls, [ARTS])

    def test_expired_or_incomplete_run_cannot_suppress_handoff(self):
        for mutation in (
            lambda x: x[ARTS]["artifacts"][0].update({"expired": True}),
            lambda x: x[RUN_URI].update({"status": "in_progress", "conclusion": None}),
            lambda x: x[RUN_URI].update({"conclusion": "failure"}),
            lambda x: x[RUN_URI].update({"conclusion": "cancelled"}),
        ):
            reader = FakeReader(fixture())
            mutation(reader.contents)
            self.assertFalse(seal.already_sealed(reader, GAME, INFRA))

    def test_invalid_existing_metadata_is_not_trusted(self):
        for mutation in (
            lambda x: x[ARTS]["artifacts"][0].update({"digest": None}),
            lambda x: x[ARTS]["artifacts"][0].update({"size_in_bytes": 0}),
            lambda x: x[ARTS]["artifacts"][0].update({"id": True}),
            lambda x: x[ARTS]["artifacts"][0]["workflow_run"].update({"head_sha": GAME}),
            lambda x: x[ARTS]["artifacts"][0]["workflow_run"].update({"head_branch": "dev"}),
            lambda x: x[RUN_URI].update({"name": "unrelated-release"}),
            lambda x: x[RUN_URI].update({"event": "pull_request"}),
            lambda x: x[RUN_URI].update({"head_sha": GAME}),
            lambda x: x[RUN_URI].update({"head_branch": "canary"}),
        ):
            reader = FakeReader(fixture())
            mutation(reader.contents)
            with self.subTest(mutation=mutation), self.assertRaises(seal.Refused):
                seal.already_sealed(reader, GAME, INFRA)

    def test_invalid_sha_and_malformed_inventory_fail_closed(self):
        for game, infra in ((GAME[:-1], INFRA), ("A"*40, INFRA), (GAME, "b"*39),
                            (GAME, "B"*40), ("../main", INFRA)):
            with self.subTest(game=game, infra=infra), self.assertRaises(seal.Refused):
                seal.already_sealed(FakeReader(fixture()), game, infra)
        for invalid in (None, {}, {"artifacts": None}, {"artifacts": "oops"},
                        {"artifacts": [None]}, {"artifacts": [{}]*101}):
            reader = FakeReader({ARTS: invalid})
            if invalid == {"artifacts": [None]}:
                # Non-target records with invalid types must not be trusted
                self.assertFalse(seal.already_sealed(reader, GAME, INFRA))
            else:
                with self.assertRaises((seal.Refused, AttributeError)):
                    seal.already_sealed(reader, GAME, INFRA)

    def test_paginated_inventory_finds_current_successful_handoff(self):
        first = {"artifacts": [{"name": "old", "id": k} for k in range(100)]}
        second = {"artifacts": [copy.deepcopy(ITEM)]}
        page2 = f"/repos/{seal.REPO}/actions/artifacts?per_page=100&page=2"
        r = FakeReader({ARTS: first, page2: second, RUN_URI: copy.deepcopy(RUN_DETAIL)})
        self.assertTrue(seal.already_sealed(r, GAME, INFRA))
        self.assertEqual(r.calls, [ARTS, page2, RUN_URI])

    def test_operator_entry_only_trusted_infra_main(self):
        good = {
            "GITHUB_REPOSITORY": seal.REPO,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_SHA": INFRA,
            "GH_TOKEN": "synthetic-readonly-token",
        }
        with mock.patch.dict(os.environ, good, clear=True), \
             mock.patch.object(seal, "GitHubReader", return_value=FakeReader(fixture())):
            with mock.patch("builtins.print") as output:
                self.assertEqual(seal.main(["check", GAME, INFRA]), 0)
                output.assert_called_once_with("sealed_exists=true")
        for k, v in (
            ("GITHUB_REPOSITORY", "attacker/fork"),
            ("GITHUB_REF", "refs/heads/branch"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_SHA", GAME),
        ):
            with self.subTest(k=k), mock.patch.dict(os.environ, {**good,k:v}, clear=True), \
                 mock.patch.object(seal, "GitHubReader", side_effect=AssertionError("must not query")):
                self.assertEqual(seal.main(["check", GAME, INFRA]), 1)
        self.assertEqual(seal.main([]), 2)


if __name__ == "__main__":
    unittest.main()
