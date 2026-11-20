import importlib.util
import pathlib
import sys
import unittest

MODULE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "game_identity_exposure.py"
spec = importlib.util.spec_from_file_location("game_identity_exposure", MODULE)
e = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = e
spec.loader.exec_module(e)


class Coverage(unittest.TestCase):
    def test_all_game_repositories_have_unique_coverage(self):
        expected = {
            "chess-studio", "chronicles-of-matthias", "star-adventures",
            "tactics-of-matthias", "football-of-matthias", "pawn-action",
            "snooker-of-matthias", "matthias-bridge-squad",
        }
        self.assertEqual({g.slug for g in e.GAMES} | set(e.UNPUBLISHED), expected)
        self.assertFalse({g.slug for g in e.GAMES} & set(e.UNPUBLISHED))
        self.assertEqual(len({(g.slug, g.environment) for g in e.GAMES}), len(e.GAMES))
        self.assertEqual(len({g.hostname for g in e.GAMES}), len(e.GAMES))
        for game, surface, host in e.endpoints():
            self.assertTrue(host.endswith(".shadowops.dpdns.org")
                            if surface == "canonical" else host.endswith(".pages.dev"))
            self.assertNotIn("/", host)
            self.assertNotIn(":", host)
            self.assertIn(game.environment, ("staging", "production"))

    def test_anonymous_200_including_pages_dev_is_never_accepted(self):
        for surface in ("canonical", "pages-dev-main"):
            self.assertEqual(e.classify(200, surface), "anonymous_content_review")
            self.assertEqual(e.classify(206, surface), "anonymous_content_review")
            o = e.Observation("game", "staging", surface, "host", "/", "GET",
                              200, e.classify(200, surface))
            self.assertEqual(e.outcome([o]), ("REVIEW_ANONYMOUS_200", 1))

    def test_denials_are_not_live_identity_acceptance(self):
        self.assertEqual(e.classify(401, "canonical"), "guest_denied")
        self.assertEqual(e.classify(404, "pages-dev-main"), "alias_denied")
        self.assertEqual(e.classify(503, "canonical"), "fail_closed_unavailable")
        o = e.Observation("game", "staging", "canonical", "host", "/", "GET",
                          503, "fail_closed_unavailable")
        self.assertEqual(e.outcome([o]), ("NOT_FULLY_VERIFIED", 2))
        self.assertEqual(e.classify(302, "canonical"), "redirect_unverified")
        self.assertEqual(e.classify(0, "canonical"), "network_unverified")

    def test_audit_checks_get_and_head_without_user_credentials(self):
        calls = []
        def fake(url, method):
            calls.append((url, method))
            return 401 if ".shadowops.dpdns.org" in url else 404
        observations = e.audit(fake)
        self.assertEqual(len(observations),
                         len(list(e.endpoints())) * len(e.ROUTES) * len(e.METHODS))
        self.assertEqual({method for _, method in calls}, {"GET", "HEAD"})
        self.assertEqual(e.outcome(observations), ("GUEST_DENIAL_OBSERVED", 0))
        self.assertTrue(all(url.startswith("https://") and "?" not in url
                            for url, _ in calls))

    def test_unreachable_cannot_be_claimed_protected(self):
        observations = e.audit(lambda _url, _method: 0)
        self.assertEqual(e.outcome(observations), ("NOT_FULLY_VERIFIED", 2))


if __name__ == "__main__":
    unittest.main()
