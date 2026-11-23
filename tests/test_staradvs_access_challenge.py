"""Cloudflare Access-specific guest challenges are candidates, not activation proof."""
from __future__ import annotations

import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import staradvs_access_challenge as challenge
import staradvs_access_quarantine as quarantine
import staradvs_pages as pages

PAGES = "old-pinned." + pages.TARGET
CURRENT = pages.TARGET
CUSTOM = pages.HOST


def login(host, team="private-team.cloudflareaccess.com"):
    return (302, f"https://{team}/cdn-cgi/access/login/{host}?redirect_url=%2F")


def sample(hosts, response=lambda host, path: None):
    return challenge.assess(hosts, lambda url: response(
        url.split("/")[2], "/" + url.split("/", 3)[3]
    ))


class Tests(unittest.TestCase):
    def test_exact_provider_redirect_is_candidate_not_generic_302(self):
        self.assertEqual(
            challenge.access_team(PAGES, *login(PAGES)),
            "private-team.cloudflareaccess.com",
        )
        invalid = [
            (302, "http://private-team.cloudflareaccess.com/cdn-cgi/access/login/" + PAGES),
            (302, "https://private-team.cloudflareaccess.com.evil.test/cdn-cgi/access/login/" + PAGES),
            (302, "https://private-team.cloudflareaccess.com:443/cdn-cgi/access/login/" + PAGES),
            (302, "https://user@private-team.cloudflareaccess.com/cdn-cgi/access/login/" + PAGES),
            (302, "https://private-team.cloudflareaccess.com/cdn-cgi/access/login/" + CURRENT),
            (302, "https://private-team.cloudflareaccess.com/login/" + PAGES),
            (302, "https://private-team.cloudflareaccess.com/cdn-cgi/access/login/" + PAGES + "#fragment"),
            (302, "https://private-team.cloudflareaccess.com/cdn-cgi/access/login/" + PAGES + "\r\n"),
            (303, login(PAGES)[1]),
            (403, login(PAGES)[1]),
            (302, "https://private-team.cloudflareaccess.com/cdn-cgi/access/login/" + PAGES + ".evil"),
        ]
        for response in invalid:
            with self.subTest(response=response):
                self.assertIsNone(challenge.access_team(PAGES, *response))

    def test_all_302_team_challenges_are_counted_without_following(self):
        result = sample([PAGES, CURRENT], lambda host, path: login(host))
        self.assertEqual(result, {
            "hosts": 2, "denied": 0, "challenged": 2,
            "exposed": 0, "unverified": 0,
        })
        denied = sample([PAGES], lambda host, path: (404, None))
        self.assertEqual(denied["denied"], 1)
        exposed = sample([PAGES], lambda host, path:
                         (200, None) if path == "/release.json" else login(host))
        self.assertEqual(exposed["exposed"], 1)

    def test_stray_location_and_mismatched_challenge_fail(self):
        def mismatched(host, path):
            if path == "/":
                return login(host)
            return login(host, team="different.cloudflareaccess.com")
        result = sample([PAGES], mismatched)
        self.assertEqual(result["unverified"], 1)
        result = sample([PAGES], lambda host, path:
                        (302, "https://login.example.org/login"))
        self.assertEqual(result["unverified"], 1)
        # No auto-login; a generic 403 is unverified even with Access metadata.
        self.assertEqual(sample([PAGES], lambda h, p: (403, None))["unverified"], 1)
        # Conflicting Access team domains across individual host challenges
        # block the entire candidate.
        result = sample([PAGES, CURRENT], lambda host, path:
                        login(host, team="a.cloudflareaccess.com"
                              if host == PAGES else "b.cloudflareaccess.com"))
        self.assertEqual(result["challenged"], 0)
        self.assertEqual(result["unverified"], 2)

    def test_disallow_foreign_and_duplicated_host_in_audit(self):
        for hosts in ([], [PAGES, PAGES], ["evil.example.com"],
                      ["bad." + pages.TARGET + ".attacker.com"]):
            with self.subTest(hosts=hosts), self.assertRaises(challenge.ChallengeError):
                sample(hosts, lambda host, path: login(host))

    def test_independent_provider_inventory_must_be_complete_and_stable(self):
        class Client:
            account = "a" * 32
            def request(self, method, path):
                self_or_other = None
                assert method == "GET"
                return 200, {"name": pages.PROJECT, "subdomain": pages.TARGET,
                             "production_branch": "main", "source": None}
        client = Client()
        project = {"name": pages.PROJECT, "subdomain": pages.TARGET,
                   "production_branch": "main", "source": None}

        def historical(client, project, max_hosts, page):
            if page == 1:
                return [PAGES], 2, 3
            return ["another." + pages.TARGET], 1, 3

        with patch.object(challenge.readiness, "historical_alias_hosts",
                          side_effect=historical):
            hosts = challenge.enumerate_historical(client, project, 3, 2)
            self.assertEqual(hosts, ["another." + pages.TARGET, PAGES])
            with self.assertRaises(challenge.ChallengeError):
                challenge.enumerate_historical(client, project, 4, 2)
            with self.assertRaises(challenge.ChallengeError):
                challenge.enumerate_historical(client, project, 3, 1)

        report = {
            "cloudflare_access": "restricted-policy-candidate",
            "historical_enumeration_status": "reported-total-observed",
            "historical_deployments_reported_total": 3,
            "historical_aliases_scanned": 2,
        }
        with patch.object(challenge.readiness, "historical_alias_hosts",
                          side_effect=historical):
            with patch.object(challenge.readiness, "alias_hosts",
                              return_value=[CURRENT]):
                evidence = challenge.collect(
                    client, report, probe=lambda url: login(url.split("/")[2])
                )
        self.assertEqual(evidence["historical"]["challenged"], 2)
        self.assertEqual(evidence["current_pages"]["challenged"], 1)
        self.assertEqual(evidence["canonical"]["challenged"], 1)
        self.assertFalse(evidence["can_activate"])
        with self.assertRaises(challenge.ChallengeError):
            challenge.collect(client, dict(report, cloudflare_access="unverified"))

    def test_quarantine_judge_never_activates_for_generic_redirect(self):
        report = {
            "historical_aliases_scanned": 114,
            "historical_aliases_exposed": 0,
            "historical_aliases_denied": 0,
            "historical_aliases_unverified": 114,
            "historical_deployments_scanned": 114,
            "historical_deployments_reported_total": 114,
            "historical_enumeration_status": "reported-total-observed",
            "cloudflare_access": "restricted-policy-candidate",
            "pages_historical_guest": "unverified-or-unavailable",
            "pages_alias_guest": "unverified-or-unavailable",
            "canonical_guest": "unverified-or-unavailable",
        }
        evidence = {
            "historical": {"hosts": 114, "challenged": 114, "denied": 0, "exposed": 0, "unverified": 0},
            "current_pages": {"hosts": 2, "challenged": 2, "denied": 0, "exposed": 0, "unverified": 0},
            "canonical": {"hosts": 1, "challenged": 1, "denied": 0, "exposed": 0, "unverified": 0},
            "can_activate": False,
        }
        self.assertEqual(quarantine.judge_guest_quarantine(report),
                         "guest-denial-unverified")
        self.assertEqual(quarantine.judge_guest_quarantine(report, evidence),
                         "access-login-challenge-candidate")
        for bad in (
            dict(evidence, can_activate=True),
            dict(evidence, historical={**evidence["historical"],
                                       "challenged": 113, "unverified": 1}),
            dict(evidence, canonical={**evidence["canonical"],
                                      "challenged": 0, "unverified": 1}),
        ):
            with self.subTest(bad=bad):
                self.assertEqual(quarantine.judge_guest_quarantine(report, bad),
                                 "guest-denial-unverified")
        self.assertEqual(quarantine.judge_guest_quarantine(
            dict(report, historical_aliases_exposed=1), evidence),
            "inventory-unverified")


if __name__ == "__main__":
    unittest.main()
