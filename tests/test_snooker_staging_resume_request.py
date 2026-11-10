import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_staging_resume_request as ticket

HEAD = "c" * 40


def approved_context(**changes):
    values = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": ticket.REPO,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": HEAD,
        "GITHUB_WORKFLOW_REF": (
            ticket.REPO + "/.github/workflows/" + ticket.WORKFLOW + "@refs/heads/main"
        ),
    }
    values.update(changes)
    return values


class OneUseResumeTests(unittest.TestCase):
    def verify(self, *, payload=None, diff=None, parents=None, head=HEAD, env=None):
        ticket.verify(json.dumps(ticket.INTENT if payload is None else payload),
                      {ticket.REQUEST: "A"} if diff is None else diff,
                      [ticket.BASE] if parents is None else parents, head,
                      approved_context() if env is None else env)

    def test_exact_approved_one_time_staging_resume(self):
        self.verify()
        actual = Path(__file__).resolve().parents[1] / ticket.REQUEST
        self.assertEqual(json.loads(actual.read_text(encoding="utf-8")), ticket.INTENT)

    def test_modification_or_replay_cannot_retrigger(self):
        for state in ("M", "D", "R100", ""):
            with self.subTest(state=state), self.assertRaises(ticket.RequestBlocked):
                self.verify(diff={ticket.REQUEST: state})
        with self.assertRaises(ticket.RequestBlocked):
            self.verify(diff={ticket.REQUEST: "A", "edge/snooker-identity-gate.mjs": "M"})

    def test_unapproved_intent_is_rejected(self):
        for name, bad in [
            ("application", "football"),
            ("environment", "production"),
            ("base_main_sha", HEAD),
            ("single_use", False),
            ("requires", "no-host-verification"),
            ("health", "identity=unhealthy"),
            ("request", "resume-after-verified-identity-health"),
            ("issue", 999),
        ]:
            with self.subTest(name=name), self.assertRaises(ticket.RequestBlocked):
                self.verify(payload={**ticket.INTENT, name: bad})
        with self.assertRaises(ticket.RequestBlocked):
            self.verify(parents=["a" * 40])
        with self.assertRaises(ticket.RequestBlocked):
            self.verify(parents=[ticket.BASE, "b" * 40])

    def test_untrusted_workflow_event_repo_ref_and_commit_rejected(self):
        for key, bad in [
            ("GITHUB_ACTIONS", "false"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REPOSITORY", "evil/infra"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_SHA", "a" * 40),
            ("GITHUB_WORKFLOW_REF", "evil/infra/.github/workflows/workflow.yml@main"),
        ]:
            with self.subTest(key=key), self.assertRaises(ticket.RequestBlocked):
                self.verify(env=approved_context(**{key: bad}))

    def test_malformed_receipts_are_rejected(self):
        with self.assertRaises(ticket.RequestBlocked):
            ticket.verify("not json", {ticket.REQUEST: "A"},
                          [ticket.BASE], HEAD, approved_context())
        with self.assertRaises(ticket.RequestBlocked):
            self.verify(head="untrusted")
        with self.assertRaises(ticket.RequestBlocked):
            self.verify(diff={ticket.REQUEST: "A", "README.md": "A"})

    def test_cli_does_not_read_secrets_or_dispatch_anything(self):
        import inspect
        source = inspect.getsource(ticket)
        for forbidden in ("gh workflow run", "oci ", "sudo ", "cloudflare "):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
