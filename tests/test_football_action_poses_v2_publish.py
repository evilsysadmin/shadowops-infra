"""V2 action-art publisher never silently broadens authority or overwrites."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import football_action_poses_v2_publish as poses
import football_delivery as delivery


class ActionPoseV2Contracts(unittest.TestCase):
    def test_exact_eight_immutable_filenames(self):
        self.assertEqual(len(poses.EXPECTED), 8)
        self.assertEqual(len(poses.SOURCES), 6)
        self.assertEqual(len(poses.KEYFRAMES), 4)
        for team in poses.TEAMS:
            for action in poses.ACTIONS:
                filename = f"{team}_{action}_poses_v2.webp"
                self.assertEqual(len(poses.EXPECTED[filename]), 64)
                self.assertEqual(len(poses.KEYFRAMES[action]), 8)
        self.assertTrue(all(name.endswith("_poses_v2.webp") for name in poses.EXPECTED))
        self.assertEqual(poses.BUCKET, "football")
        self.assertNotEqual(poses.BUCKET, delivery.BUCKET)

    def test_pr_and_local_publish_denied_before_network_or_cloud(self):
        with patch.dict(os.environ, {
            "GITHUB_REPOSITORY": "evilsysadmin/shadowops-infra",
            "GITHUB_REF": "refs/pull/42/merge",
            "GITHUB_EVENT_NAME": "pull_request",
        }):
            with patch.object(poses.delivery, "admit", side_effect=AssertionError("network must not run")):
                with self.assertRaises(delivery.DeliveryError):
                    poses.publish({})

    def test_mutated_branch_refused(self):
        with patch.dict(os.environ, {
            "GITHUB_REPOSITORY": "evilsysadmin/shadowops-infra",
            "GITHUB_REF": "refs/heads/other",
            "GITHUB_EVENT_NAME": "push",
        }):
            with patch.object(poses.delivery, "admit", side_effect=AssertionError("network must not run")):
                with self.assertRaises(delivery.DeliveryError):
                    poses.publish({})

    def test_wrong_football_main_sha_refused_before_cloud(self):
        with patch.dict(os.environ, {
            "GITHUB_REPOSITORY": "evilsysadmin/shadowops-infra",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push",
        }):
            with patch.object(poses.delivery, "admit", return_value={"source_sha": "1" * 40}):
                with patch.object(poses, "inventory", side_effect=AssertionError("cloud must not run")):
                    with self.assertRaises(delivery.DeliveryError):
                        poses.publish({})


if __name__ == "__main__":
    unittest.main()
