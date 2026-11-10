"""No real OCI access: only fixed read-only command inventory calls."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_atlas_release_audit as audit


class AuditTests(unittest.TestCase):
    def test_only_exact_success_receipt_is_success(self):
        ok = SimpleNamespace(lifecycle_state="SUCCEEDED",
              content=SimpleNamespace(exit_code=0,text=audit.SUCCEEDED))
        self.assertEqual(audit.interpret(ok),
          "IDENTITY_ATLAS_RELEASE_AUDIT command=observed state=SUCCEEDED exit=0 receipt=accepted")
        for text in ("", audit.SUCCEEDED + "\nPRIVATE", "PASSWORD=hidden"):
            bad = SimpleNamespace(lifecycle_state="SUCCEEDED",
                  content=SimpleNamespace(exit_code=0, text=text))
            self.assertIn("receipt=absent-or-unrecognized", audit.interpret(bad))
            self.assertNotIn(text, audit.interpret(bad)) if text else None

    def test_failure_and_unsafe_output_are_sanitized(self):
        bad = SimpleNamespace(lifecycle_state="FAILED",
              content=SimpleNamespace(exit_code=77,
               text="PRIVATE URI mongodb+srv://account:password@db"))
        result = audit.interpret(bad)
        self.assertIn("state=FAILED exit=77", result)
        self.assertIn("receipt=absent-or-unrecognized", result)
        self.assertNotIn("password", result)
        blocked = SimpleNamespace(lifecycle_state="FAILED",
              content=SimpleNamespace(exit_code=1,
               text="IDENTITY_ATLAS_DEPLOY_BLOCKED type=AtlasTransitionBlocked"))
        self.assertIn("receipt=blocked", audit.interpret(blocked))

    def test_inventory_matches_only_pinned_host_and_never_creates_commands(self):
        observed = []
        instance = "ocid1.instance.test"
        def list_(*, compartment_id, instance_id, limit, sort_by, sort_order):
            observed.append("list")
            self.assertEqual((compartment_id,instance_id,limit,sort_by,sort_order),
                             ("compartment", instance,25,"TIMECREATED","DESC"))
            return SimpleNamespace(data=[
              SimpleNamespace(display_name="foreign",instance_id=instance),
              SimpleNamespace(display_name=audit.NAME,instance_id=instance,
                              instance_agent_command_id="command-123")])
        def get_(**kw):
            observed.append("get")
            self.assertEqual(kw,{"instance_agent_command_id":"command-123","instance_id":instance})
            return SimpleNamespace(data=SimpleNamespace(
                lifecycle_state="SUCCEEDED",
                content=SimpleNamespace(text=audit.SUCCEEDED,exit_code=0)))
        client=SimpleNamespace(list_instance_agent_command_executions=list_,
                               get_instance_agent_command_execution=get_)
        sdk=SimpleNamespace(compute_instance_agent=SimpleNamespace(
                     ComputeInstanceAgentClient=lambda cfg:client))
        old=audit.resolve_existing_host
        try:
            audit.resolve_existing_host=lambda *args:("compartment",instance)
            self.assertIn("receipt=accepted",audit.inspect(sdk,{}))
            self.assertEqual(observed,["list","get"])
        finally:
            audit.resolve_existing_host=old

    def test_recent_inventory_not_found_is_not_proof_of_no_host_execution(self):
        client=SimpleNamespace(
            list_instance_agent_command_executions=lambda **kw:SimpleNamespace(data=[]),
            get_instance_agent_command_execution=lambda **kw:self.fail("unexpected get"))
        sdk=SimpleNamespace(compute_instance_agent=SimpleNamespace(
                         ComputeInstanceAgentCommandDetails=None,
                         ComputeInstanceAgentClient=lambda cfg:client))
        old=audit.resolve_existing_host
        try:
            audit.resolve_existing_host=lambda *args:("compartment","host")
            self.assertEqual(audit.inspect(sdk,{}),
                "IDENTITY_ATLAS_RELEASE_AUDIT command=not-observed-in-recent-25")
        finally:
            audit.resolve_existing_host=old


if __name__ == "__main__":
    unittest.main()
