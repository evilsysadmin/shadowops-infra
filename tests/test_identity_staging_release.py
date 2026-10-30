from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import identity_staging_release as release

DIGEST='sha256:'+'a'*64
SHA='b'*40
VAULT='ocid1.vault.oc1.eu.exampleidentifier'


class ReleaseTests(unittest.TestCase):
 def test_omitted_success_output_requires_independent_public_verification(self):
  result=release.receipt('SUCCEEDED',SimpleNamespace(text=None,exit_code=0),DIGEST,SHA)
  self.assertEqual(result,'IDENTITY_STAGING_COMMAND_COMPLETED source_sha='+SHA+' digest='+DIGEST+' public_verification=required')
  self.assertNotIn('SERVICE_STARTED',result)
  for state,code in [('FAILED',0),('SUCCEEDED',1),('SUCCEEDED',None)]:
   with self.assertRaises(release.ReleaseError):release.receipt(state,SimpleNamespace(text=None,exit_code=code),DIGEST,SHA)
 def test_exact_fixed_wrapper_request(self):
  command=release.command_for(DIGEST,SHA,VAULT)
  self.assertEqual(command,'set -eu\ntest -x /usr/local/sbin/shadowops-identity-staging\nsudo --non-interactive /usr/local/sbin/shadowops-identity-staging deploy '+DIGEST+' '+SHA+' '+VAULT+'\n')

 def test_injected_and_mutable_inputs_rejected(self):
  for args in [('latest',SHA,VAULT),(DIGEST,'main',VAULT),(DIGEST,SHA,VAULT+';env'),(DIGEST+'$(env)',SHA,VAULT)]:
   with self.assertRaises(release.ReleaseError):release.command_for(*args)

 def test_raw_host_output_and_wrong_source_never_become_receipts(self):
  expected='IDENTITY_STAGING_SERVICE_STARTED source_sha='+SHA+' digest='+DIGEST
  self.assertEqual(release.receipt('SUCCEEDED',SimpleNamespace(text=expected,exit_code=0),DIGEST,SHA),expected)
  for status,code,output in [('FAILED',1,expected),('SUCCEEDED',0,expected+'\nprivate output'),('SUCCEEDED',0,expected.replace(SHA,'c'*40))]:
   with self.assertRaises(release.ReleaseError) as error:release.receipt(status,SimpleNamespace(text=output,exit_code=code),DIGEST,SHA)
   self.assertNotIn(output,str(error.exception))

 def test_oci_cannot_be_touched_before_input_admission(self):
  with patch.object(release,'inspect') as inspect:
   with self.assertRaises(release.ReleaseError):release.execute(None,{},'latest',SHA)
   inspect.assert_not_called()

 def test_host_failure_exposes_only_fixed_marker_and_state(self):
  private='mongodb://private:secret@database/'
  content=SimpleNamespace(text=private+'\nIDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError',exit_code=1)
  with self.assertRaises(release.ReleaseError) as error:release.receipt('FAILED',content,DIGEST,SHA)
  self.assertIn('status=FAILED reason=IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError',str(error.exception))
  self.assertNotIn(private,str(error.exception))

 def test_inspection_reads_fixed_host_history_without_submitting_a_command(self):
  private='mongodb://private:secret@database/'
  rows=[SimpleNamespace(display_name='other-release',instance_id='host'),SimpleNamespace(display_name='identity-staging-admitted-release',instance_id='host',instance_agent_command_id='fixture-command')]
  calls=[]
  details=[]
  full=SimpleNamespace(lifecycle_state='FAILED',content=SimpleNamespace(text=private+'\nIDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError',exit_code=1))
  client=SimpleNamespace(list_instance_agent_command_executions=lambda **kwargs:calls.append(kwargs) or SimpleNamespace(data=rows),get_instance_agent_command_execution=lambda **kwargs:details.append(kwargs) or SimpleNamespace(data=full))
  sdk=SimpleNamespace(compute_instance_agent=SimpleNamespace(ComputeInstanceAgentClient=lambda config:client))
  with patch.object(release,'resolve_existing_host',return_value=('compartment','host')):
   output=release.inspect_previous(sdk,{})
  self.assertEqual(calls,[dict(compartment_id='compartment',instance_id='host',limit=25,sort_by='TIMECREATED',sort_order='DESC')])
  self.assertEqual(details,[dict(instance_agent_command_id='fixture-command',instance_id='host')])
  self.assertEqual(output,'IDENTITY_STAGING_PREVIOUS_RELEASE status=FAILED exit=1 lines=2 reason=IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError')
  self.assertNotIn(private,output)


if __name__=='__main__':unittest.main()
