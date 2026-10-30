from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import identity_staging_authority_once as authority


class AuthorityTests(unittest.TestCase):
 def test_all_existing_authority_combinations_are_observations(self):
  from itertools import product
  for flags in product(('yes','no'),repeat=4):
   value='IDENTITY_STAGING_AUTHORITY docker=%s identity_wrapper=%s repo=%s operator_sudo=%s'%flags
   self.assertEqual(authority.receipt('SUCCEEDED',SimpleNamespace(text=value,exit_code=0)),value)

 def test_failed_partial_and_extra_output_never_leak_host_text(self):
  valid='IDENTITY_STAGING_AUTHORITY docker=no identity_wrapper=no repo=yes operator_sudo=no'
  for status,code,text in [('FAILED',0,valid),('SUCCEEDED',1,valid),('SUCCEEDED',0,valid+'\nprivate host output'),('SUCCEEDED',0,'unexpected diagnostic'),('SUCCEEDED',None,valid)]:
   with self.assertRaises(authority.AuthorityError) as error:
    authority.receipt(status,SimpleNamespace(text=text,exit_code=code))
   self.assertNotIn(text,str(error.exception))

 def test_resolves_only_adopted_host_and_sends_constant_command(self):
  captured=[]
  def model(**kwargs):return SimpleNamespace(**kwargs)
  content=SimpleNamespace(text='IDENTITY_STAGING_AUTHORITY docker=no identity_wrapper=no repo=yes operator_sudo=no',exit_code=0)
  client=SimpleNamespace(create_instance_agent_command=lambda **kwargs:captured.append(kwargs['create_instance_agent_command_details']) or SimpleNamespace(data=SimpleNamespace(id='fixture')),get_instance_agent_command_execution=lambda **kwargs:SimpleNamespace(data=SimpleNamespace(lifecycle_state='SUCCEEDED',content=content)))
  models=SimpleNamespace(**{name:model for name in ['CreateInstanceAgentCommandDetails','InstanceAgentCommandTarget','InstanceAgentCommandContent','InstanceAgentCommandSourceViaTextDetails','InstanceAgentCommandOutputViaTextDetails']})
  sdk=SimpleNamespace(compute_instance_agent=SimpleNamespace(models=models,ComputeInstanceAgentClient=lambda config:client))
  with patch.object(authority,'inspect'),patch.object(authority,'resolve_existing_host',return_value=('adopted-compartment','adopted-instance')):
   self.assertEqual(authority.run(sdk,{}),content.text)
  self.assertEqual(captured[0].target.instance_id,'adopted-instance')
  self.assertEqual(captured[0].content.source.text,authority.COMMAND)


if __name__=='__main__':unittest.main()
