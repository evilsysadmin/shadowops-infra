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


if __name__=='__main__':unittest.main()
