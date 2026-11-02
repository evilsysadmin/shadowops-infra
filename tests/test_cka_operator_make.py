"""Current operator surface cannot recreate the retired CKA service."""
from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[1]
class OperatorMake(unittest.TestCase):
    def test_default_help_and_retirement_targets(self):
        result=subprocess.run(['make','--no-print-directory'],cwd=ROOT,capture_output=True,text=True,check=True)
        self.assertIn('make cka-retire-host',result.stdout)
        self.assertIn('make cka-retire-inspect',result.stdout)
        for target,action in [('cka-retire-host','retire'),('cka-retire-inspect','inspect')]:
            result=subprocess.run(['make','-n',target],cwd=ROOT,capture_output=True,text=True,check=True)
            self.assertIn('bash host/cka-retire-over-ssh.sh '+action,result.stdout)
    def test_legacy_make_targets_fail_without_network(self):
        for target in ['bootstrap','cluster-bootstrap','api-start','tunnel-start']:
            result=subprocess.run(['make','cka-lab-'+target],cwd=ROOT,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('retired',result.stderr)
if __name__=='__main__':unittest.main()
