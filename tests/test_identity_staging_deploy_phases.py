from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import identity_staging_release as release

spec = importlib.util.spec_from_file_location('identity_host_phases', ROOT / 'host/identity-staging-deploy.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)

DIGEST = 'sha256:' + 'a' * 64
SHA = 'b' * 40
VAULT = 'ocid1.vault.oc1.eu.exampleidentifier'


class IdentityDeployPhaseTests(unittest.TestCase):
    def test_host_and_oci_have_the_same_finite_phase_contract(self):
        self.assertEqual(host.DEPLOY_PHASES, release.DEPLOY_PHASES)
        self.assertEqual(len(host.DEPLOY_PHASES), 7)
        self.assertNotIn('password', repr(host.DEPLOY_PHASES))
        for phase in host.DEPLOY_PHASES:
            with self.subTest(phase=phase):
                with self.assertRaises(host.DeployPhaseError) as result:
                    with host.deployment_phase(phase):
                        raise RuntimeError('sensitive-host-exception database://password')
                self.assertEqual(result.exception.phase, phase)
                self.assertNotIn('sensitive-host-exception', str(result.exception))
                self.assertNotIn('password', str(result.exception))

    def test_untrusted_stage_names_do_not_get_into_host_receipts(self):
        for invalid in ('../etc/shadowops', 'password', '', 'database-start\nSECRET', 'images&env'):
            with self.subTest(invalid=invalid):
                with self.assertRaises(host.DeployError):
                    with host.deployment_phase(invalid):
                        pass

    def test_root_wrapper_emits_only_fixed_phase_not_private_exception(self):
        for phase in host.DEPLOY_PHASES:
            private = f'vault-private-{phase}-secret'
            output = io.StringIO()
            with patch.object(sys, 'argv', ['wrapper', 'deploy', DIGEST, SHA, VAULT]), \
                    patch.object(host, 'deploy', side_effect=host.DeployPhaseError(phase)), \
                    redirect_stdout(output):
                self.assertEqual(host.main(), 1)
            marker = f'IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError phase={phase}'
            self.assertEqual(output.getvalue().strip(), marker)
            self.assertNotIn(private, output.getvalue())
            self.assertEqual(release.failure_reason(f'{private}\n{marker}'), marker)
            with self.assertRaises(release.ReleaseError) as error:
                release.receipt('FAILED', SimpleNamespace(
                    text=f'{private}\n{marker}', exit_code=1), DIGEST, SHA)
            self.assertIn('reason=' + marker, str(error.exception))
            self.assertNotIn(private, str(error.exception))

    def test_legacy_generic_deploy_error_is_still_understood(self):
        self.assertEqual(release.failure_reason(
            'IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError'),
            'IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError')

    def test_oci_rejects_unknown_phase_and_embedded_private_text(self):
        for raw in (
            'IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError phase=secrets',
            'IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError phase=../../../etc',
            'IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError phase=images secret=abc',
        ):
            with self.subTest(raw=raw):
                self.assertEqual(release.failure_reason(raw), 'no-wrapper-receipt')

        # Extra private host text is deliberately discarded, not echoed to CI.
        self.assertEqual(
            release.failure_reason('private-host-data\nIDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError phase=images'),
            'IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError phase=images',
        )


if __name__ == '__main__':
    unittest.main()
