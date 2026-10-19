import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from authorization.scope import Denied
from deployer import schema
import test_authorization as auth
import test_projects as projects


class SandboxAndOperations(auth.GrantEnforcement):
    def test_preauthorized_signed_sandbox_and_data_expansion(self):
        image = self.cfg['images']['example.invalid/team/app']
        image.update(allow_unsigned=False,
            identity='https://github.com/team/app/.github/workflows/build.yml@refs/heads/main',
            issuer='https://token.actions.githubusercontent.com', platform='linux/amd64')
        self.cfg['verification'] = {'socket': '/run/verify.sock', 'service_key': '/etc/verify.key'}
        self.cfg['authorization']['sandbox'] = {'repositories': ['example.invalid/team/app'], 'memory_mb': 128, 'cpus': 1, 'max_services': 1}
        item = projects.spec()
        item['services']['app'].update(mounts=[], ports=[])
        item['egress'] = False
        self.assertEqual(self.call('plan', item)['status'], 'authorized')
        for change in ('mounts', 'ports', 'egress', 'memory_mb'):
            new = copy.deepcopy(item)
            if change == 'egress':
                new['egress'] = True
            elif change == 'memory_mb':
                new['services']['app']['memory_mb'] = 256
            else:
                new['services']['app'][change] = projects.spec()['services']['app'][change]
            self.assertEqual(self.call('plan', new)['status'], 'needs_approval')

    def test_retire_never_deletes_data_and_requires_apply_to_recreate(self):
        self.apply(); self.run_job()
        task = self.call('retire')['task_id']
        ident = 'a' * 64
        with patch.object(self.service, 'docker', side_effect=[ident.encode(), b'', b'']) as docker:
            self.service.run_one()
        self.assertEqual(self.task(task)['status'], 'success')
        self.assertEqual([c.args[0] for c in docker.call_args_list], ['ps', 'stop', 'rm'])
        self.assertNotIn('-v', json.dumps([c.args for c in docker.call_args_list]))
        with self.assertRaises(Denied):
            self.call('start')
        self.apply(); self.run_job()
        with self.service.db() as db:
            self.assertEqual(db.execute('SELECT retired FROM project_lifecycle').fetchone()[0], 0)

    def test_structured_diagnostics_no_environment_health_output_or_logs(self):
        self.apply(); self.run_job()
        outputs = [b'app running\n', b'abc123\n', b'1 4 unhealthy\n', b'12.4% 0.5%\n']
        with patch.object(self.service, 'docker', side_effect=outputs) as docker:
            result = self.call('diagnose')
        self.assertEqual(result['diagnostics']['app']['health'], 'unhealthy')
        self.assertEqual(result['diagnostics']['app']['restart_count'], 4)
        self.assertEqual(result['last_task']['stage'], 'complete')
        for call in docker.call_args_list:
            self.assertNotIn('logs', call.args)
            self.assertNotIn('{{json .}}', call.args)
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_durable_audit_outbox_is_idempotent_and_survives_restart(self):
        self.apply(); self.run_job()
        self.service.flush_audit(); self.service.flush_audit()
        with self.auth_store.db() as db:
            actions = [r[0] for r in db.execute("SELECT action FROM audit WHERE action LIKE 'deployment_%'")]
        self.assertEqual(actions, ['deployment_queued', 'deployment_success'])
        with self.service.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM audit_outbox WHERE sent=0').fetchone()[0], 0)


def load_tests(loader, tests, pattern):
    # The base regressions already run once with grants in test_authorization.
    return unittest.TestSuite(SandboxAndOperations(name) for name in SandboxAndOperations.__dict__ if name.startswith('test_'))
