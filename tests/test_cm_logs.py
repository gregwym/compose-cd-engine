"""Container Manager log guards without a NAS, Docker writes or host-adapter mocks."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from runner import compose
from runner.cm_logs import Guard
from runner.server import Runner, sha
from shared.wire import Denied


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.wd = self.root / 'app'
        self.wd.mkdir()
        self.path = self.wd / 'compose.yaml'
        self.old = b'services:\n  web:\n    image: example/app:old\n'
        self.path.write_bytes(self.old)
        self.identity = {'project': 'app', 'working_dir': str(self.wd), 'config_files': [str(self.path)]}
        self.config = {'services': {'web': {'image': 'example/app:old'}}}
        self.container = {'id': 'a' * 64, 'name': 'app-web-1', 'service': 'web', 'log_driver': 'db'}

    def denied(self, fn, *args, **kwargs):
        with self.assertRaises(Denied) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, 'cm_logging')


class LogGuard(Fixture):
    def test_inherited_and_explicit_db_allowed(self):
        with patch('runner.compose.run', return_value=b'{"LoggingDriver":"db"}'):
            Guard('logs').preflight(self.config)
            self.config['services']['web']['logging'] = {'driver': 'db', 'options': {}}
            Guard('logs').preflight(self.config)

    def test_overrides_and_unvalidated_options_rejected(self):
        with patch('runner.compose.run', return_value=b'{"LoggingDriver":"db"}'):
            for logging in ({'driver': 'json-file'}, {'driver': 'none'}, {'driver': 'local'},
                            {'options': {'max-size': '2m'}}, {'driver': 'db', 'options': {'max-file': '3'}}):
                with self.subTest(logging=logging):
                    self.config['services']['web']['logging'] = logging
                    self.denied(Guard('logs').preflight, self.config)

    def test_non_synology_default_and_missing_default_fail_closed(self):
        for info in ({'LoggingDriver': 'json-file'}, {}):
            with self.subTest(info=info), patch('runner.compose.run', return_value=json.dumps(info).encode()):
                self.denied(Guard('logs').preflight, self.config)

    def test_off_mode_leaves_docker_only_installations_unchanged(self):
        with patch('runner.compose.run') as run, patch('runner.compose.project_containers') as inspect:
            Guard().preflight(self.config)
            Guard().verify(self.identity)
            run.assert_not_called()
            inspect.assert_not_called()

    def test_unknown_mode_is_not_silently_disabled(self):
        with self.assertRaises(ValueError):
            Guard('log')

    def test_actual_container_driver_checked(self):
        with patch('runner.compose.project_containers', return_value=[self.container]):
            Guard('logs').verify(self.identity)
            for driver in ('json-file', None):
                with self.subTest(driver=driver):
                    self.container['log_driver'] = driver
                    self.denied(Guard('logs').verify, self.identity)

    def test_empty_and_partially_missing_services_fail(self):
        with patch('runner.compose.project_containers', return_value=[self.container]) as containers:
            self.denied(Guard('logs').verify, self.identity, ['web', 'worker'])
            containers.return_value = []
            self.denied(Guard('logs').verify, self.identity)

    def test_service_subset_verifies_only_affected_containers(self):
        worker = {**self.container, 'service': 'worker', 'log_driver': 'json-file'}
        with patch('runner.compose.project_containers', return_value=[self.container, worker]):
            Guard('logs').verify(self.identity, ['web'])
            self.denied(Guard('logs').verify, self.identity)

    def test_docker_inspect_projects_the_actual_log_driver(self):
        raw = {'Id': self.container['id'], 'Name': '/app-web-1',
               'Config': {'Labels': {compose.LABEL + 'project': 'app', compose.LABEL + 'service': 'web'}},
               'HostConfig': {'LogConfig': {'Type': 'db', 'Config': {}}}}
        with patch('runner.compose.run', side_effect=[b'container-id\n', json.dumps([raw]).encode()]):
            self.assertEqual(compose.containers()[0]['log_driver'], 'db')


class RunnerChecks(Fixture):
    def setUp(self):
        super().setUp()
        self.runner = Runner(self.root, min_free_mb=0, prune_images=False, cm_mode='logs')
        observed = patch('runner.compose.observed_identity', return_value=self.identity)
        observed.start()
        self.addCleanup(observed.stop)

    def test_preflight_does_not_resolve_external_env_files(self):
        def render(identity, *, env_resolution=True):
            self.assertFalse(env_resolution, 'log checks must not read env_file before authorization')
            return self.config
        with patch('runner.compose.render', side_effect=render), \
                patch('runner.compose.run', return_value=b'{"LoggingDriver":"db"}'):
            self.runner.check_cm_logs(self.identity)

    def test_boundary_refusal_precedes_log_check(self):
        with patch.object(self.runner, 'check_boundary', side_effect=Denied('boundary_exceeded')), \
                patch.object(self.runner, 'check_cm_logs') as check, self.assertRaises(Denied) as caught:
            self.runner.check_files(self.identity, {})
        self.assertEqual(caught.exception.code, 'boundary_exceeded')
        check.assert_not_called()

    def test_plan_and_apply_refuse_incompatible_yaml_before_writing(self):
        bad = {'services': {'web': {'image': 'example/app:new', 'logging': {'driver': 'json-file'}}}}
        text = self.old.decode().replace(':old', ':new')
        plan = {'identity': self.identity, 'new': False, 'compose': text,
                'base': {'compose': sha(self.old), 'env': None}, 'env_set': {}, 'env_unset': []}
        with patch('runner.compose.render', return_value=self.config), \
                patch.object(self.runner, 'render', return_value=bad), \
                patch('runner.compose.run', return_value=b'{"LoggingDriver":"db"}'), \
                patch('runner.compose.compose') as execute:
            self.denied(self.runner.plan, self.identity, text)
            self.denied(self.runner.apply, plan)
            self.assertEqual(self.path.read_bytes(), self.old)
            self.assertEqual(list(self.wd.iterdir()), [self.path])
            execute.assert_not_called()

    def test_new_project_refused_without_creating_directory(self):
        wd = self.root / 'new'
        identity = {'project': 'new', 'working_dir': str(wd), 'config_files': [str(wd / 'compose.yaml')]}
        bad = {'services': {'web': {'image': 'example/app:new', 'logging': {'driver': 'json-file'}}}}
        with patch('runner.compose.observed_identity', return_value=None), \
                patch.object(self.runner, 'render', return_value=bad), \
                patch('runner.compose.run', return_value=b'{"LoggingDriver":"db"}'):
            self.denied(self.runner.plan, identity, 'services: {}', new=True)
            self.assertFalse(wd.exists())

    def test_up_and_update_refuse_bad_logging_before_mutation(self):
        self.config['services']['web']['logging'] = {'driver': 'json-file'}
        with patch('runner.compose.render', return_value=self.config), \
                patch('runner.compose.run', return_value=b'{"LoggingDriver":"db"}'), \
                patch('runner.compose.compose') as execute:
            for action in ('up', 'update'):
                with self.subTest(action=action):
                    self.denied(self.runner.lifecycle, self.identity, action)
            execute.assert_not_called()

    def test_start_restart_do_not_try_to_change_existing_driver(self):
        self.container['log_driver'] = 'json-file'
        with patch('runner.compose.render', return_value=self.config), \
                patch('runner.compose.run', return_value=b'{"LoggingDriver":"db"}'), \
                patch('runner.compose.project_containers', return_value=[self.container]), \
                patch('runner.compose.compose') as execute:
            for action in ('start', 'restart'):
                with self.subTest(action=action):
                    self.denied(self.runner.lifecycle, self.identity, action)
            execute.assert_not_called()

    def test_stop_and_down_remain_available_for_repair(self):
        with patch.object(self.runner, 'check_cm_logs', side_effect=Denied('cm_logging')) as check, \
                patch('runner.compose.compose') as execute:
            self.assertEqual(self.runner.lifecycle(self.identity, 'stop')['status'], 'success')
            self.assertEqual(self.runner.down(self.identity)['status'], 'success')
            check.assert_not_called()
            self.assertEqual(execute.call_count, 2)

    def test_same_file_trigger_cannot_bypass_preflight(self):
        with patch.object(self.runner, 'check_cm_logs', side_effect=Denied('cm_logging')), \
                patch.object(self.runner, 'fingerprint', return_value='approved'), \
                patch('runner.compose.compose') as execute:
            self.denied(self.runner.pull_image, self.identity, 'example/app', 'latest',
                        ['sha256:' + 'b' * 64], files='approved')
            execute.assert_not_called()

    def test_pin_no_change_still_verifies_runtime_driver(self):
        pinned = 'example/app@sha256:' + 'b' * 64
        with patch('runner.compose.render', return_value={'services': {'web': {'image': pinned}}}), \
                patch('runner.compose.run', return_value=b'{"LoggingDriver":"db"}'), \
                patch('runner.compose.project_containers', return_value=[{**self.container, 'log_driver': 'json-file'}]):
            self.denied(self.runner.update_image, self.identity, 'web', pinned)

    def test_pull_no_change_still_verifies_runtime_driver(self):
        with patch.object(self.runner, 'check_cm_logs'), \
                patch.object(self.runner, 'fingerprint', return_value='approved'), \
                patch.object(self.runner, 'tagged_services', return_value={'web': 'example/app:latest'}), \
                patch('runner.compose.image_ids', return_value={'web': ('example/app:latest', 'image-id')}), \
                patch('runner.compose.has_digest', return_value=True), \
                patch('runner.compose.project_containers', return_value=[{**self.container, 'log_driver': 'json-file'}]):
            self.denied(self.runner.pull_image, self.identity, 'example/app', 'latest',
                        ['sha256:' + 'b' * 64], files='approved')

    def test_postflight_and_rollback_must_verify_actual_log_driver(self):
        for rollback_fails in (False, True):
            with self.subTest(rollback_fails=rollback_fails):
                self.path.write_bytes(self.old)
                plan = {'identity': self.identity, 'new': False, 'compose': self.old.decode().replace(':old', ':new'),
                        'base': {'compose': sha(self.old), 'env': None}, 'env_set': {}, 'env_unset': []}
                checks = []
                def containers(project):
                    checks.append(self.path.read_bytes())
                    driver = 'json-file' if self.path.read_bytes() != self.old or rollback_fails else 'db'
                    return [{**self.container, 'log_driver': driver}]
                with patch('runner.compose.render', return_value=self.config), \
                        patch('runner.compose.run', return_value=b'{"LoggingDriver":"db"}'), \
                        patch('runner.compose.wait_healthy'), \
                        patch('runner.compose.project_containers', side_effect=containers), \
                        patch('runner.compose.compose') as execute:
                    result = self.runner.write_and_up(plan)
                    self.assertEqual(self.path.read_bytes(), self.old)
                    self.assertEqual(checks, [plan['compose'].encode(), self.old])
                    self.assertEqual(result['error'], 'cm_logging')
                    self.assertEqual(result['status'], 'failed' if rollback_fails else 'rolled_back')
                    if rollback_fails:
                        self.assertEqual(result['rollback_error'], 'cm_logging')
                    self.assertEqual(execute.call_args.args,
                        (self.identity, 'up', '-d', '--no-build', '--pull', 'never', '--remove-orphans'))

    def test_rollback_rejects_incompatible_old_config_before_recreating(self):
        restore = Mock()
        with patch.object(self.runner, 'check_cm_logs', side_effect=Denied('cm_logging')), \
                patch('runner.compose.compose') as execute:
            result = self.runner.recover(Denied('unhealthy'), restore, self.identity)
            restore.assert_called_once()
            execute.assert_not_called()
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['rollback_error'], 'cm_logging')
