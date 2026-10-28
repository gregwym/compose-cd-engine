"""Runner against a real Docker daemon. Opt in with CD_DOCKER_TESTS=1.

Projects live in a temporary PROJECTS_ROOT and are torn down afterwards."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from runner import compose
from runner.server import Runner
from shared.wire import Denied

IMAGE = os.environ.get('CD_TEST_IMAGE', 'busybox:1.36')
HEALTHY = f'''services:
  web:
    image: {IMAGE}
    command: ["sh", "-c", "touch /tmp/ok; sleep 3600"]
    healthcheck:
      test: ["CMD", "test", "-f", "/tmp/ok"]
      interval: 1s
      retries: 3
    volumes:
      - ./data:/data
'''


@unittest.skipUnless(os.environ.get('CD_DOCKER_TESTS') == '1', 'set CD_DOCKER_TESTS=1 to use the Docker daemon')
class RunnerDocker(unittest.TestCase):
    def setUp(self):
        compose.DOCKER = shutil.which('docker')
        base = os.environ.get('CD_TEST_ROOT', tempfile.gettempdir())
        self.temp = tempfile.mkdtemp(prefix='cd-root-', dir=base)
        self.root = Path(self.temp) / 'docker'
        self.root.mkdir()
        self.runner = Runner(self.root, str(Path(self.temp) / 'deployer'), health_timeout=20)
        self.name = 'cdtest' + uuid.uuid4().hex[:8]

    def tearDown(self):
        for item in self.root.iterdir():
            subprocess.run([compose.DOCKER, 'compose', '-p', item.name, '--project-directory', str(item),
                            'down', '--remove-orphans'], capture_output=True)
        subprocess.run(['rm', '-rf', self.temp])

    def identity(self, name=None):
        name = name or self.name
        wd = str(self.root / name)
        return {'project': name, 'working_dir': wd, 'config_files': [wd + '/compose.yaml']}

    def create(self, text=HEALTHY, env=None):
        plan = self.runner.plan(self.identity(), text, env, None, new=True)
        result = self.runner.apply(plan)
        self.assertEqual(result['status'], 'success', result)
        return plan

    def test_created_project_has_container_manager_identity(self):
        plan = self.create()
        self.assertIn('+    image: ' + IMAGE, plan['diff'])
        listed = {p['project']: p for p in self.runner.projects()['projects']}
        self.assertTrue(listed[self.name]['manageable'])
        self.assertEqual(listed[self.name]['identity'], self.identity())
        read = self.runner.read(self.identity())
        self.assertEqual(read['compose'], HEALTHY)

    def test_change_is_written_in_place_with_backup(self):
        self.create()
        path = Path(self.identity()['config_files'][0])
        inode = path.stat().st_ino
        changed = HEALTHY.replace('sleep 3600', 'sleep 3601')
        plan = self.runner.plan(self.identity(), changed, {'GREETING': 'hello world'})
        self.assertEqual(plan['env'], {'added': ['GREETING'], 'removed': [], 'changed': []})
        result = self.runner.apply(plan)
        self.assertEqual(result['status'], 'success', result)
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(path.read_text(), changed)
        self.assertEqual(len(result['backups']), 1)
        self.assertTrue((path.parent / result['backups'][0]).exists())
        self.assertEqual((path.parent / '.env').read_text(), "GREETING='hello world'\n")
        self.assertEqual(compose.observed_identity(self.name), self.identity())

    def test_unhealthy_change_rolls_back_files_and_containers(self):
        self.create()
        before = compose.project_containers(self.name)[0]['id']
        broken = HEALTHY.replace('test", "-f", "/tmp/ok', 'test", "-f", "/tmp/missing')
        result = self.runner.apply(self.runner.plan(self.identity(), broken))
        self.assertEqual(result['status'], 'rolled_back', result)
        self.assertEqual(Path(self.identity()['config_files'][0]).read_text(), HEALTHY)
        now = compose.project_containers(self.name)
        self.assertNotEqual(now[0]['id'], before)
        self.assertEqual(now[0]['health'], 'healthy')

    def test_container_manager_edit_after_approval_is_not_overwritten(self):
        self.create()
        plan = self.runner.plan(self.identity(), HEALTHY.replace('3600', '3602'))
        path = Path(self.identity()['config_files'][0])
        path.write_text(HEALTHY.replace('3600', '3603'))
        with self.assertRaises(Denied) as caught:
            self.runner.apply(plan)
        self.assertEqual(caught.exception.code, 'stale')
        self.assertIn('3603', path.read_text())

    def test_hard_policy_rejects_before_review(self):
        self.create()
        for text in (HEALTHY.replace('    volumes:', '    privileged: true\n    volumes:'),
                     HEALTHY.replace('./data:/data', '/var/run/docker.sock:/var/run/docker.sock'),
                     HEALTHY.replace('./data:/data', self.temp + '/deployer:/x')):
            with self.assertRaises(Denied) as caught:
                self.runner.plan(self.identity(), text)
            self.assertEqual(caught.exception.code, 'policy')

    def test_highlights_new_host_paths_and_ports(self):
        self.create()
        text = HEALTHY.replace('./data:/data', '/tmp:/host-tmp:ro') + '    ports: ["127.0.0.1:18999:80"]\n'
        plan = self.runner.plan(self.identity(), text)
        self.assertIn('web: host path /tmp -> /host-tmp (read-only)', plan['highlights'])
        self.assertIn('web: port 127.0.0.1:18999 -> 80/tcp', plan['highlights'])

    def test_secret_and_env_files_follow_the_mount_rules(self):
        self.create()
        deployer = Path(self.temp) / 'deployer'
        deployer.mkdir()
        (deployer / 'state').write_text('KEY=private\n')
        outside = Path(self.temp) / 'outside.env'
        outside.write_text('OTHER=1\n')
        env_file = HEALTHY.replace('    volumes:', '    env_file: [{path}]\n    volumes:')
        secret = HEALTHY.replace('    volumes:', '    secrets: [s]\n    volumes:') + 'secrets:\n  s:\n    file: {path}\n'
        for text in (env_file, secret):
            for path in (deployer / 'state', '../../deployer/state'):  # relative paths resolve from the project
                with self.assertRaises(Denied, msg=(text, path)) as caught:
                    self.runner.plan(self.identity(), text.format(path=path))
                self.assertEqual(caught.exception.code, 'policy')
        self.assertIn(f'web: env_file: host file {outside}',
                      self.runner.plan(self.identity(), env_file.format(path=outside))['highlights'])
        self.assertIn(f'secret s: host file {outside}',
                      self.runner.plan(self.identity(), secret.format(path=outside))['highlights'])

    def test_lifecycle(self):
        self.create()
        self.assertEqual(self.runner.lifecycle(self.identity(), 'stop')['status'], 'success')
        self.assertEqual(compose.project_containers(self.name)[0]['state'], 'exited')
        self.assertEqual(self.runner.lifecycle(self.identity(), 'start')['status'], 'success')
        self.assertEqual(self.runner.lifecycle(self.identity(), 'restart', ['web'])['status'], 'success')
        self.assertEqual(self.runner.lifecycle(self.identity(), 'up')['status'], 'success')
        self.assertEqual(self.runner.lifecycle(self.identity(), 'update'), {'status': 'success', 'updated': []})
        self.assertEqual(self.runner.down(self.identity())['status'], 'success')
        self.assertEqual(compose.project_containers(self.name), [])

    def pinned(self):
        out = subprocess.run([compose.DOCKER, 'image', 'inspect', IMAGE], capture_output=True, check=True).stdout
        return json.loads(out)[0]['RepoDigests'][0]

    def test_update_image_literal_line(self):
        self.create()
        result = self.runner.update_image(self.identity(), 'web', self.pinned())
        self.assertEqual(result['status'], 'success', result)
        self.assertIn('image: ' + self.pinned(), Path(self.identity()['config_files'][0]).read_text())
        self.assertEqual(self.runner.update_image(self.identity(), 'web', self.pinned())['status'], 'no_change')

    def test_update_image_variable_in_env(self):
        self.create(HEALTHY.replace('image: ' + IMAGE, 'image: ${WEB_IMAGE}'), {'WEB_IMAGE': IMAGE})
        result = self.runner.update_image(self.identity(), 'web', self.pinned())
        self.assertEqual(result['status'], 'success', result)
        self.assertIn('image: ${WEB_IMAGE}', Path(self.identity()['config_files'][0]).read_text())
        self.assertEqual((self.root / self.name / '.env').read_text(), 'WEB_IMAGE=' + self.pinned() + '\n')

    def test_update_image_refuses_another_repository(self):
        self.create()
        with self.assertRaises(Denied) as caught:
            self.runner.update_image(self.identity(), 'web', 'ghcr.io/evil/busybox@sha256:' + 'a' * 64)
        self.assertEqual(caught.exception.code, 'repository_mismatch')

    def test_identity_must_match_container_labels(self):
        self.create()
        other = self.root / 'elsewhere'
        other.mkdir()
        (other / 'compose.yaml').write_text(HEALTHY)
        moved = {'project': self.name, 'working_dir': str(other), 'config_files': [str(other / 'compose.yaml')]}
        with self.assertRaises(Denied) as caught:
            self.runner.lifecycle(moved, 'restart')
        self.assertEqual(caught.exception.code, 'identity_changed')

    def test_projects_outside_root_are_read_only(self):
        outside = Path(self.temp) / 'outside'
        outside.mkdir()
        (outside / 'compose.yaml').write_text(HEALTHY)
        subprocess.run([compose.DOCKER, 'compose', '-p', self.name, '--project-directory', str(outside),
                        '-f', str(outside / 'compose.yaml'), 'up', '-d'], check=True, capture_output=True)
        try:
            listed = {p['project']: p for p in self.runner.projects()['projects']}
            self.assertFalse(listed[self.name]['manageable'])
            self.assertEqual(listed[self.name]['reason'], 'outside PROJECTS_ROOT')
            with self.assertRaises(Denied):
                self.runner.read(listed[self.name]['identity'])
            self.assertIn(self.name, ''.join(self.runner.logs(self.name)['logs']))
        finally:
            subprocess.run([compose.DOCKER, 'compose', '-p', self.name, 'down'], capture_output=True)

    def test_failed_create_stops_but_keeps_files(self):
        with mock.patch.object(self.runner, 'health_timeout', 5):
            plan = self.runner.plan(self.identity(), HEALTHY.replace('/tmp/ok"]', '/tmp/never"]'), new=True)
            result = self.runner.apply(plan)
        self.assertEqual(result['status'], 'failed', result)
        self.assertTrue(Path(self.identity()['config_files'][0]).exists())
        self.assertEqual(compose.project_containers(self.name), [])


if __name__ == '__main__':
    unittest.main()
