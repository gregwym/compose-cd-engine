"""Agent -> gateway -> Passkey approval -> real runner -> Docker. Opt in with CD_DOCKER_TESTS=1."""
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from helpers import Stack
from runner import compose, server
from runner.server import Runner
from test_runner_docker import HEALTHY


@unittest.skipUnless(os.environ.get('CD_DOCKER_TESTS') == '1', 'set CD_DOCKER_TESTS=1 to use the Docker daemon')
class EndToEnd(unittest.TestCase):
    def setUp(self):
        compose.DOCKER = shutil.which('docker')
        self.temp = tempfile.mkdtemp(prefix='cd-e2e-', dir=os.environ.get('CD_TEST_ROOT', tempfile.gettempdir()))
        self.root = Path(self.temp) / 'docker'
        self.root.mkdir()
        self.sockets = tempfile.mkdtemp(prefix='cd-', dir='/tmp')
        path = self.sockets + '/runner.sock'
        runner = Runner(self.root, '', health_timeout=30)
        threading.Thread(target=server.serve, args=(runner, path), daemon=True).start()
        while not os.path.exists(path):
            pass
        self.stack = Stack(runner_socket=path, fake=False)
        self.stack.enroll()
        self.stack.pair()
        self.agent = self.stack.agent
        self.name = 'cde2e' + uuid.uuid4().hex[:6]

    def tearDown(self):
        self.stack.close()
        subprocess.run([compose.DOCKER, 'compose', '-p', self.name, 'down', '--remove-orphans'], capture_output=True)
        subprocess.run(['rm', '-rf', self.temp, self.sockets])

    def test_create_operate_change_and_down(self):
        created = self.stack.approve(self.agent('request', kind='create', project=self.name, compose=HEALTHY, days=1))
        self.assertEqual(self.stack.wait_job(created['outcome']['job'])['status'], 'success')
        read = self.stack.approve(self.agent('request', kind='read'))
        listed = {p['project']: p for p in self.agent('projects')['projects']}
        self.stack.browser.passkey('revoke', read['outcome']['grant'])
        self.assertTrue(listed[self.name]['manageable'])
        self.assertIsNotNone(listed[self.name]['operate_until'])

        self.assertEqual(self.stack.wait_job(self.agent('restart', project=self.name)['job'])['status'], 'success')
        current = self.agent('read', project=self.name)['compose']
        change = self.agent('request', kind='change', project=self.name, compose=current.replace('3600', '7200'),
                            env_set={'MODE': 'prod'})
        self.assertNotIn('diff', change['detail']['plan'])  # agent response excludes the raw diff
        status, page = self.stack.browser.request('GET', '/api/request/' + change['id'])
        self.assertFalse(page['detail']['plan']['redacted'])
        self.assertNotIn('sleep 7200', page['detail']['plan']['diff'])
        self.assertEqual(page['detail']['plan']['env']['added'], ['MODE'])
        done = self.stack.approve(change)
        self.assertEqual(self.stack.wait_job(done['outcome']['job'])['status'], 'success')
        self.assertIn('7200', (self.root / self.name / 'compose.yaml').read_text())
        self.assertEqual(self.agent('read', project=self.name)['env_keys'], ['MODE'])

        privileged = current.replace('    volumes:', '    privileged: true\n    volumes:')
        status, data = self.agent.send(self.agent.body('request', {'kind': 'change', 'project': self.name,
                                                                  'compose': privileged}))
        self.assertEqual(data['error'], 'policy')

        down = self.stack.approve(self.agent('request', kind='down', project=self.name))
        self.assertEqual(self.stack.wait_job(down['outcome']['job'])['status'], 'success')
        self.assertEqual(compose.project_containers(self.name), [])
        self.assertTrue((self.root / self.name / 'compose.yaml').exists())


if __name__ == '__main__':
    unittest.main()
