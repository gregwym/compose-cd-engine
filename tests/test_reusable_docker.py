"""Opt-in real-Docker evidence for reusable creation, editing, exec and diagnostics."""
import os
import time
import unittest
from test_runner_docker import RunnerDocker, IMAGE
from runner import compose


@unittest.skipUnless(os.environ.get('CD_DOCKER_TESTS') == '1', 'set CD_DOCKER_TESTS=1')
class ReusableDocker(RunnerDocker):
    # Reuse setup/cleanup, not the inherited legacy test suite.
    def test_reusable_create_edit_exec_timeout(self):
        identity = self.identity()
        boundary = {'mounts': [], 'networks': []}
        text = f'services:\n  web:\n    image: {IMAGE}\n    command: ["sleep", "3600"]\n'
        plan = self.runner.plan(identity, text, new=True, boundary=boundary)
        self.assertEqual(self.runner.apply(plan, boundary=boundary)['status'], 'success')
        for seconds in (3601, 3602):
            changed = text.replace('3600', str(seconds))
            plan = self.runner.plan(identity, changed, boundary=boundary)
            self.assertEqual(self.runner.apply(plan, boundary=boundary)['status'], 'success')
        diagnostic = self.runner.diagnose(identity['project'])
        container = diagnostic['containers'][0]['id']
        for word in ('hello', 'again'):
            result = self.runner.exec(identity, boundary, container, ['echo', word], int(time.time()) + 30)
            self.assertEqual(result['status'], 'success', result)
            self.assertIn(word, result['output'])
        result = self.runner.exec(identity, boundary, container, ['sleep', '20'], int(time.time()) + 30, timeout=1)
        self.assertTrue(result['timed_out'], result)
        result = self.runner.exec(identity, boundary, container, ['sh', '-c', 'yes output | head -c 100000'],
                                  int(time.time()) + 30)
        self.assertTrue(result['truncated'])
        self.assertLessEqual(len(result['output'].encode()), 65536)


# Avoid duplicating RunnerDocker's imported/inherited test cases in discovery.
for _name in list(vars(RunnerDocker)):
    if _name.startswith('test_'):
        setattr(ReusableDocker, _name, None)
del RunnerDocker
