import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from scripts.agent import Client, Workflow
from deployer import schema


class DurableContinuation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'flow.json'
        self.client = Client('https://engine.example.ts.net', 'openclaw', 'app', b'x' * 48)
        self.client.call = Mock()
        self.spec = {'services': {'app': {'image': 'ghcr.io/example/app@sha256:' + 'a' * 64,
                                         'environment': {'TOKEN': 'SENSITIVE_VALUE'}, 'memory_mb': 64, 'cpus': 1}}}

    def tearDown(self):
        self.temp.cleanup()

    def test_approval_restart_and_original_plan_automatic_continuation(self):
        self.client.call.side_effect = [
            {'status': 'needs_approval', 'plan_id': 'a' * 32, 'grant_diff': {'egress': True}},
            {'status': 'pending', 'request_id': 'b' * 32, 'approval_url': 'https://approval.example.ts.net/requests/' + 'b' * 32,
             'scope': {'egress': True}, 'mode': 'persistent'},
            {'status': 'pending'}, {'status': 'approved'}, {'status': 'accepted', 'task_id': 'c' * 32}, {'status': 'success'}]
        first = Workflow(self.client, self.path, self.spec)
        self.assertEqual(first.step()['status'], 'planned')
        self.assertEqual(first.step()['status'], 'authorization_required')
        self.assertNotIn('SENSITIVE_VALUE', self.path.read_text())
        restored = Workflow(self.client, self.path)
        self.assertEqual(restored.step()['status'], 'waiting_for_authorization')
        self.assertEqual(restored.run(follow=True, interval=0), 0)
        self.client.call.assert_any_call('apply', {'plan_id': 'a' * 32})
        self.assertEqual(sum(c.args[0] == 'plan' for c in self.client.call.call_args_list), 1)
        self.assertEqual(Workflow(self.client, self.path).step()['status'], 'success')

    def test_apply_lost_response_retries_only_same_immutable_plan(self):
        self.client.call.side_effect = [{'status': 'authorized', 'plan_id': 'a' * 32}, OSError(),
                                        {'status': 'accepted', 'task_id': 'c' * 32}, {'status': 'success'}]
        flow = Workflow(self.client, self.path, self.spec, emit=lambda _: None)
        self.assertEqual(flow.run(follow=True, interval=0), 0)
        applies = [c.args[1] for c in self.client.call.call_args_list if c.args[0] == 'apply']
        self.assertEqual(applies, [{'plan_id': 'a' * 32}] * 2)

    def test_resume_does_not_accept_spec_identity_or_endpoint_swap(self):
        Workflow(self.client, self.path, self.spec)
        changed = copy.deepcopy(self.spec); changed['services']['app']['memory_mb'] = 128
        with self.assertRaises(ValueError):
            Workflow(self.client, self.path, changed)
        self.client.endpoint = 'https://other.example.ts.net'
        with self.assertRaises(ValueError):
            Workflow(self.client, self.path)

    def test_unknown_task_outcome_does_not_retry_or_replan(self):
        self.client.call.side_effect = [{'status': 'authorized', 'plan_id': 'a' * 32},
            {'status': 'accepted', 'task_id': 'c' * 32}, {'status': 'outcome_unknown'}]
        flow = Workflow(self.client, self.path, self.spec, emit=lambda _: None)
        self.assertEqual(flow.run(follow=True, interval=0), 1)
        self.assertEqual(self.client.call.call_count, 3)

    def test_private_state_and_key_and_https_boundaries(self):
        for endpoint in ('http://localhost', 'https://x/path', 'https://user:pass@x', 'https://x?token=foo'):
            with self.assertRaises(ValueError):
                Client(endpoint, 'openclaw', 'app', b'x' * 48)
        self.path.symlink_to(Path(self.temp.name) / 'missing')
        with self.assertRaises(ValueError):
            Workflow(self.client, self.path, self.spec)
