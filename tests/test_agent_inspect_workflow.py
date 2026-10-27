"""Offline only: no NAS, keychain, credentials or external services."""
import io
import json
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from deployer import schema
from deployer.adoption import inspection_scope, inspection_policy
from scripts.agent import Client, InspectWorkflow, main


class InspectionContinuation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'read.json'
        self.client = Client('https://engine.example.invalid', 'openclaw', 'existing-app', b'x' * 48)
        self.client.call = Mock()
        self.events = []

    def request(self, status='pending'):
        scope = inspection_scope(self.client.project)
        return {'status': status, 'request_id': 'a'*32, 'plan_id': 'b'*32,
                'project': self.client.project, 'agent': self.client.agent,
                'approval_url': 'https://approval.example.invalid/requests/' + 'a'*32,
                'scope': scope, 'policy': inspection_policy(self.client.project),
                'spec_hash': schema.fingerprint(scope), 'mode': 'once', 'lifetime': 600}

    def structure(self):
        row = {'container_id': 'c'*64, 'name': 'private-container', 'project': 'existing-app',
               'service': 'web', 'image': 'example.invalid/private:latest', 'image_id': 'sha256:'+'d'*64,
               'working_dir': '/private/nas', 'config_files': ['/private/nas/compose.yaml'],
               'mounts': [{'type': 'bind', 'source': '/private/data', 'target': '/data', 'read_only': False}],
               'ports': [{'target': '80/tcp', 'host_ip': '0.0.0.0', 'published': 8080}],
               'networks': ['private-network'], 'state': 'running'}
        baseline = {'project': 'existing-app', 'containers': [row]}
        return {**baseline, 'baseline_hash': schema.fingerprint(baseline), 'read_only': True,
                'managed_access_granted': False, 'adoption_ready': False, 'blockers': ['review required']}

    def flow(self):
        return InspectWorkflow(self.client, self.path, 'once', 600, self.events.append)

    def waiting(self):
        self.client.call.return_value = self.request()
        flow = self.flow()
        self.assertEqual(flow.step()['status'], 'authorization_required')
        return flow

    def test_pending_restart_approval_then_private_structure_and_sanitized_counts(self):
        flow = self.waiting()
        self.client.call.return_value = self.request()
        self.assertEqual(flow.run(interval=0), 75)
        # Default options on restore do not renew/change the stored grant mode.
        restored = InspectWorkflow(self.client, self.path, emit=self.events.append)
        self.client.call.side_effect = [self.request('approved'), self.structure()]
        self.assertEqual(restored.run(True, interval=0), 0)
        self.assertEqual([c.args[0] for c in self.client.call.call_args_list],
                         ['inspect_request', 'grant_status', 'grant_status', 'inspect'])
        event = self.events[-1]
        self.assertEqual((event['containers'], event['mounts'], event['ports'], event['networks']), (1, 1, 1, 1))
        self.assertEqual(event['baseline_hash'], self.structure()['baseline_hash'])
        for secret in ('private-container', '/private/nas', 'private-network', 'private/data'):
            self.assertNotIn(secret, json.dumps(self.events) + self.path.read_text())
        self.assertEqual(json.loads(restored.output.read_text()), self.structure())
        for path in (self.path, restored.output, self.path.with_name('read.json.lock')):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        calls = self.client.call.call_count
        self.assertEqual(self.flow().run(True, interval=0), 0)
        self.assertEqual(self.client.call.call_count, calls)

    def test_scaled_service_inspection_stored_once_without_relaxing_adoption(self):
        from deployer.adoption import inspect_project, validate_baseline, adoption_preview
        template = self.structure()['containers'][0]
        projected = {}
        for index, cid in enumerate(('c'*64, 'e'*64), 1):
            row = dict(template, container_id=cid, name='/private-container-' + str(index))
            row['config_files'] = ','.join(row['config_files'])
            row['mounts'] = [{'Type': 'bind', 'Source': '/private/data',
                              'Destination': '/data', 'RW': True}]
            row['ports'] = {'80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8080'}]}
            row['networks'] = ['private-network', None]
            projected[cid] = row
        def docker(*args, **kwargs):
            if args[0] == 'ps':
                return ('\n'.join(projected) + '\n').encode()
            self.assertEqual(args[0], 'inspect')
            return json.dumps(projected[args[-1]]).encode()
        structure = inspect_project(docker, self.client.project)
        self.assertEqual([row['service'] for row in structure['containers']], ['web', 'web'])
        with self.assertRaises(ValueError):
            validate_baseline(structure)
        with self.assertRaises(ValueError):
            adoption_preview(structure)
        flow = self.waiting()
        self.client.call.side_effect = [self.request('approved'), structure]
        self.assertEqual(flow.run(True, interval=0), 0)
        self.assertEqual(json.loads(flow.output.read_text()), structure)
        self.assertEqual(self.events[-1]['containers'], 2)
        for sensitive in ('private-container', '/private/data', 'private-network'):
            self.assertNotIn(sensitive, json.dumps(self.events) + self.path.read_text())
        count = self.client.call.call_count
        self.assertEqual(self.flow().run(True, interval=0), 0)
        self.assertEqual(self.client.call.call_count, count)

    def test_initial_approved_still_polls_before_consuming(self):
        self.client.call.side_effect = [self.request('approved'), self.request('approved'), self.structure()]
        self.assertEqual(self.flow().run(True, interval=0), 0)
        self.assertEqual([c.args[0] for c in self.client.call.call_args_list], ['inspect_request', 'grant_status', 'inspect'])

    def test_denied_expired_revoked_unpaired_and_consumed_stop_without_new_requests(self):
        for status in ('denied', 'expired', 'revoked', 'unpaired', 'consumed'):
            with self.subTest(status=status):
                self.path = Path(self.temp.name) / (status + '.json')
                flow = self.waiting()
                self.client.call.return_value = self.request(status)
                self.assertEqual(flow.run(True, interval=0), 1)
                count = self.client.call.call_count
                self.assertEqual(self.flow().step()['status'], status)
                self.assertEqual(self.client.call.call_count, count)
                self.assertFalse(flow.output.exists())

    def test_poll_transient_failures_recover_but_three_failures_stop_resumably(self):
        flow = self.waiting()
        self.client.call.side_effect = [OSError('PRIVATE'), self.request(), OSError(), self.request('approved'), self.structure()]
        self.assertEqual(flow.run(True, interval=0), 0)
        self.assertNotIn('PRIVATE', json.dumps(self.events))
        self.path = Path(self.temp.name) / 'retry.json'
        self.client.call.side_effect = None
        flow = self.waiting()
        self.client.call.side_effect = [OSError()] * 3
        self.assertEqual(flow.run(True, interval=0), 75)
        self.assertEqual(json.loads(self.path.read_text())['phase'], 'waiting')

    def test_request_response_loss_never_creates_replacement(self):
        self.client.call.side_effect = OSError('lost request response')
        self.assertEqual(self.flow().run(True, interval=0), 1)
        self.assertEqual(self.flow().step()['status'], 'outcome_unknown')
        self.assertEqual(self.client.call.call_count, 1)

    def test_consumed_inspect_response_loss_and_restart_never_repeat(self):
        flow = self.waiting()
        def respond(op, payload):
            if op == 'grant_status':
                return self.request('approved')
            self.assertEqual(op, 'inspect')
            self.assertEqual(json.loads(self.path.read_text())['phase'], 'inspect_intent')
            raise OSError('lost response after once consumption')
        self.client.call.side_effect = respond
        self.assertEqual(flow.run(True, interval=0), 1)
        count = self.client.call.call_count
        self.assertEqual(self.flow().step()['status'], 'outcome_unknown')
        self.assertEqual(self.client.call.call_count, count)

    def test_crash_after_intent_and_before_result_commit_stops_without_replay(self):
        flow = self.waiting()
        for phase in ('request_intent', 'inspect_intent'):
            flow.state['phase'] = phase
            flow.save()
            self.client.call.reset_mock()
            self.assertEqual(self.flow().step()['status'], 'outcome_unknown')
            self.client.call.assert_not_called()

    def test_timeout_has_owned_resume_and_does_not_create_request(self):
        flow = self.flow()
        with patch('scripts.agent.time.monotonic', side_effect=[0, 2]):
            self.assertEqual(flow.run(True, timeout=1), 75)
        self.assertEqual(self.events[-1]['status'], 'timeout')
        self.client.call.assert_not_called()

    def test_endpoint_agent_project_swaps_and_state_permissions_rejected(self):
        self.flow()
        for field, value in (('endpoint', 'https://other.invalid'), ('agent', 'other'), ('project', 'other')):
            original = getattr(self.client, field)
            setattr(self.client, field, value)
            with self.assertRaises(ValueError):
                self.flow()
            setattr(self.client, field, original)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.flow()
        self.path.chmod(0o600)
        self.path.parent.chmod(0o755)
        with self.assertRaises(ValueError):
            self.flow()
        self.path.parent.chmod(0o700)

    def test_symlink_lock_state_output_and_concurrent_owner_rejected(self):
        target = self.path.parent / 'target'
        target.write_text('PRIVATE')
        target.chmod(0o600)
        lock = self.path.with_name('read.json.lock')
        lock.symlink_to(target)
        with self.assertRaises(OSError): self.flow()
        lock.unlink()
        self.path.symlink_to(target)
        with self.assertRaises(ValueError): self.flow()
        self.path.unlink()
        output = self.path.with_name('read.json.structure.json')
        output.symlink_to(target)
        with self.assertRaises(ValueError): self.flow()
        output.unlink()
        flow = self.flow()
        with flow.locked():
            with self.assertRaises(BlockingIOError): self.flow()
        self.client.call.assert_not_called()
        self.assertEqual(target.read_text(), 'PRIVATE')

    def test_altered_binding_and_malformed_structure_never_emit_or_repeat(self):
        flow = self.waiting()
        wrong = self.request('approved'); wrong['request_id'] = 'f'*32
        self.client.call.return_value = wrong
        self.assertEqual(flow.run(True, interval=0), 1)
        self.assertEqual(self.events[-1]['status'], 'invalid_response_or_binding')
        self.assertFalse(any(c.args[0] == 'inspect' for c in self.client.call.call_args_list))
        self.path = Path(self.temp.name) / 'broken.json'
        flow = self.waiting()
        broken = self.structure(); broken['baseline_hash'] = 'f'*64
        self.client.call.side_effect = [self.request('approved'), broken]
        self.assertEqual(flow.run(True, interval=0), 1)
        self.assertEqual(self.flow().step()['status'], 'outcome_unknown')
        self.assertFalse(flow.output.exists())

    def test_approved_request_but_expired_or_revoked_read_stops_without_renewal(self):
        for status in ('not_authorized', 'expired', 'revoked', 'unpaired'):
            self.path = Path(self.temp.name) / ('read-' + status + '.json')
            self.client.call.reset_mock()
            self.client.call.side_effect = [self.request(), self.request('approved'), {'status': status}]
            flow = self.flow()
            self.assertEqual(flow.run(True, interval=0), 1)
            self.assertEqual(self.events[-1]['status'], status)
            self.assertEqual([c.args[0] for c in self.client.call.call_args_list],
                             ['inspect_request', 'grant_status', 'inspect'])
            self.assertFalse(flow.output.exists())
            count = self.client.call.call_count
            self.assertEqual(self.flow().run(True, interval=0), 1)
            self.assertEqual(self.client.call.call_count, count)

    def test_structured_poll_unavailability_retries_only_status(self):
        flow = self.waiting()
        self.client.call.side_effect = [{'status': 'authorization_unavailable'}, {'status': 'busy'},
                                        self.request('approved'), self.structure()]
        self.assertEqual(flow.run(True, interval=0), 0)
        self.assertEqual([c.args[0] for c in self.client.call.call_args_list],
                         ['inspect_request', 'grant_status', 'grant_status', 'grant_status', 'inspect'])

    def test_backoff_stops_without_retry_and_keeps_pending_state(self):
        for code, headers in ((429, {}), (503, {'Retry-After': '120'})):
            self.path = Path(self.temp.name) / ('backoff-' + str(code) + '.json')
            self.client.call.side_effect = None
            flow = self.waiting()
            count = self.client.call.call_count
            self.client.call.side_effect = urllib.error.HTTPError(self.client.endpoint, code, 'PRIVATE', headers, None)
            self.assertEqual(flow.run(True, interval=0), 75)
            self.assertEqual(self.client.call.call_count, count + 1)
            self.assertEqual(self.events[-1]['status'], 'retry_later')
            self.assertEqual(json.loads(self.path.read_text())['phase'], 'waiting')

    def test_deadline_during_approved_poll_does_not_consume(self):
        flow = self.waiting()
        self.client.call.return_value = self.request('approved')
        with patch('scripts.agent.time.monotonic', side_effect=[0, 0, 2]):
            self.assertEqual(flow.run(True, timeout=1, interval=0), 75)
        self.assertEqual(self.events[-1]['status'], 'timeout')
        self.assertEqual(json.loads(self.path.read_text())['phase'], 'waiting')
        self.assertFalse(any(c.args[0] == 'inspect' for c in self.client.call.call_args_list))

    def test_private_structure_persistence_failure_never_repeats_consumed_read(self):
        flow = self.waiting()
        self.client.call.side_effect = [self.request('approved'), self.structure()]
        original = InspectWorkflow.save
        def fail_done():
            if flow.state['phase'] == 'done':
                raise OSError('disk failure after structure write')
            return original(flow)
        with patch.object(flow, 'save', side_effect=fail_done):
            # If result commit fails, disk still says inspect_intent.
            self.assertEqual(flow.run(True, interval=0), 1)
        count = self.client.call.call_count
        self.assertEqual(self.flow().step()['status'], 'outcome_unknown')
        self.assertEqual(self.client.call.call_count, count)
        self.assertEqual(flow.output.stat().st_mode & 0o777, 0o600)

    def test_completed_structure_permission_or_hash_tampering_never_reads_again(self):
        for tamper in ('permission', 'hash'):
            self.path = Path(self.temp.name) / (tamper + '.json')
            self.client.call.side_effect = [self.request(), self.request('approved'), self.structure()]
            flow = self.flow()
            self.assertEqual(flow.run(True, interval=0), 0)
            count = self.client.call.call_count
            if tamper == 'permission':
                flow.output.chmod(0o644)
            else:
                flow.output.write_text('{}')
            self.assertEqual(self.flow().run(True, interval=0), 1)
            self.assertEqual(self.client.call.call_count, count)

    def test_http_denial_stops_and_transient_server_error_can_recover(self):
        flow = self.waiting()
        error = urllib.error.HTTPError(self.client.endpoint, 503, 'PRIVATE', {}, None)
        self.client.call.side_effect = [error, self.request('approved'), self.structure()]
        self.assertEqual(flow.run(True, interval=0), 0)
        self.path = Path(self.temp.name) / 'denial.json'
        self.client.call.side_effect = None
        flow = self.waiting()
        self.client.call.side_effect = urllib.error.HTTPError(self.client.endpoint, 403, 'PRIVATE', {}, None)
        self.assertEqual(flow.run(True, interval=0), 1)
        self.assertEqual(self.events[-1]['status'], 'access_denied_or_unpaired')
        self.assertNotIn('PRIVATE', json.dumps(self.events))


class Dispatch(unittest.TestCase):
    def invoke(self, args):
        argv = ['agent', *args, 'existing-app', '--endpoint', 'https://example.invalid', '--secret-file', '/unused']
        with patch('sys.argv', argv), patch('scripts.agent.private', return_value=b'x'*48), redirect_stdout(io.StringIO()):
            return main()

    def test_inspect_follow_dispatch_requires_state_and_forbids_other_operations(self):
        with patch('scripts.agent.InspectWorkflow') as workflow:
            workflow.return_value.run.return_value = 75
            self.assertEqual(self.invoke(['inspect_request', '--follow', '--state', '/private/state']), 75)
            workflow.return_value.run.assert_called_once_with(True, 3600)
        for args in (['inspect_request', '--follow'], ['inspect', '--follow', '--state', '/private/state'],
                     ['adoption_apply', '--follow', '--state', '/private/state']):
            with self.assertRaises(ValueError): self.invoke(args)

    def test_legacy_single_inspect_request_and_deploy_unchanged(self):
        with patch('scripts.agent.Client.call', return_value={'status': 'pending'}) as call:
            self.assertEqual(self.invoke(['inspect_request']), 0)
            call.assert_called_once_with('inspect_request', {'mode': 'persistent', 'lifetime': 86400})
        with patch('scripts.agent.Workflow') as workflow:
            workflow.return_value.run.return_value = 75
            self.assertEqual(self.invoke(['deploy', '--state', '/private/state', '--follow']), 75)
            workflow.return_value.run.assert_called_once_with(True, 3600)
