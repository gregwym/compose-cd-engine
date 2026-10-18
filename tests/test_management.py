import hashlib
import hmac
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
from management import protocol, broker, gateway
from test_cd import runner


def message(action='status', **extra):
    return dict(project='test', action=action, request_id='a' * 32, timestamp=int(time.time()), **extra)


def config():
    return {'id': 'test', 'services': ['app'], 'observe': False, 'rollback': False,
            'snapshot_paths': [], 'require_readiness': True,
            'management': {'socket': '/run/compose-cd-management/test.sock',
                           'verifier_socket': '/run/compose-cd/test-verify.sock',
                           'actions': sorted(protocol.ACTIONS)}}


class Authentication(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / 'nonces.sqlite')
        self.secret = b's' * 48

    def tearDown(self):
        self.tmp.cleanup()

    def auth(self, value, signature=None, now=None):
        raw = json.dumps(value).encode()
        sig = 'sha256=' + hmac.new(self.secret, raw, hashlib.sha256).hexdigest()
        return protocol.authenticate(raw, sig if signature is None else signature, self.secret, self.db, now)

    def test_valid_request_then_durable_replay_denied(self):
        value = message()
        self.assertEqual(self.auth(value), value)
        with self.assertRaises(ValueError):
            self.auth(value)

    def test_bad_signature_expiry_and_future_rejected(self):
        for change in (-61, 61):
            value = message()
            value['timestamp'] += change
            with self.assertRaises(ValueError):
                self.auth(value)
        with self.assertRaises(ValueError):
            self.auth(message(), signature='invalid')

    def test_unknown_fields_commands_and_paths_rejected(self):
        for extra in ({'command': 'id'}, {'image': 'attacker'}, {'services': ['other']}, {'mount': '/'}):
            with self.assertRaises(ValueError):
                self.auth(message(**extra))
        for action in ('exec', 'pull', 'compose', 'prune', 'remove', 'shell'):
            with self.assertRaises(ValueError):
                self.auth(message(action))
        value = message()
        value['project'] = '../other'
        with self.assertRaises(ValueError):
            self.auth(value)

    def test_nonce_reservation_is_atomic(self):
        value = message()
        outcomes = []
        def attempt():
            try:
                self.auth(value)
                outcomes.append('ok')
            except ValueError:
                outcomes.append('denied')
        threads = [threading.Thread(target=attempt) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ['denied', 'denied', 'denied', 'ok'])

    def test_body_size_bounded(self):
        with self.assertRaises(ValueError):
            protocol.request(b' ' * (protocol.MAX_REQUEST + 1))


class PrivilegedBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        self.patch = patch.object(runner, 'STATE_DIR', self.state)
        self.patch.start()
        self.cfg = config()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_cross_project_action_and_extra_fields_rejected_before_docker(self):
        self.cfg['management']['actions'] = ['status']
        values = [message('restart'), message(command='id')]
        other = message()
        other['project'] = 'other'
        values.append(other)
        with patch.object(runner, 'command', side_effect=AssertionError('Docker touched')):
            for value in values:
                with self.assertRaises(ValueError):
                    broker.dispatch(self.cfg, value, runner)

    def test_restart_uses_fixed_services_and_requires_readiness(self):
        with patch.object(runner, 'command') as command, patch.object(runner, 'wait_healthy') as health:
            result = broker.dispatch(self.cfg, message('restart'), runner)
            command.assert_called_once_with(self.cfg, 'restart', '--no-deps', 'app', timeout=120)
            health.assert_called_once_with(self.cfg)
            self.assertEqual(result['status'], 'success')
            with self.assertRaises(ValueError):
                broker.dispatch(self.cfg, message('restart'), runner)
            self.assertEqual(command.call_count, 1)

    def test_observe_mode_cannot_start_or_restart(self):
        self.cfg['observe'] = True
        with patch.object(runner, 'command', side_effect=AssertionError('Docker touched')):
            with self.assertRaises(ValueError):
                broker.dispatch(self.cfg, message('start'), runner)

    def test_update_only_wakes_verifier(self):
        with patch.object(broker.socket, 'socket') as sock, patch.object(runner, 'command', side_effect=AssertionError('Docker touched')):
            result = broker.dispatch(self.cfg, message('update'), runner)
            sock.return_value.__enter__.return_value.sendto.assert_called_once_with(b'check', self.cfg['management']['verifier_socket'])
            self.assertEqual(result['status'], 'accepted')

    def test_failed_partial_restart_records_failure_without_stderr(self):
        with patch.object(runner, 'command'), patch.object(runner, 'wait_healthy', side_effect=RuntimeError('SECRET /private/path')):
            with self.assertRaises(RuntimeError):
                broker.dispatch(self.cfg, message('restart'), runner)
        audit = (self.state / 'management-audit.jsonl').read_text()
        self.assertNotIn('SECRET', audit)
        self.assertNotIn('/private/path', audit)
        self.assertEqual(json.loads(audit)['status'], 'failed')

    def test_nas_policy_rejects_snapshots_and_implicit_rollback(self):
        for key, value in [('snapshot_paths', ['/media']), ('rollback', True), ('require_readiness', False)]:
            cfg = config()
            cfg[key] = value
            with self.assertRaises(ValueError):
                broker.validate_policy(cfg)

    def test_status_does_not_expose_container_metadata(self):
        completed = Mock(stdout=b'container\n')
        with patch.object(runner, 'command', return_value=completed), patch.object(broker.subprocess, 'run', return_value=Mock(stdout=b'running healthy')):
            result = broker.dispatch(self.cfg, message(), runner)
        self.assertEqual(result['services'], {'app': {'state': 'running', 'health': 'healthy'}})
        self.assertNotIn('image', json.dumps(result))

    def test_busy_deployment_rejects_management_mutation(self):
        import fcntl
        with (self.state / 'global.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with patch.object(runner, 'command', side_effect=AssertionError('Docker touched')):
                with self.assertRaises(BlockingIOError):
                    broker.dispatch(self.cfg, message('stop'), runner)

    def test_logs_only_return_counts_no_free_form_text(self):
        import subprocess, sys
        raw = '{"level":"error","message":"SECRET token=abc"}\nprivate path /volume1/photos\n'
        process = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdout.write(' + repr(raw) + ')'], stdout=subprocess.PIPE)
        with patch.object(runner, 'log_process', return_value=process):
            result = broker.log_summary(self.cfg, runner)
        self.assertEqual(result['summary']['app']['error'], 1)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('/volume1', json.dumps(result))


class WireProtocol(unittest.TestCase):
    def test_fragmented_and_oversized_frames(self):
        a, b = socket.socketpair()
        with a, b:
            b.sendall(b'{"ok":true}\n')
            self.assertEqual(protocol.read_frame(a, 64), b'{"ok":true}')
        a, b = socket.socketpair()
        with a, b:
            b.sendall(b'a' * 65)
            with self.assertRaises(ValueError):
                protocol.read_frame(a, 64)


class RecoverySemantics(unittest.TestCase):
    def fail_deploy(self, rollback, restore_failure=False, snapshots=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = {'id': 'test', 'services': ['app'], 'observe': False, 'snapshot_paths': ['/data'] if snapshots else [], 'files': ['compose.yml'], 'rollback': rollback}
            candidate = {'order': [1, 1], 'source_sha': 'a' * 40, 'mode': 'deploy', 'images': {'app': 'repo@sha256:' + 'b' * 64}}
            old = {'app': {'image_id': 'old', 'image_ref': 'old', 'container': 'old'}}
            with patch.object(runner, 'STATE_DIR', root), patch.object(runner, 'candidate', return_value=candidate), patch.object(runner, 'current_containers', return_value=old), patch.object(runner, 'preflight_space'), patch.object(runner.subprocess, 'run', return_value=Mock(stdout=b'new')), patch.object(runner, 'command', side_effect=RuntimeError('partial failure')), patch.object(runner, 'restore', side_effect=RuntimeError('restore failure') if restore_failure else None) as restore:
                with self.assertRaises(RuntimeError):
                    runner.deploy(cfg)
                receipt = json.loads((root / 'test.receipt').read_text())
                if not rollback:
                    restore.assert_not_called()
                return receipt

    def test_disabled_rollback_never_claims_recovery(self):
        self.assertEqual(self.fail_deploy(False)['status'], 'recovery_required')

    def test_failed_rollback_is_reported(self):
        self.assertEqual(self.fail_deploy(True, True)['status'], 'rollback_failed')

    def test_partial_stop_failure_is_not_reported_as_recovered(self):
        self.assertEqual(self.fail_deploy(False, snapshots=True)['status'], 'recovery_required')

    def test_liveness_without_probe_rejected(self):
        cfg = {'services': ['app'], 'health_timeout': 10, 'require_readiness': True}
        with patch.object(runner, 'command', return_value=Mock(stdout=b'id')), patch.object(runner.subprocess, 'run', return_value=Mock(stdout=b'running none')), patch.object(runner.time, 'monotonic', side_effect=[0, 1, 20]), patch.object(runner.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'readiness probe required'):
                runner.wait_healthy(cfg)

class HTTPBoundary(unittest.TestCase):
    def test_signed_http_to_unix_roundtrip_and_replay(self):
        import http.client
        from receiver.receiver import BoundedHTTPServer
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sockpath = str(root / 'broker.sock')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix:
                unix.bind(sockpath)
                unix.listen(1)
                def receive():
                    connection, _ = unix.accept()
                    with connection:
                        value = protocol.request(protocol.read_frame(connection, protocol.MAX_REQUEST))
                        connection.sendall(json.dumps({'status': 'success', 'request_id': value['request_id']}).encode() + b'\n')
                listener = threading.Thread(target=receive)
                listener.start()
                class Handler(gateway.Gateway):
                    pass
                Handler.secret = b's' * 48
                Handler.cfg = {'projects': {'test': {'socket': sockpath, 'actions': ['status']}}, 'nonce_db': str(root / 'nonce.sqlite')}
                httpd = BoundedHTTPServer(('127.0.0.1', 0), Handler)
                server = threading.Thread(target=httpd.serve_forever)
                server.start()
                try:
                    def post(value, signature=None):
                        raw = json.dumps(value).encode()
                        sig = 'sha256=' + hmac.new(Handler.secret, raw, hashlib.sha256).hexdigest()
                        client = http.client.HTTPConnection('127.0.0.1', httpd.server_port, timeout=5)
                        client.request('POST', '/v1/manage', body=raw, headers={'X-Management-Signature': signature or sig})
                        response = client.getresponse()
                        result = (response.status, json.loads(response.read()))
                        client.close()
                        return result
                    value = message()
                    self.assertEqual(post(value)[0], 200)
                    self.assertEqual(post(value), (403, {'status': 'denied'}))
                    self.assertEqual(post(message('exec'))[0], 403)
                    self.assertEqual(post(message(), 'invalid')[0], 403)
                    self.assertEqual(post(message('stop'))[0], 403)
                finally:
                    httpd.shutdown()
                    httpd.server_close()
                    server.join(timeout=5)
                    listener.join(timeout=5)

class RecoveryLatch(unittest.TestCase):
    def test_new_candidate_cannot_bypass_nas_recovery_latch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = config()
            candidate = {'order': [20, 1], 'mode': 'deploy'}
            (root / 'test.recovery-required.json').write_text('{}')
            with patch.object(runner, 'STATE_DIR', root), patch.object(runner, 'candidate', return_value=candidate), patch.object(runner, 'current_containers', side_effect=AssertionError('Docker touched')):
                with self.assertRaisesRegex(RuntimeError, 'administrator recovery'):
                    runner.deploy(cfg)
                with self.assertRaisesRegex(ValueError, 'administrator recovery'):
                    broker.dispatch(cfg, message('start'), runner)
