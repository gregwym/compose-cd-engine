"""Deterministic same-socket checks after runner lock acquisition."""
import json
import socket
import threading
import time
from unittest.mock import patch
from test_reusable import Grants, Boundaries
from runner.server import Runner, session
from shared import wire


class ExecHandshake(Grants):
    def setUp(self):
        super().setUp()
        self.root = __import__('pathlib').Path(self.temp.name).resolve()
        wd = self.root / 'app'
        wd.mkdir()
        (wd / 'compose.yaml').write_text('services: {}')
        self.identity = {'project': 'app', 'working_dir': str(wd), 'config_files': [str(wd / 'compose.yaml')]}
        self.runner = Runner(self.root)
        self.manage = self.grant('manage', boundary={'mounts': [], 'networks': []})
        self.elevated = self.grant('elevated', 60, {'manage_grant': self.manage['id']})
        self.path = '/tmp/cd-exec-' + __import__('uuid').uuid4().hex[:16] + '.sock'
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        self.listener.listen()
        self.gateway.runner_socket = self.path
        self.target = {'Id': 'a' * 64, 'Config': {'Labels': {
            'com.docker.compose.project': 'app', 'com.docker.compose.project.working_dir': str(wd),
            'com.docker.compose.project.config_files': str(wd / 'compose.yaml')}}, 'HostConfig': {}}
        self.args = {'identity': self.identity, 'boundary': self.manage['boundary'], 'container': 'a' * 64,
                     'argv': ['id'], 'timeout': 30, 'expires': self.elevated['expires']}

    def tearDown(self):
        self.listener.close()
        __import__('os').unlink(self.path)
        super().tearDown()

    def test_revoke_while_waiting_for_runner_lock(self):
        entered = threading.Event()
        lock = threading.Lock()
        lock.acquire()
        class ObservedLock:
            def __enter__(self):
                entered.set()
                lock.acquire()
            def __exit__(self, *args):
                lock.release()
        self.runner.lock = ObservedLock()
        outcome = []
        def serve():
            connection, _ = self.listener.accept()
            session(self.runner, connection)
        def client():
            try:
                outcome.append(self.gateway.runner_exec('a', self.manage, self.elevated, self.args))
            except wire.Denied as exc:
                outcome.append(exc.code)
        with patch.object(self.runner, 'check_boundary'), patch('runner.compose.observed_identity', return_value=self.identity),              patch('runner.diagnostics.inspect_project', return_value=[self.target]), patch('runner.execution.run') as execute:
            server = threading.Thread(target=serve)
            caller = threading.Thread(target=client)
            server.start()
            caller.start()
            self.assertTrue(entered.wait(3), 'runner did not enter lock wait')
            with self.store.db() as db:
                db.execute("UPDATE grants SET status='revoked' WHERE id=?", (self.elevated['id'],))
            lock.release()
            caller.join(3)
            server.join(3)
            self.assertFalse(caller.is_alive())
            self.assertFalse(server.is_alive())
            execute.assert_not_called()
        self.assertEqual(outcome, ['not_authorized'])

    def test_valid_handshake_and_wrong_challenge(self):
        with patch.object(self.runner, 'check_boundary'), patch('runner.compose.observed_identity', return_value=self.identity),              patch('runner.diagnostics.inspect_project', return_value=[self.target]),              patch('runner.execution.run', return_value={'status': 'success', 'output': ''}) as execute:
            def serve():
                connection, _ = self.listener.accept()
                session(self.runner, connection)
            server = threading.Thread(target=serve)
            server.start()
            result = self.gateway.runner_exec('a', self.manage, self.elevated, self.args)
            server.join(3)
            self.assertEqual(result['status'], 'success')
            execute.assert_called_once()
            execute.reset_mock()
            server = threading.Thread(target=serve)
            server.start()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                sock.connect(self.path)
                sock.sendall(wire.canonical({'op': 'exec', 'args': self.args}).encode() + b'\n')
                challenge = json.loads(wire.read_line(sock))
                self.assertEqual(challenge['phase'], 'authorize_exec')
                sock.sendall(wire.canonical({**challenge, 'challenge': 'wrong', 'allow': True}).encode() + b'\n')
                reply = json.loads(wire.read_line(sock))
            server.join(3)
            self.assertEqual(reply['error'], 'not_authorized')
            execute.assert_not_called()


# Reuse fixtures only, not inherited test cases.
for _name in list(vars(Grants)):
    if _name.startswith('test_'):
        setattr(ExecHandshake, _name, None)
del Grants, Boundaries
