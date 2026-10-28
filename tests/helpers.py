"""Test doubles that use real cryptography: a software Passkey, an agent key, a fake runner."""
import hashlib
import http.client
import json
import socket
import tempfile
import threading
import time
import uuid
from http.cookies import SimpleCookie
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fido2 import cbor
from fido2.cose import ES256
from fido2.utils import websafe_encode
from fido2.webauthn import AttestedCredentialData, AuthenticatorData, CollectedClientData
from gateway.agents import CONTEXT, identity
from gateway.core import Gateway
from gateway.passkeys import Passkeys
from gateway.server import HookHandler, OwnerHandler, Server
from gateway.store import Store
from shared.wire import canonical, read_line

HOST = 'deployer.example.ts.net'
ORIGIN = 'https://' + HOST


class Authenticator:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = uuid.uuid4().bytes
        self.counter = 0

    def response(self, ceremony, register=False, origin=ORIGIN):
        options = ceremony['options']['publicKey']
        client = CollectedClientData.create('webauthn.create' if register else 'webauthn.get',
                                            options['challenge'], origin)
        self.counter += 1
        flags = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV
        data = b''
        if register:
            flags |= AuthenticatorData.FLAG.AT
            data = AttestedCredentialData.create(b'\0' * 16, self.id, ES256.from_cryptography_key(self.key.public_key()))
        auth = AuthenticatorData.create(hashlib.sha256(HOST.encode()).digest(), flags, self.counter, data)
        response = {'clientDataJSON': websafe_encode(client)}
        if register:
            response['attestationObject'] = websafe_encode(cbor.encode({'fmt': 'none', 'authData': bytes(auth), 'attStmt': {}}))
        else:
            response.update(authenticatorData=websafe_encode(auth), userHandle=websafe_encode(b'owner'),
                            signature=websafe_encode(self.key.sign(bytes(auth) + client.hash, ec.ECDSA(hashes.SHA256()))))
        return {'id': websafe_encode(self.id), 'rawId': websafe_encode(self.id), 'type': 'public-key', 'response': response}


class Agent:
    def __init__(self, port, host=HOST):
        self.port, self.host = port, host
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.id = identity(self.public)

    def body(self, op, args=None, **override):
        value = {'agent': self.id, 'public_key': self.public, 'audience': self.host, 'op': op, 'args': args or {},
                 'request_id': uuid.uuid4().hex, 'timestamp': int(time.time()), **override}
        return json.dumps(value).encode()

    def send(self, body, signature=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=30)
        connection.request('POST', '/agent', body, {'Host': HOST, 'Content-Type': 'application/json',
                           'X-Agent-Signature': signature or 'ed25519=' + self.key.sign(CONTEXT + body).hex()})
        response = connection.getresponse()
        data = json.loads(response.read())
        connection.close()
        return response.status, data

    def __call__(self, op, **args):
        status, data = self.send(self.body(op, args))
        if status != 200:
            raise AssertionError(f'{op} -> {status} {data}')
        return data['result']

    def error(self, op, **args):
        status, data = self.send(self.body(op, args))
        assert status == 403, (status, data)
        return data['error']


class Browser:
    def __init__(self, port, authenticator):
        self.port, self.authenticator, self.cookie, self.csrf = port, authenticator, None, None
        self.session()

    def request(self, method, path, body=None, origin=ORIGIN):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=30)
        headers = {'Host': HOST}
        if self.cookie:
            headers['Cookie'] = '__Host-cd=' + self.cookie
        if body is not None:
            headers.update({'Content-Type': 'application/json', 'Origin': origin, 'X-CSRF-Token': self.csrf})
        connection.request(method, path, json.dumps(body).encode() if body is not None else None, headers)
        response = connection.getresponse()
        cookie = response.getheader('Set-Cookie')
        if cookie:
            self.cookie = SimpleCookie(cookie)['__Host-cd'].value
        raw = response.read()
        connection.close()
        return response.status, (json.loads(raw) if response.getheader('Content-Type') == 'application/json' else raw)

    def session(self):
        status, data = self.request('GET', '/api/session')
        self.csrf = data['csrf']
        return data

    def passkey(self, action, target='', token=None, register=False):
        status, start = self.request('POST', '/api/begin', {'action': action, 'target': target, **({'token': token} if token else {})})
        assert status == 200, start
        status, result = self.request('POST', '/api/finish', {'ceremony_id': start['ceremony_id'],
                                      'response': self.authenticator.response(start, register=register or action == 'enroll')})
        return status, result


class FakeRunner:
    """Unix-socket runner that records calls and returns canned results."""

    def __init__(self, path):
        self.path, self.calls = path, []
        self.identity = {'project': 'app', 'working_dir': '/volume1/docker/app',
                         'config_files': ['/volume1/docker/app/compose.yaml']}
        self.results = {}
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(8)
        threading.Thread(target=self.loop, daemon=True).start()

    def answer(self, op, args):
        if op in self.results:
            result = self.results[op]
            return result(args) if callable(result) else result
        if op == 'projects':
            return {'root': '/volume1/docker', 'projects': [{
                'project': 'app', 'identity': self.identity, 'manageable': True, 'reason': None,
                'services': [{'service': 'web', 'name': 'app-web-1', 'image': 'ghcr.io/owner/app:latest',
                              'state': 'running', 'health': None,
                              'ports': [{'host_ip': '0.0.0.0', 'host_port': 8096, 'container': '80/tcp'}]}]}]}
        if op == 'plan':
            return {'identity': args['identity'], 'new': args.get('new', False), 'base': {'compose': 'a', 'env': None},
                    'compose': args.get('compose_text') or 'services: {}\n', 'env_set': args.get('env_set') or {},
                    'env_unset': args.get('env_unset') or [], 'diff': '-old\n+new\n',
                    'env': {'added': sorted(args.get('env_set') or {}), 'removed': [], 'changed': []},
                    'expect': None, 'highlights': ['web: port 0.0.0.0:8096 -> 80/tcp'], 'services': ['web']}
        if op == 'read':
            return {'compose': 'services: {}\n', 'env_keys': ['TOKEN'], 'compose_sha': 'a', 'env_sha': 'b',
                    'config_files': args['identity']['config_files']}
        if op == 'logs':
            return {'logs': {'app-web-1': 'hello\n'}}
        return {'status': 'success'}

    def loop(self):
        while True:
            connection, _ = self.sock.accept()
            with connection:
                request = json.loads(read_line(connection))
                self.calls.append((request['op'], request['args']))
                try:
                    reply = {'ok': True, 'result': self.answer(request['op'], request['args'])}
                except Exception as exc:
                    reply = {'ok': False, 'error': getattr(exc, 'code', 'failed'), 'detail': getattr(exc, 'detail', None)}
                connection.sendall(canonical(reply).encode() + b'\n')

    def ops(self):
        return [op for op, _ in self.calls]


class Stack:
    """A gateway with HTTP servers on ephemeral ports and a given runner socket."""

    def __init__(self, runner_socket=None, fake=True):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp')  # short AF_UNIX paths
        root = Path(self.temp.name)
        self.socket = runner_socket or str(root / 'runner.sock')
        self.runner = FakeRunner(self.socket) if fake else None
        self.store = Store(root / 'gateway.sqlite')
        self.serve_configs = []
        self.gateway = Gateway(self.store, self.socket, ORIGIN, HOST, funnel=True, apply_serve=self.serve_configs.append)
        passkeys = Passkeys(self.store, HOST, ORIGIN)
        self.owner = Server(('127.0.0.1', 0), OwnerHandler, self.gateway, passkeys)
        self.hooks = Server(('127.0.0.1', 0), HookHandler, self.gateway, passkeys)
        for server in (self.owner, self.hooks):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self.port, self.hook_port = self.owner.server_address[1], self.hooks.server_address[1]
        self.authenticator = Authenticator()
        self.browser = Browser(self.port, self.authenticator)
        self.agent = Agent(self.port)

    def enroll(self):
        status, result = self.browser.passkey('enroll', token=self.store.enrollment_code())
        assert status == 200, result

    def pair(self, agent=None):
        agent = agent or self.agent
        pending = agent('pair', label='openclaw')
        token = pending['approval_url'].rsplit('/', 1)[1]
        status, result = self.browser.passkey('pair', token)
        assert status == 200, result
        return pending

    def approve(self, request):
        status, result = self.browser.passkey('approve', request['id'])
        assert status == 200, result
        return self.agent('request_status', id=request['id'])

    def wait_job(self, job, agent=None, timeout=600):
        agent = agent or self.agent
        deadline = time.time() + timeout
        while True:
            state = agent('job', id=job)
            if state['status'] not in ('queued', 'running') or time.time() > deadline:
                return state
            time.sleep(0.2)

    def close(self):
        for server in (self.owner, self.hooks):
            server.shutdown()
            server.server_close()
        for thread in self.gateway.threads:
            thread.join(timeout=60)
        self.temp.cleanup()

