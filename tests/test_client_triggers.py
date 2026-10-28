import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from client import cdctl
from gateway import agents, triggers
from shared.wire import Denied

CONFIG = {'repository': 'owner/app', 'workflow': '.github/workflows/docker.yml', 'branch': 'main',
          'image': 'ghcr.io/owner/app', 'platform': 'linux/amd64', 'repository_id': 42}


class Client(unittest.TestCase):
    def test_signed_request_verifies_at_gateway(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.object(cdctl, 'HOME', Path(home)):
                cdctl.init(mock.Mock(endpoint='https://deployer.example.ts.net'))
                client = cdctl.Client(Path(home))
            sent = {}

            class Response:
                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    return False

                def read(self):
                    return b'{"ok": true, "result": {"status": "ok"}}'

            def urlopen(request, timeout):
                sent['body'], sent['signature'] = request.data, request.headers['X-agent-signature']
                return Response()
            with mock.patch('urllib.request.urlopen', urlopen):
                self.assertEqual(client.call('restart', project='app', services=['web']), {'status': 'ok'})
            value = agents.verify(sent['body'], sent['signature'], 'deployer.example.ts.net')
            self.assertEqual((value['op'], value['args']), ('restart', {'project': 'app', 'services': ['web']}))
            self.assertEqual(oct(Path(home, 'key.pem').stat().st_mode & 0o777), '0o600')


class Triggers(unittest.TestCase):
    def github(self, path):
        return {'owner/app': {'id': 42}, 'owner/app/branches/main': {'commit': {'sha': 'c' * 40}}}[path]

    def test_latest_verifies_signature_and_revision(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        with mock.patch.object(triggers, 'github', self.github), \
                mock.patch('shared.registry.auth', return_value='t'), \
                mock.patch('shared.registry.manifest', return_value=({}, 'sha256:' + 'i' * 64)), \
                mock.patch('shared.registry.resolve', return_value=('sha256:' + 'p' * 64, {})), \
                mock.patch('shared.registry.labels', return_value={'org.opencontainers.image.revision': 'c' * 40}), \
                mock.patch('subprocess.run', run):
            commit, image = triggers.latest(CONFIG)
        self.assertEqual(image, 'ghcr.io/owner/app@sha256:' + 'p' * 64)
        self.assertIn('https://github.com/owner/app/.github/workflows/docker.yml@refs/heads/main', calls[0])
        self.assertEqual(calls[0][-1], 'ghcr.io/owner/app@sha256:' + 'i' * 64)

    def test_cosign_timeout_is_a_refusal(self):
        def run(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 180)
        with mock.patch.object(triggers, 'github', self.github), \
                mock.patch('shared.registry.auth', return_value='t'), \
                mock.patch('shared.registry.manifest', return_value=({}, 'sha256:' + 'i' * 64)), \
                mock.patch('subprocess.run', run):
            with self.assertRaises(Denied) as caught:
                triggers.latest(CONFIG)
        self.assertEqual(caught.exception.code, 'signature_timeout')

    def test_unsigned_or_wrong_revision_is_refused(self):
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, b'', b'no signatures')
        with mock.patch.object(triggers, 'github', self.github), \
                mock.patch('shared.registry.auth', return_value='t'), \
                mock.patch('shared.registry.manifest', return_value=({}, 'sha256:' + 'i' * 64)), \
                mock.patch('subprocess.run', run):
            with self.assertRaises(Denied) as caught:
                triggers.latest(CONFIG)
            self.assertEqual(caught.exception.code, 'signature_invalid')
        ok = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, b'', b'')
        with mock.patch.object(triggers, 'github', self.github), \
                mock.patch('shared.registry.auth', return_value='t'), \
                mock.patch('shared.registry.manifest', return_value=({}, 'sha256:' + 'i' * 64)), \
                mock.patch('shared.registry.resolve', return_value=('sha256:' + 'p' * 64, {})), \
                mock.patch('shared.registry.labels', return_value={'org.opencontainers.image.revision': 'd' * 40}), \
                mock.patch('subprocess.run', ok):
            with self.assertRaises(Denied) as caught:
                triggers.latest(CONFIG)
            self.assertEqual(caught.exception.code, 'revision_mismatch')

    def test_renamed_repository_is_refused(self):
        with mock.patch.object(triggers, 'github', return_value={'id': 7}):
            with self.assertRaises(Denied) as caught:
                triggers.latest(CONFIG)
        self.assertEqual(caught.exception.code, 'repository_changed')

    def test_validate_shapes(self):
        with mock.patch.object(triggers, 'github', return_value={'id': 42}):
            config = triggers.validate({k: v for k, v in CONFIG.items() if k not in ('platform', 'repository_id')})
        self.assertEqual((config['platform'], config['repository_id']), ('linux/amd64', 42))
        for bad in ({'workflow': 'x.yml'}, {'image': 'quay.io/x/y'}, {'branch': '../x'}, {'extra': 1}):
            with self.assertRaises(Denied):
                triggers.validate({**CONFIG, **bad})

    def test_webhook_filters_events(self):
        import hashlib
        import hmac
        body = json.dumps({'action': 'completed', 'repository': {'id': 42}, 'workflow_run': {
            'conclusion': 'success', 'head_branch': 'dev', 'path': CONFIG['workflow']}}).encode()
        signature = 'sha256=' + hmac.new(b's', body, hashlib.sha256).hexdigest()
        self.assertFalse(triggers.webhook(body, signature, 'workflow_run', 's', CONFIG))
        self.assertFalse(triggers.webhook(body, signature, 'ping', 's', CONFIG))
        with self.assertRaises(Denied):
            triggers.webhook(body, signature, 'workflow_run', 'other', CONFIG)


if __name__ == '__main__':
    unittest.main()
