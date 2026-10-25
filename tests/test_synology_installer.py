import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from installer.configure import configure, domain, status
from installer.enrollment import first_code
from installer.initialize import initialize
from authorization.store import Store
from scripts.build_synology_installer import build


class DomainConfiguration(unittest.TestCase):
    def test_requires_authenticated_device_and_https_and_uses_self_not_peer(self):
        self.assertIsNone(domain({'BackendState': 'NeedsLogin'}))
        value = {'BackendState': 'Running', 'Self': {'DNSName': 'deployer-1.tail123.ts.net.'},
                 'CertDomains': ['deployer-1.tail123.ts.net'], 'Peer': {'x': {'DNSName': 'wrong.tail123.ts.net'}}}
        self.assertEqual(domain(value), 'deployer-1.tail123.ts.net')
        for invalid in ('evil.invalid', '../evil.tail123.ts.net', 'bad/path.tail123.ts.net'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                domain({**value, 'Self': {'DNSName': invalid}})
        with self.assertRaises(ValueError):
            domain({**value, 'CertDomains': []})

    @unittest.skipUnless(os.geteuid() == 0, 'root-owned configuration checks require Linux container root')
    def test_atomic_publication_preserves_existing_identity_and_refuses_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            configure(path, 'deployer.tail123.ts.net')
            contents = path.read_bytes()
            configure(path, 'deployer.tail123.ts.net')
            self.assertEqual(path.read_bytes(), contents)
            with self.assertRaises(ValueError):
                configure(path, 'renamed.tail123.ts.net')
            self.assertEqual(path.read_bytes(), contents)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_status_uses_unix_localapi_without_network_listener(self):
        import http.server
        import socketserver
        import threading
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_GET(self):
                self.server.observed = self.path
                data = b'{"BackendState":"NeedsLogin"}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'tailscaled.sock')
            with socketserver.UnixStreamServer(path, Handler) as server:
                thread = threading.Thread(target=server.handle_request)
                thread.start()
                self.assertEqual(status(path)['BackendState'], 'NeedsLogin')
                thread.join()
                self.assertEqual(server.observed, '/localapi/v0/status')


@unittest.skipUnless(os.geteuid() == 0, 'UID/GID isolation requires Linux container root')
class Initialization(unittest.TestCase):
    def test_accepts_only_the_expected_empty_docker_created_bind_skeleton(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('config/service-keys/approval-service', 'state/approval', 'runtime/approval', 'apps/config'):
                (root / name).mkdir(parents=True, mode=0o755)
            initialize(root)
            self.assertEqual((root / 'state/approval').stat().st_uid, 10004)
            self.assertEqual((root / 'config/service-keys/approval-service/key').stat().st_mode & 0o777, 0o640)

    def test_repeated_start_preserves_keys_modified_policy_identity_and_media(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize(root)
            keys = {p: p.read_bytes() for p in root.glob('config/**/*') if p.name == 'key' or p.suffix == '.key'}
            policy = root / 'config/provisioning/policy.json'
            value = json.loads(policy.read_text())
            self.assertFalse(value['enabled'])
            from deployer.schema import policy as validate
            validate(value)
            value['max_projects'] = 3
            policy.write_text(json.dumps(value))
            identity = root / 'state/approval/identity-sentinel'
            identity.write_bytes(b'keep identity')
            media = root / 'apps/downloads/media-sentinel'
            media.write_bytes(b'keep media')
            initialize(root)
            self.assertEqual({p: p.read_bytes() for p in keys}, keys)
            self.assertEqual(json.loads(policy.read_text())['max_projects'], 3)
            self.assertEqual(identity.read_bytes(), b'keep identity')
            self.assertEqual(media.read_bytes(), b'keep media')
            self.assertEqual((root / 'state/approval').stat().st_uid, 10004)
            self.assertEqual((root / 'state/approval').stat().st_mode & 0o777, 0o700)

    def test_unmarked_old_data_symlinks_and_insecure_keys_are_not_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'state').mkdir()
            (root / 'state/existing-database').write_bytes(b'old identity')
            with self.assertRaises(ValueError):
                initialize(root)
            self.assertFalse((root / 'installation.json').exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize(root)
            key = root / 'config/agent-keys/openclaw.key'
            contents = key.read_bytes()
            key.chmod(0o666)
            with self.assertRaises(ValueError):
                initialize(root)
            self.assertEqual(key.read_bytes(), contents)
            key.unlink()
            key.symlink_to('/not-a-real-key')
            with self.assertRaises(ValueError):
                initialize(root)
            self.assertTrue(key.is_symlink())


class FirstEnrollment(unittest.TestCase):
    def test_codes_are_rotated_and_never_minted_after_first_passkey(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'auth.sqlite', 'https://deployer.tail123.ts.net')
            one, two = first_code(store), first_code(store)
            self.assertNotEqual(one, two)
            with store.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM bootstrap').fetchone()[0], 1)
                db.execute('INSERT INTO credentials VALUES (?,?,?,?,?)', (b'credential', 'owner', b'data', 0, 1))
            self.assertIsNone(first_code(store))

    def test_bundle_contains_only_compose_and_instructions_in_one_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'installer.zip'
            build(output)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()), {'compose-deployer/compose.yaml', 'compose-deployer/README.md'})


if __name__ == '__main__':
    unittest.main()
