import os
import tempfile
import unittest
from pathlib import Path
from runner import files, policy
from shared.registry import repository
from shared.wire import Denied


class EnvEdits(unittest.TestCase):
    def test_set_unset_keeps_comments_and_order(self):
        before = b'# app settings\nA=1\nexport B=2\nC="three"\n'
        after = files.edit_env(before, {'B': 'two', 'D': 'x y'}, ['C'])
        self.assertEqual(after, b"# app settings\nA=1\nB=two\nD='x y'\n")
        self.assertEqual(files.env_summary(before, after), {'added': ['D'], 'removed': ['C'], 'changed': ['B']})
        self.assertEqual(files.env_keys(after), ['A', 'B', 'D'])

    def test_rejects_unsafe_keys_and_values(self):
        for change in ({'1BAD': 'x'}, {'A': 'line\nbreak'}, {'A': "it's"}):
            with self.assertRaises(Denied):
                files.edit_env(b'', change)
        with self.assertRaises(Denied):
            files.edit_env(b'', {'A': '1'}, ['A'])

    def test_duplicate_keys_collapse(self):
        self.assertEqual(files.edit_env(b'A=1\nA=2\n', {'A': '3'}), b'A=3\n')


class ImageEdits(unittest.TestCase):
    COMPOSE = b'services:\n  web:\n    image: "nginx:1.25"  # pinned\n  db:\n    image: postgres:16\n'

    def test_literal_line(self):
        data, env = files.image_edit(self.COMPOSE, 'nginx:1.25', 'nginx@sha256:' + 'a' * 64)
        self.assertIn(b'image: "nginx@sha256:' + b'a' * 64 + b'"  # pinned', data)
        self.assertIn(b'image: postgres:16', data)
        self.assertEqual(env, {})

    def test_variable_goes_to_env(self):
        data, env = files.image_edit(b'services:\n  web:\n    image: ${WEB_IMAGE:-nginx}\n', '${WEB_IMAGE:-nginx}', 'x@sha256:1')
        self.assertEqual(env, {'WEB_IMAGE': 'x@sha256:1'})

    def test_ambiguous_line_refused(self):
        with self.assertRaises(Denied):
            files.image_edit(b'a:\n  image: x\nb:\n  image: x\n', 'x', 'y')


class InPlaceWrites(unittest.TestCase):
    def test_keeps_inode_and_mode_and_backs_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'compose.yaml'
            path.write_text('one\n')
            os.chmod(path, 0o640)
            inode = path.stat().st_ino
            names = [files.backup(path, path.read_bytes()) for _ in range(7)]
            files.write_in_place(path, b'two\n')
            self.assertEqual((path.read_text(), path.stat().st_ino, path.stat().st_mode & 0o777), ('two\n', inode, 0o640))
            backups = sorted(Path(tmp).glob('compose.yaml.bak-*'))
            self.assertEqual(len(backups), files.KEEP_BACKUPS)
            self.assertEqual(backups[-1].name, names[-1])
            self.assertEqual(backups[-1].read_text(), 'one\n')

    def test_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / 'compose.yaml'
            link.symlink_to('/etc/hostname')
            with self.assertRaises(Denied):
                files.read(link)
            with self.assertRaises(OSError):
                files.write_in_place(link, b'x')


def service(**fields):
    return {'services': {'web': fields}}


class HardPolicy(unittest.TestCase):
    def violations(self, **fields):
        return policy.violations(service(**fields), '/volume1/docker/deployer')

    def test_forbidden(self):
        bind = lambda source: [{'type': 'bind', 'source': source, 'target': '/x'}]
        for fields in ({'privileged': True}, {'cap_add': ['SYS_ADMIN']}, {'pid': 'host'},
                       {'security_opt': ['seccomp:unconfined']}, {'build': {'context': '.'}},
                       {'volumes': bind('/var/run/docker.sock')}, {'volumes': bind('/')},
                       {'volumes': bind('/etc')}, {'volumes': bind('/volume1')},
                       {'volumes': bind('/volume1/@appstore/x')}, {'volumes': bind('/volume1/docker/deployer/state')},
                       {'volumes': bind('/srv/../etc/shadow')}):
            self.assertTrue(self.violations(**fields), fields)

    def test_allowed(self):
        self.assertEqual(self.violations(network_mode='host', cap_add=['NET_ADMIN'],
                                         volumes=[{'type': 'bind', 'source': '/volume1/media', 'target': '/media'},
                                                  {'type': 'volume', 'source': 'data', 'target': '/data'}]), [])

    def test_highlights_only_what_is_new(self):
        before = service(ports=[{'published': '80', 'target': 80}])
        after = service(ports=[{'published': '80', 'target': 80}, {'published': '443', 'target': 443}],
                        network_mode='host', devices=[{'source': '/dev/dri', 'target': '/dev/dri'}],
                        volumes=[{'type': 'bind', 'source': '/volume1/media', 'target': '/m', 'read_only': True},
                                 {'type': 'bind', 'source': '/volume1/docker/app/data', 'target': '/d'}])
        self.assertEqual(policy.new_highlights(before, after, '/volume1/docker/app'), [
            'web: device /dev/dri:/dev/dri', 'web: host network',
            'web: host path /volume1/media -> /m (read-only)', 'web: port 0.0.0.0:443 -> 443/tcp'])


class Repositories(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(repository('nginx:1'), repository('docker.io/library/nginx@sha256:' + 'a' * 64))
        self.assertEqual(repository('ghcr.io/o/app:sha-1'), 'ghcr.io/o/app')
        self.assertNotEqual(repository('ghcr.io/o/app'), repository('ghcr.io/x/app'))


if __name__ == '__main__':
    unittest.main()
