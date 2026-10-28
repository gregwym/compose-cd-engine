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

    def test_multiline_quoted_values_stay_whole(self):
        before = b"SCRIPT='echo start\nMODE=inside\necho end'\nQ=\"a\\\"\nB=inside\"\nMODE=outside\n"
        after = files.edit_env(before, {'MODE': 'production'}, ['Q'])
        self.assertEqual(after, b"SCRIPT='echo start\nMODE=inside\necho end'\nMODE=production\n")
        self.assertEqual(files.env_keys(before), ['SCRIPT', 'Q', 'MODE'])
        self.assertEqual(files.env_summary(before, after), {'added': [], 'removed': ['Q'], 'changed': ['MODE']})


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

    def test_short_writes_continue_and_a_stalled_write_fails(self):
        from unittest import mock
        real = os.write
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.env'
            with mock.patch.object(files.os, 'write', lambda fd, data: real(fd, bytes(data[:3]))):
                files.write_in_place(path, b'MODE=production\n')
            self.assertEqual(path.read_bytes(), b'MODE=production\n')
            with mock.patch.object(files.os, 'write', lambda fd, data: 0), self.assertRaises(OSError):
                files.write_in_place(path, b'MODE=x\n')
            with mock.patch.object(files.os, 'write', lambda fd, data: 0), self.assertRaises(OSError):
                files.backup(path, b'MODE=x\n')

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

    def test_api_socket_and_host_backed_volumes_are_rejected(self):
        self.assertEqual(self.violations(use_api_socket=True), ['web: use_api_socket'])
        for device in ('/', '/etc', '/volume1/docker/deployer/state'):
            config = {'services': {'web': {}}, 'volumes': {'data': {
                'driver': 'local', 'driver_opts': {'type': 'none', 'o': 'bind', 'device': device}}}}
            self.assertTrue(policy.violations(config, '/volume1/docker/deployer'), device)
        config['volumes']['data']['driver_opts']['device'] = '/volume1/media'
        self.assertEqual(policy.violations(config, '/volume1/docker/deployer'), [])
        self.assertEqual(policy.highlights(config, '/volume1/docker/app'), {'volume data: host path /volume1/media'})

    def test_secret_and_config_files_follow_the_mount_rules(self):
        for path in ('/etc/shadow', '/volume1/docker/deployer/gateway/gateway.sqlite'):
            for config in ({'secrets': {'s': {'file': path}}}, {'configs': {'c': {'file': path}}}):
                self.assertTrue(policy.violations(config, '/volume1/docker/deployer'), (path, config))
        config = {'secrets': {'s': {'file': '/volume1/keys/s'}}, 'configs': {'c': {'file': '/volume1/docker/app/c'}}}
        self.assertEqual(policy.violations(config, '/volume1/docker/deployer'), [])
        self.assertEqual(policy.highlights(config, '/volume1/docker/app'), {'secret s: host file /volume1/keys/s'})

    def test_directories_containing_the_deployer_are_rejected(self):
        bind = lambda source: [{'type': 'bind', 'source': source, 'target': '/x'}]
        self.assertEqual(self.violations(volumes=bind('/volume1/docker')), ['web: mounts the deployer directory'])
        self.assertEqual(self.violations(volumes=bind('/volume1/docker/app')), [])
        self.assertEqual(self.violations(volumes=bind('/volume1/docker/deployer-old')), [])

    def test_violations_do_not_echo_paths(self):
        found = policy.violations(service(volumes=[{'type': 'bind', 'source': '/etc/hunter2', 'target': '/x'}]), '')
        self.assertNotIn('hunter2', ' '.join(found))

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


class ServeRouting(unittest.TestCase):
    def test_hook_proxy_keeps_the_path_prefix(self):
        from gateway import tailscale
        config = tailscale.serve_config('h.ts.net', [], False)
        self.assertEqual(config['Web']['h.ts.net:8443']['Handlers']['/hooks/']['Proxy'],
                         f'http://127.0.0.1:{tailscale.HOOK_PORT}/hooks/')


class TransactionalApply(unittest.TestCase):
    """write_and_up with Docker replaced, to pin down recovery and stale handling."""
    def setUp(self):
        from unittest import mock
        from runner import compose, server
        self.compose, self.server, self.mock = compose, server, mock
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.wd = self.root / 'app'
        self.wd.mkdir()
        (self.wd / 'compose.yaml').write_bytes(b'old: 1\n')
        self.runner = server.Runner(self.root, health_timeout=1)
        self.identity = {'project': 'app', 'working_dir': str(self.wd), 'config_files': [str(self.wd / 'compose.yaml')]}
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def plan(self, base=None):
        return {'identity': self.identity, 'new': False, 'compose': 'new: 1\n', 'env_set': {}, 'env_unset': [],
                'base': base or {'compose': server_sha(b'old: 1\n'), 'env': None}}

    def fake(self, fail_first=None):
        def compose(identity, *args, **kwargs):
            self.calls.append(args)
            if fail_first and len(self.calls) == 1:
                raise fail_first
        return compose

    def test_timeout_rolls_back_files_and_restarts_without_pulling(self):
        timeout = self.server.Denied('timeout', 'up exceeded 1800s')
        with self.mock.patch.object(self.compose, 'compose', self.fake(timeout)), \
                self.mock.patch.object(self.compose, 'wait_healthy'):
            result = self.runner.write_and_up(self.plan())
        self.assertEqual(result['status'], 'rolled_back')
        self.assertEqual((self.wd / 'compose.yaml').read_bytes(), b'old: 1\n')
        self.assertIn('--pull', self.calls[-1])
        self.assertEqual(self.calls[-1][self.calls[-1].index('--pull') + 1], 'never')

    def test_run_turns_subprocess_timeout_into_denied(self):
        import subprocess
        with self.mock.patch('subprocess.run', side_effect=subprocess.TimeoutExpired('docker', 1)):
            with self.assertRaises(Denied) as caught:
                self.compose.run(['docker', 'compose', 'up'], timeout=1)
        self.assertEqual(caught.exception.code, 'timeout')

    def test_edit_after_planning_is_stale_and_kept(self):
        (self.wd / 'compose.yaml').write_bytes(b'edited by Container Manager\n')
        with self.mock.patch.object(self.compose, 'compose', self.fake()):
            with self.assertRaises(Denied) as caught:
                self.runner.write_and_up(self.plan())
        self.assertEqual(caught.exception.code, 'stale')
        self.assertEqual((self.wd / 'compose.yaml').read_bytes(), b'edited by Container Manager\n')
        self.assertEqual(self.calls, [])


def server_sha(data):
    from runner import server
    return server.sha(data)


class ResolvedAndRechecked(unittest.TestCase):
    def test_symlinked_bind_source_to_forbidden_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / 'media'
            link.symlink_to('/etc')
            found = policy.violations(service(volumes=[{'type': 'bind', 'source': str(link), 'target': '/m'}]), '')
            self.assertEqual(found, ['web: symlink mounts a system path'])

    def test_up_and_update_recheck_policy(self):
        from unittest import mock
        from runner import compose, server
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            wd = root / 'app'
            wd.mkdir()
            (wd / 'compose.yaml').write_text('x: 1\n')
            runner = server.Runner(root)
            identity = {'project': 'app', 'working_dir': str(wd), 'config_files': [str(wd / 'compose.yaml')]}
            bad = service(privileged=True)
            with mock.patch.object(compose, 'observed_identity', return_value=None), \
                    mock.patch.object(compose, 'render', return_value=bad), \
                    mock.patch.object(compose, 'compose') as run:
                for action in ('up', 'update'):
                    with self.assertRaises(Denied) as caught:
                        runner.lifecycle(identity, action)
                    self.assertEqual(caught.exception.code, 'policy')
                run.assert_not_called()

    def test_write_failure_restores_files(self):
        from unittest import mock
        from runner import compose, server
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            wd = root / 'app'
            wd.mkdir()
            (wd / 'compose.yaml').write_bytes(b'old: 1\n')
            runner = server.Runner(root, health_timeout=1)
            identity = {'project': 'app', 'working_dir': str(wd), 'config_files': [str(wd / 'compose.yaml')]}
            plan = {'identity': identity, 'new': False, 'compose': 'new: 1\n', 'env_set': {'A': '1'}, 'env_unset': [],
                    'base': {'compose': server.sha(b'old: 1\n'), 'env': None}}
            real = files.write_in_place

            def flaky(path, data, *args, **kwargs):
                if Path(path).name == '.env':
                    raise OSError(28, 'No space left on device')
                return real(path, data, *args, **kwargs)
            with mock.patch.object(files, 'write_in_place', flaky), mock.patch.object(compose, 'compose'), \
                    mock.patch.object(compose, 'wait_healthy'):
                result = runner.write_and_up(plan)
            self.assertEqual(result['status'], 'rolled_back')
            self.assertEqual(result['error'], 'write_failed')
            self.assertEqual((wd / 'compose.yaml').read_bytes(), b'old: 1\n')
            self.assertFalse((wd / '.env').exists())


if __name__ == '__main__':
    unittest.main()
