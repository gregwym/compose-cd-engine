import io
import json
import unittest
from unittest.mock import patch
from client import cdctl
from runner import boundary, diagnostics
from shared.wire import Denied
from test_reusable import Grants


class ReadPriority(Grants):
    def test_global_read_does_not_shadow_project_grants(self):
        self.grant('read')
        for scope in ('legacy', 'manage'):
            with self.subTest(scope=scope):
                self.grant(scope, 60)
                self.call('read', project='app')
                self.assertEqual(self.calls[-1], ('read', {'identity': self.identity}))
        self.call('read', project='deployer')
        self.assertEqual(self.calls[-1], ('diagnose', {'project': 'deployer'}))
        with self.store.db() as db:
            db.execute("UPDATE grants SET status='revoked' WHERE project='app'")
        self.call('read', project='app')
        self.assertEqual(self.calls[-1], ('diagnose', {'project': 'app'}))


for _name in list(vars(Grants)):
    if _name.startswith('test_'):
        setattr(ReadPriority, _name, None)
del Grants


class ResourceCompatibility(unittest.TestCase):
    def check(self, kind='volumes', name='custom-state', owner='app', driver='local', options=None,
              exists=True, external=False):
        resource = {'Name': name, 'Driver': driver, 'Options': options,
                    'Labels': {'com.docker.compose.project': owner} if owner else {}}
        replies = [name.encode() if exists else b'']
        if exists:
            replies.append(json.dumps([resource]).encode())
        with patch('runner.compose.run', side_effect=replies):
            return boundary.check({kind: {'state': {'name': name, 'external': external}}},
                                  {'project': 'app'}, {'mounts': [], 'networks': []}, '')

    def test_custom_existing_owned_local_volume(self):
        self.check()

    def test_custom_volume_foreign_unowned_missing_and_external_rejected(self):
        for override in ({'owner': 'foreign'}, {'owner': None}, {'exists': False}, {'external': True},
                         {'driver': 'nfs'}, {'options': {'device': '/etc', 'type': 'none', 'o': 'bind'}}):
            with self.subTest(override=override), self.assertRaises(Denied):
                self.check(**override)

    def test_no_default_name_takeover_and_new_default_allowed(self):
        self.check(name='app_state', exists=False)
        with self.assertRaises(Denied):
            self.check(name='app_state', owner=None)

    def test_existing_custom_bridge_requires_owner_and_no_options(self):
        self.check(kind='networks', driver='bridge')
        for override in ({'owner': None}, {'owner': 'foreign'}, {'exists': False},
                         {'driver': 'macvlan'}, {'options': {'parent': 'eth0'}}):
            with self.subTest(override=override), self.assertRaises(Denied):
                self.check(kind='networks', **{'driver': 'bridge', **override})

    def test_shared_namespace_policy_unchanged(self):
        with self.assertRaises(Denied):
            boundary.check({'services': {'proxy': {'network_mode': 'service:tailscale'}}},
                           {'project': 'app'}, {'mounts': [], 'networks': []}, '')


class DiagnosticProjection(unittest.TestCase):
    def test_structural_network_mount_and_ownership_without_secrets(self):
        labels = {'com.docker.compose.project': 'app', 'com.docker.compose.service': 'web',
                  'com.docker.compose.project.working_dir': '/volume1/docker/app',
                  'com.docker.compose.project.config_files': '/volume1/docker/app/compose.yaml',
                  'secret-label': 'SECRET'}
        raw = [{'Id': 'cid', 'Name': '/app-web', 'Image': 'sha256:image',
                'Config': {'Image': 'image:tag', 'Labels': labels, 'Env': ['TOKEN=SECRET'], 'Cmd': ['SECRET']},
                'Mounts': [{'Type': 'bind', 'Source': '/volume1/media', 'Destination': '/media', 'RW': False},
                           {'Type': 'volume', 'Name': 'custom-state', 'Destination': '/state'}],
                'NetworkSettings': {'Networks': {'edge': {'NetworkID': 'nid', 'IPAddress': '172.20.0.2',
                                                         'Gateway': '172.20.0.1', 'DriverOpts': {'token': 'SECRET'}}}}}]
        network = {'Name': 'edge', 'Driver': 'bridge', 'Labels': labels, 'Options': {'token': 'SECRET'},
                   'IPAM': {'Driver': 'default', 'Options': {'token': 'SECRET'},
                            'Config': [{'Subnet': '172.20.0.0/16', 'Gateway': '172.20.0.1', 'secret': 'SECRET'}]}}
        volume = {'Name': 'custom-state', 'Driver': 'local', 'Labels': labels, 'Options': {'token': 'SECRET'}}
        image = {'Id': 'sha256:image', 'Config': {'Env': ['TOKEN=SECRET']}}
        with patch('runner.diagnostics.inspect_project', return_value=raw), patch('runner.compose.run',
                side_effect=[json.dumps([x]).encode() for x in (network, volume, image)]):
            result = diagnostics.diagnose('app')
        container = result['containers'][0]
        self.assertEqual(container['mounts'][0]['Source'], '/volume1/media')
        self.assertFalse(container['mounts'][0]['RW'])
        self.assertEqual(container['image_id'], 'sha256:image')
        self.assertEqual(container['ownership']['com.docker.compose.project'], 'app')
        self.assertEqual(container['network_endpoints']['edge']['IPAddress'], '172.20.0.2')
        self.assertEqual(result['networks'][0]['IPAM']['Config'][0]['Subnet'], '172.20.0.0/16')
        self.assertEqual(result['volumes'][0]['Labels']['com.docker.compose.project'], 'app')
        self.assertTrue(result['volumes'][0]['has_driver_options'])
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('secret-label', json.dumps(result))


class ClientReadDefault(unittest.TestCase):
    def test_request_read_defaults_to_environment(self):
        with patch('client.cdctl.Client') as client, patch('sys.stdout', new_callable=io.StringIO):
            client.return_value.call.return_value = {}
            cdctl.main(['request', 'read', '--permanent'])
            self.assertEqual(client.return_value.call.call_args.kwargs['project'], '*')
            cdctl.main(['request', 'read', 'explicit'])
            self.assertEqual(client.return_value.call.call_args.kwargs['project'], 'explicit')
            cdctl.main(['request', 'unserve', '--https-port', '8444'])
            self.assertEqual(client.return_value.call.call_args.kwargs['project'], '')
