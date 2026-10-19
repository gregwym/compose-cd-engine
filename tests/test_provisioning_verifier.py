import copy
import unittest
from unittest.mock import patch
from authorization.scope import Denied
from deployer import schema
from verifier.provisioning import ProvisioningVerifier
import test_projects as projects


class ProvisioningSignatures(unittest.TestCase):
    def setUp(self):
        self.cfg = projects.policy()
        self.repo = 'example.invalid/team/app'
        self.cfg['verification'] = {'socket': '/run/verify.sock', 'service_key': '/etc/verify.key'}
        self.cfg['images'][self.repo].update(allow_unsigned=False,
            identity='https://github.com/team/app/.github/workflows/build.yml@refs/heads/main',
            issuer='https://token.actions.githubusercontent.com', platform='linux/amd64')
        self.spec = projects.spec()
        self.doc = {'os': 'linux', 'architecture': 'amd64', 'config': {'Labels': {
            'org.opencontainers.image.source': 'https://github.com/team/app',
            'org.opencontainers.image.revision': 'a' * 40}}}
        self.trust = patch('verifier.provisioning.trusted_json', side_effect=lambda _: copy.deepcopy(self.cfg))
        self.trust.start()

    def tearDown(self):
        self.trust.stop()

    def verify(self):
        return ProvisioningVerifier('policy').dispatch('verify', {'project': 'test', 'spec': self.spec, 'policy': schema.fingerprint(self.cfg)})

    def test_signed_platform_and_index_membership(self):
        self.spec['services']['app']['signed_index'] = self.repo + '@sha256:' + 'b' * 64
        with patch('verifier.provisioning.cosign') as cosign, \
             patch('verifier.provisioning.resolve', return_value=('sha256:' + 'a' * 64, {})), \
             patch('verifier.provisioning.config_document', return_value=self.doc):
            self.assertEqual(self.verify()['status'], 'verified')
            self.assertEqual(cosign.call_args.args[-1], self.spec['services']['app']['signed_index'])
            self.assertIn(self.cfg['images'][self.repo]['identity'], cosign.call_args.args)

    def test_failed_signature_wrong_platform_digest_source_and_inconsistent_group(self):
        for change in ('signature', 'digest', 'architecture', 'source', 'group'):
            self.spec = projects.spec()
            doc = copy.deepcopy(self.doc)
            if change == 'architecture':
                doc['architecture'] = 'arm64'
            if change == 'source':
                doc['config']['Labels']['org.opencontainers.image.source'] = 'https://github.com/evil/app'
            if change == 'group':
                self.spec['services']['second'] = copy.deepcopy(self.spec['services']['app'])
                self.spec['services']['second']['ports'] = []
                changed = copy.deepcopy(doc)
                changed['config']['Labels']['org.opencontainers.image.revision'] = 'b' * 40
            with patch('verifier.provisioning.cosign', side_effect=RuntimeError() if change == 'signature' else None), \
                 patch('verifier.provisioning.resolve', return_value=('sha256:' + ('b' if change == 'digest' else 'a') * 64, {})), \
                 patch('verifier.provisioning.config_document', side_effect=[doc, changed] if change == 'group' else None, return_value=doc), \
                 self.subTest(change=change), self.assertRaises(Exception):
                self.verify()

    def test_unsigned_exception_must_be_exact_even_without_grants(self):
        self.cfg['images'][self.repo]['allow_unsigned'] = True
        with self.assertRaises(Denied):
            self.verify()
        self.cfg['images'][self.repo]['digests'] = ['a' * 64]
        self.assertEqual(self.verify()['services']['app'], 'administrator_unsigned_exception')

    def test_initial_coordinated_group_cannot_be_incomplete_or_unsigned(self):
        self.cfg['release_groups'] = [['app', 'worker']]
        with self.assertRaises(schema.PolicyViolation):
            self.verify()
        self.spec['services']['worker'] = copy.deepcopy(self.spec['services']['app'])
        self.spec['services']['worker']['ports'] = []
        with patch('verifier.provisioning.cosign'), \
             patch('verifier.provisioning.resolve', return_value=('sha256:' + 'a' * 64, {})), \
             patch('verifier.provisioning.config_document', return_value=self.doc):
            self.assertEqual(self.verify()['status'], 'verified')
        self.cfg['images'][self.repo].update(allow_unsigned=True, digests=['a' * 64])
        with self.assertRaises(Denied):
            self.verify()
