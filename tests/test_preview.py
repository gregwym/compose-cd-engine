"""Public review projection preserves useful changes without credential payloads."""
import unittest
from shared import preview


class Preview(unittest.TestCase):
    def test_both_versions_and_executable_payloads_are_scrubbed(self):
        before = {'services': {'web': {'image': 'app:old', 'environment': {'TOKEN': 'old-value'},
            'command': ['echo', 'command-secret'], 'labels': {'password': 'label-secret'},
            'volumes': [{'source': '/data/old-value', 'target': '/data'}]}}}
        after = {'services': {'web': {'image': 'app:new', 'environment': {'TOKEN': 'new-value'},
            'healthcheck': {'test': ['CMD', 'health-secret']},
            'volumes': [{'source': '/data/new-value', 'target': '/data', 'read_only': True}],
            'ports': [{'published': '8080', 'target': 80}], 'restart': 'unless-stopped'}}}
        result = preview.diff(before, after)
        for secret in ('old-value', 'new-value', 'command-secret', 'label-secret', 'health-secret'):
            self.assertNotIn(secret, result)
        for visible in ('app:old', 'app:new', '8080', 'read_only', 'unless-stopped'):
            self.assertIn(visible, result)

    def test_embedded_url_credentials_and_unknown_fields_are_hidden(self):
        result = preview.project({'services': {'web': {
            'image': 'https://user:pass@registry/image', 'unknown': 'private',
            'networks': {'default': {'secret': 'private-key'}}}}})
        self.assertEqual(result['services']['web']['image'], preview.HIDDEN)
        self.assertEqual(result['services']['web']['unknown'], preview.HIDDEN)
        self.assertEqual(result['services']['web']['networks']['default']['secret'], preview.HIDDEN)
