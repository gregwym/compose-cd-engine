"""Configuration tooling must not write outside the selected output directory."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class WorkflowGeneration(unittest.TestCase):
    def generate(self, name):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'projects.json'
            config.write_text(json.dumps({'projects': {name: {'enabled': False, 'cron': '0 1 * * *'}}}))
            output = root / 'workflows'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/generate_workflows.py'), '--config', str(config), '--output-dir', str(output)], capture_output=True)
            return result, list(output.iterdir()), (output / 'check-example-app.yml').read_text() if (output / 'check-example-app.yml').exists() else ''

    def test_external_ops_configuration_has_no_schedule_when_disabled(self):
        result, files, text = self.generate('example-app')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(files), 1)
        self.assertNotIn('  schedule:', text)
        self.assertIn('workflow_dispatch:', text)

    def test_project_cannot_escape_output_directory(self):
        result, files, _ = self.generate('../../escape')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(files, [])

    def test_project_cannot_inject_workflow_commands(self):
        result, files, _ = self.generate('app; echo injected')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(files, [])
