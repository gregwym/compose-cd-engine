"""Regression: Compose diagnostics must not become container identifiers."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runner import runner


class ComposeOutput(unittest.TestCase):
    def test_warning_on_stderr_does_not_break_container_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / 'docker'
            docker.write_text('''#!/bin/sh
if [ "$1" = "inspect" ]; then
  printf '%s\\n' 'container-id image-id example/app@sha256:abc'
else
  printf '%s\\n' 'the attribute `version` is obsolete' >&2
  printf '%s\\n' 'container-id'
fi
''')
            docker.chmod(0o700)
            cfg = {'compose_dir': directory, 'project': 'test',
                   'id': 'test', 'files': ['compose.yml'], 'services': ['app']}
            with patch.object(runner, 'DOCKER', str(docker)), patch.object(runner, 'STATE_DIR', root):
                actual = runner.current_containers(cfg)
            self.assertEqual(actual['app']['container'], 'container-id')
            self.assertEqual(actual['app']['image_id'], 'image-id')
