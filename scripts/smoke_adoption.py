#!/usr/bin/env python3
"""Disposable structural projection smoke; never points at an existing project."""
import json
import os
import subprocess
import uuid
from deployer.adoption import inspect_project, adoption_preview
from shared.bounded import run


def main():
    assert os.environ.get('CD_DISPOSABLE_CI') == '1'
    project = 'adoption-smoke-' + uuid.uuid4().hex[:12]
    name = project + '-web'
    docker = ['docker']
    cid = subprocess.check_output(docker + ['create', '--name', name,
        '--label', 'com.docker.compose.project=' + project,
        '--label', 'com.docker.compose.service=web',
        '--label', 'com.docker.compose.project.working_dir=/srv/disposable',
        '--label', 'com.docker.compose.project.config_files=/srv/disposable/compose.yaml',
        '--env', 'PRIVATE_SMOKE=must-not-return',
        os.environ.get('CD_SMOKE_IMAGE','compose-cd-engine:test')]).decode().strip()
    try:
        def query(*args, timeout):
            return run(docker + list(args), env=os.environ, timeout=timeout)
        baseline = inspect_project(query, project)
        assert baseline['containers'][0]['container_id'] == cid
        assert 'must-not-return' not in json.dumps(baseline)
        assert not adoption_preview(baseline)['execute_allowed']
        assert subprocess.check_output(docker + ['inspect', '--format', '{{.Id}}', cid]).decode().strip() == cid
        print('PASS real Docker projection, private-env exclusion, baseline preview; no app mutation')
    finally:
        # Only remove the exact disposable fixture created by this process.
        subprocess.run(docker + ['rm', cid], check=True, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
