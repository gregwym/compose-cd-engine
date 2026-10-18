#!/usr/bin/env python3
"""Disposable Docker daemon integration test; CI only, never run on a NAS."""
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from management import broker
from runner import runner


def main():
    project = 'management-smoke-' + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runner.STATE_DIR = root / 'state'
        runner.STATE_DIR.mkdir()
        check = ['python3', '-c', "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8080',timeout=2).status == 200"]
        service = {'image': 'compose-cd-engine:test',
                   'command': ['python3', '-m', 'http.server', '8080', '--bind', '127.0.0.1'],
                   'read_only': True, 'cap_drop': ['ALL'], 'network_mode': 'none',
                   'healthcheck': {'test': ['CMD', *check], 'interval': '1s', 'timeout': '3s', 'retries': 10}}
        # New Compose emits an obsolete-version warning to stderr; it must not
        # contaminate ps output used by status/readiness/start/stop operations.
        (root / 'compose.json').write_text(json.dumps({'version': '3.8', 'services': {'app': service, 'unrelated': service}}))
        cfg = {'id': 'test', 'project': project, 'services': ['app'],
               'files': ['compose.json'], 'compose_dir': directory, 'rollback': False,
               'snapshot_paths': [], 'observe': False, 'require_readiness': True, 'health_timeout': 30,
               'management': {'socket': '/run/compose-cd-management/test.sock',
                              'verifier_socket': '/run/compose-cd/test-verify.sock',
                              'actions': ['status', 'logs', 'start', 'stop', 'restart', 'diagnose', 'update']}}
        def action(name):
            return broker.dispatch(cfg, {'project': 'test', 'action': name,
                'request_id': uuid.uuid4().hex, 'timestamp': int(time.time())}, runner)
        try:
            runner.command(cfg, 'up', '-d', '--pull', 'never', 'app', 'unrelated')
            runner.wait_healthy(cfg)
            unrelated_before = runner.command(cfg, 'ps', '-q', 'unrelated').stdout.strip()
            assert unrelated_before
            assert action('status')['services']['app']['state'] == 'running'
            assert action('diagnose')['readiness'] == 'passed'
            assert action('logs')['content'] == 'withheld'
            assert action('restart')['status'] == 'success'
            assert action('stop')['status'] == 'success'
            assert action('status')['services']['app']['state'] == 'exited'
            assert action('start')['status'] == 'success'
            assert runner.command(cfg, 'ps', '-q', 'unrelated').stdout.strip() == unrelated_before
            state = subprocess.check_output([runner.DOCKER, 'inspect', '--format', '{{.State.Running}}', unrelated_before.decode()]).strip()
            assert state == b'true'
            print('Management Docker integration passed: readiness, status, log summary, restart, stop/start; unrelated service unchanged.')
        finally:
            # Only this randomly named disposable CI project. No data volumes.
            runner.command(cfg, 'down', '--remove-orphans', timeout=60)


if __name__ == '__main__':
    if os.environ.get('CD_DISPOSABLE_CI') != '1':
        raise SystemExit('refusing: this test requires an explicitly disposable CI daemon')
    main()
