#!/usr/bin/env python3
"""Real project provisioning on an explicitly disposable CI Docker daemon only."""
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

from deployer.service import Service
from runner import runner


def main():
    nonce = uuid.uuid4().hex[:10]
    root = Path('/run/compose-project-smoke') / nonce
    root.mkdir(mode=0o700)
    for key in ('private', 'config', 'downloads', 'state'):
        (root / key).mkdir(mode=0o700)
    runner.STATE_DIR = root / 'state'
    project = 'pilot-' + nonce
    unrelated = 'unrelated-' + nonce
    docker = [runner.DOCKER, '--host', 'unix:///var/run/docker.sock']
    # Prepare a disposable local image with a useful default command. Production
    # never accepts image creation, commands or commits through this API.
    check = ['python3', '-c', "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8080',timeout=2).status == 200"]
    label = 'project-smoke:' + nonce
    builder = 'builder-' + nonce
    subprocess.run(docker + ['create', '--name', builder, 'compose-cd-engine:test'],
                   stdout=subprocess.DEVNULL, check=True)
    try:
        subprocess.run(docker + ['commit', '--change',
            'CMD ["python3", "-m", "http.server", "8080", "--bind", "0.0.0.0"]', builder, label],
            stdout=subprocess.DEVNULL, check=True)
    finally:
        subprocess.run(docker + ['rm', builder], stdout=subprocess.DEVNULL, check=True)
    image_id = subprocess.check_output(docker + ['image', 'inspect', '--format', '{{.Id}}', label]).decode().strip()
    # A local committed image has no registry manifest. The adapter below does
    # not test registry resolution/pull or signatures; report that explicitly.
    repo = 'example.invalid/ci/project'
    image = repo + '@' + image_id
    subprocess.run(docker + ['tag', label, repo + ':local'], check=True)
    cfg = {'workspace': str(root / 'private'), 'storage': {
        'config': {'path': str(root / 'config'), 'shared': False, 'uid': 10001, 'gid': 10001},
        'downloads': {'path': str(root / 'downloads'), 'shared': True, 'uid': 10001, 'gid': 10001}},
        'images': {repo: {'digests': [image_id.split(':')[1]], 'allow_unsigned': True,
                          'healthcheck': check, 'environment': ['PRIVATE_TEST']}},
        'port_range': [20000, 20010], 'bind_ip': '192.168.50.10', 'max_projects': 2,
        'max_services': 2, 'max_memory_mb': 256, 'max_cpus': 2, 'max_pids': 64,
        'health_timeout': 60, 'enabled': True, 'allow_egress': False,
        'operations': ['plan', 'apply', 'task', 'status', 'start', 'stop', 'restart']}
    policy = root / 'policy.json'
    policy.write_text(json.dumps(cfg))
    policy.chmod(0o600)
    service = Service(str(policy), runner)
    original = service.compose
    # Local builds have no registry manifest digest. Substitute only the image
    # reference and pull step in this smoke adapter; all generated restrictions,
    # storage creation, actual up/start/stop/restart/health/failure run unchanged.
    def compose(directory, project, *args, **kwargs):
        if args[0] == 'pull':
            return
        path = directory / 'compose.json'
        doc = json.loads(path.read_text())
        for item in doc['services'].values():
            item['image'] = label
        path.write_text(json.dumps(doc))
        return original(directory, project, *args, **kwargs)
    service.compose = compose
    def call(op, payload=None):
        return service.dispatch({'project': project, 'operation': op, 'payload': payload or {},
                                 'request_id': uuid.uuid4().hex, 'timestamp': int(time.time())})
    def finish(task):
        assert service.run_one()
        return call('task', {'task_id': task})['status']
    spec = {'services': {'web': {'image': image, 'memory_mb': 64, 'cpus': 1,
        'environment': {'PRIVATE_TEST': 'do-not-return-${UNSET}'},
        'mounts': [{'storage': 'config', 'slot': 'web', 'target': '/appdata', 'read_only': False}], 'ports': []}}}
    try:
        subprocess.run(docker + ['run', '-d', '--name', unrelated, '--network', 'none', label],
                       check=True, stdout=subprocess.DEVNULL)
        before = subprocess.check_output(docker + ['inspect', '--format', '{{.Id}} {{.State.StartedAt}}', unrelated])
        plan = call('plan', spec)
        assert 'do-not-return' not in json.dumps(plan)
        task = call('apply', {'plan_id': plan['plan_id']})['task_id']
        assert call('apply', {'plan_id': plan['plan_id']})['task_id'] == task
        assert finish(task) == 'success'
        assert call('status')['services']['web'] == 'running'
        for op in ('restart', 'stop', 'start'):
            assert finish(call(op)['task_id']) == 'success', op
        container = service.docker('ps', '--quiet', '--filter',
            'label=com.docker.compose.project=cdp-' + project).decode().strip()
        # Simulate app writes as the actual unprivileged image user. Runner has
        # neither DAC_OVERRIDE nor permission to traverse the app's 0750 leaf.
        service.docker('exec', container, 'python3', '-c',
            "from pathlib import Path; Path('/appdata/media').write_text('preserve-downloads')")
        # Administrator changes approved fixed readiness probe to force a real
        # partially applied update failure. No change to image/mount authority.
        cfg['images'][repo]['healthcheck'] = ['python3', '-c', 'raise SystemExit(1)']
        cfg['health_timeout'] = 10
        policy.write_text(json.dumps(cfg))
        task = call('apply', {'plan_id': call('plan', spec)['plan_id']})['task_id']
        state = finish(task)
        assert state == 'recovery_required', call('task', {'task_id': task})
        assert call('status')['recovery_required']
        container = service.docker('ps', '--quiet', '--filter',
            'label=com.docker.compose.project=cdp-' + project).decode().strip()
        assert service.docker('exec', container, 'python3', '-c',
            "from pathlib import Path; print(Path('/appdata/media').read_text())").strip() == b'preserve-downloads'
        try:
            call('restart')
            raise AssertionError('recovery bypassed')
        except ValueError:
            pass
        assert finish(call('stop')['task_id']) == 'success'
        assert subprocess.check_output(docker + ['inspect', '--format', '{{.Id}} {{.State.StartedAt}}', unrelated]) == before
        print('Project Docker integration passed: create, idempotent apply, health, lifecycle, real failed update, recovery latch, preserved media and unrelated uptime. Local-image adapter; registry verification is NOT covered by this smoke.')
    finally:
        # Only disposable, random CI names; never cleanup NAS or user data.
        subprocess.run(docker + ['rm', '-f', unrelated], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for directory in (root / 'private').iterdir():
            if directory.is_dir() and (directory / 'compose.json').exists():
                try:
                    original(directory, project, 'down', '--remove-orphans', timeout=30)
                except Exception:
                    pass
        subprocess.run(docker + ['image', 'rm', label, repo + ':local'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    if os.environ.get('CD_DISPOSABLE_CI') != '1':
        raise SystemExit('refusing: disposable CI Docker daemon required')
    main()
