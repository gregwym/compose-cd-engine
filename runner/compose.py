"""Docker and Compose invocations using each project's Container Manager identity."""
import json
import os
import re
import subprocess
import time
from shared.wire import Denied

DOCKER = os.environ.get('CD_DOCKER', '/usr/local/bin/docker')
LABEL = 'com.docker.compose.'
NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,62}')
SERVICE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}')


def environment():
    # Only the project's own .env may take part in interpolation.
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp',
            'DOCKER_HOST': os.environ.get('DOCKER_HOST', 'unix:///var/run/docker.sock')}


def run(argv, timeout=120, check=True):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=environment(), timeout=timeout)
    if check and result.returncode:
        tail = result.stderr.decode('utf-8', 'replace').strip()[-2000:]
        raise Denied('docker_failed', tail)
    return result.stdout


def containers():
    ids = run([DOCKER, 'ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL + 'project']).decode().split()
    if not ids:
        return []
    found = []
    for item in json.loads(run([DOCKER, 'inspect', *ids])):
        labels = item.get('Config', {}).get('Labels') or {}
        if labels.get(LABEL + 'oneoff') == 'True':
            continue
        state = item.get('State') or {}
        ports = []
        for key, bindings in ((item.get('NetworkSettings') or {}).get('Ports') or {}).items():
            for binding in bindings or []:
                if binding.get('HostPort'):
                    ports.append({'host_ip': binding.get('HostIp') or '0.0.0.0',
                                  'host_port': int(binding['HostPort']), 'container': key})
        found.append({
            'id': item['Id'], 'name': item.get('Name', '').lstrip('/'),
            'project': labels.get(LABEL + 'project', ''), 'service': labels.get(LABEL + 'service', ''),
            'working_dir': labels.get(LABEL + 'project.working_dir', ''),
            'config_files': [x for x in labels.get(LABEL + 'project.config_files', '').split(',') if x],
            'image': item.get('Config', {}).get('Image', ''), 'image_id': item.get('Image', ''),
            'state': state.get('Status', 'unknown'), 'health': (state.get('Health') or {}).get('Status'),
            'exit_code': state.get('ExitCode'),
            'restart': ((item.get('HostConfig') or {}).get('RestartPolicy') or {}).get('Name') or 'no',
            'ports': sorted(ports, key=lambda p: (p['host_port'], p['host_ip'])),
        })
    return found


def project_containers(name):
    return [c for c in containers() if c['project'] == name]


def observed_identity(name, items=None):
    """The identity Container Manager and Compose recorded on the containers."""
    items = project_containers(name) if items is None else items
    if not items:
        return None
    identities = {(c['working_dir'], tuple(c['config_files'])) for c in items}
    if len(identities) != 1:
        raise Denied('ambiguous_project', 'containers disagree on working directory or files')
    working_dir, files = identities.pop()
    return {'project': name, 'working_dir': working_dir, 'config_files': list(files)}


def base(identity, files=None, env_file=None):
    argv = [DOCKER, 'compose', '-p', identity['project'], '--project-directory', identity['working_dir']]
    for path in files or identity['config_files']:
        argv += ['-f', str(path)]
    if env_file is not None:
        argv += ['--env-file', str(env_file)]
    return argv


def render(identity, files=None, env_file=None, interpolate=True):
    argv = base(identity, files, env_file) + ['config', '--format', 'json']
    if not interpolate:
        argv.append('--no-interpolate')
    return json.loads(run(argv, timeout=60))


def compose(identity, *args, timeout=1800):
    return run(base(identity) + list(args), timeout=timeout)


def wait_healthy(identity, timeout, services=()):
    """Each container runs (healthy if it has a check) or is a finished one-shot."""
    deadline = time.monotonic() + timeout
    last = 'no containers'
    while True:
        items = [c for c in project_containers(identity['project']) if not services or c['service'] in services]
        pending, failed = [], []
        for c in items:
            label = f"{c['service']}: {c['state']}" + (f"/{c['health']}" if c['health'] else '')
            if c['state'] == 'running':
                if c['health'] == 'unhealthy':
                    failed.append(label)
                elif c['health'] == 'starting':
                    pending.append(label)
            elif c['state'] == 'exited':
                label += f" (exit {c['exit_code']})"
                if c['exit_code'] == 0 and c['restart'] in ('no', 'on-failure'):
                    pass
                elif c['restart'] == 'no':
                    failed.append(label)
                else:
                    pending.append(label)  # Docker restarts it; the deadline decides.
            elif c['state'] in ('created', 'restarting'):
                pending.append(label)
            else:
                failed.append(label)
        if items and not pending and not failed:
            return
        last = '; '.join(failed + pending) or last
        if failed or time.monotonic() >= deadline:
            raise Denied('unhealthy', last)
        time.sleep(2)


def logs(container, tail):
    result = subprocess.run([DOCKER, 'logs', '--tail', str(tail), '--timestamps', container],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env=environment(), timeout=30)
    return result.stdout[-65536:].decode('utf-8', 'replace')


def image_ids(identity):
    return {c['service']: (c['image'], c['image_id']) for c in project_containers(identity['project'])}


def retag(ref, image_id):
    # Pinned references cannot move; only tags need restoring.
    if '@' not in ref:
        run([DOCKER, 'image', 'tag', image_id, ref], timeout=60)

