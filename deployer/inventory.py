"""Fixed read-only Docker query. Never read Compose files, env, mounts or logs."""
import json
import re
import time

FORMAT = ('{"name":{{json .Names}},"image":{{json .Image}},"state":{{json .State}},'
          '"project":{{json (.Label "com.docker.compose.project")}},'
          '"service":{{json (.Label "com.docker.compose.service")}}}')


def collect(docker):
    raw = docker('ps', '--all', '--no-trunc', '--last', '65', '--format', FORMAT)
    if len(raw) > 524288:
        raise ValueError('inventory response too large')
    rows = raw.decode().splitlines()
    containers = []
    for line in rows[:64]:
        row = json.loads(line)
        def name(key):
            value = row.get(key)
            return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value) else None
        image = row.get('image')
        image = image if (isinstance(image, str) and len(image) <= 256 and '://' not in image
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:-]*(?:@sha256:[a-f0-9]{64})?', image)) else '[withheld]'
        state = row.get('state')
        containers.append({'name': name('name'), 'project': name('project'), 'service': name('service'),
                           'image': image, 'state': state if state in (
                               'created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead') else 'unknown'})
    return {'containers': containers, 'truncated': len(rows) > 64, 'collected_at': int(time.time()),
            'read_only': True, 'managed_access_granted': False}
