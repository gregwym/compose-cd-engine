"""Allowlisted diagnostic projection. Never exposes Docker Env, commands or arbitrary labels."""
import json
import re
from runner import compose


def clean_text(text, values=()):
    for value in sorted((v for v in values if v), key=len, reverse=True):
        text = text.replace(value, '[redacted]')
    text = re.sub(r'(?i)(bearer\s+)[^\s]+', r'\1[redacted]', text)
    text = re.sub(r'(?i)((?:password|passwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*)[^\s,;]+',
                  r'\1[redacted]', text)
    return text


def container_info(item):
    config, host = item.get('Config') or {}, item.get('HostConfig') or {}
    return {'id': item['Id'], 'name': item.get('Name'), 'image': config.get('Image'),
            'state': {k: (item.get('State') or {}).get(k) for k in ('Status', 'Running', 'ExitCode')},
            'config': {'environment_keys': [v.split('=', 1)[0] for v in config.get('Env') or []],
                       'user': config.get('User'), 'working_dir': config.get('WorkingDir'),
                       'privileged': host.get('Privileged'), 'readonly_rootfs': host.get('ReadonlyRootfs')},
            'mounts': [{k: m.get(k) for k in ('Type', 'Name', 'Destination', 'RW')} for m in item.get('Mounts') or []],
            'networks': sorted(((item.get('NetworkSettings') or {}).get('Networks') or {}))}


def inspect_project(project):
    items = compose.project_containers(project)
    if not items:
        from shared.wire import Denied
        raise Denied('not_found')
    raw = json.loads(compose.run([compose.DOCKER, 'inspect', *[c['id'] for c in items]]))
    return raw


def diagnose(project):
    raw = inspect_project(project)
    networks = sorted({n for c in raw for n in ((c.get('NetworkSettings') or {}).get('Networks') or {})})
    volumes = sorted({m['Name'] for c in raw for m in c.get('Mounts') or [] if m.get('Type') == 'volume' and m.get('Name')})
    images = sorted({c['Image'] for c in raw})
    result = {'project': project, 'containers': [container_info(c) for c in raw]}
    for kind, names, fields in [('network', networks, ('Name', 'Id', 'Driver', 'Internal', 'Scope')),
                                ('volume', volumes, ('Name', 'Driver', 'Scope')),
                                ('image', images, ('Id', 'RepoTags', 'RepoDigests', 'Architecture', 'Os', 'Size'))]:
        result[kind + 's'] = [{k: i.get(k) for k in fields} for name in names
                              for i in json.loads(compose.run([compose.DOCKER, kind, 'inspect', name]))]
    return result
