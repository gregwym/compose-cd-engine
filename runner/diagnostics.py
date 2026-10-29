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


def ownership(item):
    labels = item.get('Labels') or {}
    return {compose.LABEL + key: labels[compose.LABEL + key]
            for key in ('project', 'service', 'volume', 'network', 'project.working_dir', 'project.config_files')
            if compose.LABEL + key in labels}


def network_info(item):
    out = {k: item.get(k) for k in ('Name', 'Id', 'Driver', 'Internal', 'Scope', 'EnableIPv6', 'Attachable')}
    out['Labels'] = ownership(item)
    ipam = item.get('IPAM') or {}
    out['IPAM'] = {'Driver': ipam.get('Driver'),
                   'Config': [{k: entry[k] for k in ('Subnet', 'IPRange', 'Gateway', 'AuxiliaryAddresses') if k in entry}
                              for entry in ipam.get('Config') or []]}
    # Options may contain credentials for third-party drivers; expose presence only.
    out['has_driver_options'] = bool(item.get('Options'))
    return out


def container_info(item):
    config, host = item.get('Config') or {}, item.get('HostConfig') or {}
    return {'id': item['Id'], 'name': item.get('Name'), 'image': config.get('Image'), 'image_id': item.get('Image'),
            'ownership': ownership(config),
            'state': {k: (item.get('State') or {}).get(k) for k in ('Status', 'Running', 'ExitCode')},
            'config': {'environment_keys': [v.split('=', 1)[0] for v in config.get('Env') or []],
                       'user': config.get('User'), 'working_dir': config.get('WorkingDir'),
                       'privileged': host.get('Privileged'), 'readonly_rootfs': host.get('ReadonlyRootfs')},
            'mounts': [{k: m.get(k) for k in ('Type', 'Name', 'Source', 'Destination', 'RW', 'Propagation')} for m in item.get('Mounts') or []],
            'networks': sorted(((item.get('NetworkSettings') or {}).get('Networks') or {})),
            'network_endpoints': {name: {k: endpoint.get(k) for k in
                ('NetworkID', 'EndpointID', 'Gateway', 'IPAddress', 'IPPrefixLen', 'IPv6Gateway',
                 'GlobalIPv6Address', 'GlobalIPv6PrefixLen', 'MacAddress', 'Aliases')}
                for name, endpoint in ((item.get('NetworkSettings') or {}).get('Networks') or {}).items()}}


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
        inspected = [i for name in names
                     for i in json.loads(compose.run([compose.DOCKER, kind, 'inspect', name]))]
        result[kind + 's'] = [network_info(i) if kind == 'network' else
                             {**{k: i.get(k) for k in fields},
                              **({'Labels': ownership(i), 'has_driver_options': bool(i.get('Options'))}
                                 if kind == 'volume' else {})}
                             for i in inspected]
    return result
