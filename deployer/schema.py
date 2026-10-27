"""Closed declaration schema; never pass caller Compose/YAML to Docker."""
import hashlib
import ipaddress
import json
import re
from pathlib import PurePosixPath

MAX_REQUEST = 65536
OPS = frozenset({'plan', 'apply', 'task', 'status', 'start', 'stop', 'restart',
                 'grant_request', 'grant_status', 'grants', 'projects', 'diagnose', 'retire',
                 'inventory', 'inventory_request', 'inspect', 'inspect_request'})
NAME = re.compile(r'[a-z][a-z0-9-]{0,31}')
HEX = re.compile(r'[a-f0-9]{32}')
IMAGE = re.compile(r'([a-z0-9][a-z0-9./_-]+)@sha256:([a-f0-9]{64})')


class PolicyViolation(ValueError):
    pass


class InsufficientResources(ValueError):
    pass


def allowed(ok):
    if not ok:
        raise PolicyViolation('forbidden_by_policy')


def resources(ok):
    if not ok:
        raise InsufficientResources('insufficient_resources')


def check(ok):
    if not ok:
        raise ValueError('invalid declaration or policy')


def fields(value, required, optional=()):
    check(isinstance(value, dict) and set(required) <= set(value)
          and not set(value) - set(required) - set(optional))


def name(value):
    check(isinstance(value, str) and NAME.fullmatch(value) is not None)
    return value


def number(value, low, high):
    check(type(value) is int and low <= value <= high)
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def request(raw):
    check(len(raw) <= MAX_REQUEST)
    value = json.loads(raw)
    fields(value, {'project', 'operation', 'request_id', 'timestamp', 'payload'})
    name(value['project'])
    check(value['operation'] in OPS and type(value['timestamp']) is int
          and isinstance(value['request_id'], str) and HEX.fullmatch(value['request_id'])
          and isinstance(value['payload'], dict))
    payload = value['payload']
    op = value['operation']
    if op == 'plan':
        fields(payload, {'services'}, {'egress'})
    elif op in ('inventory_request', 'inspect_request'):
        fields(payload, {'mode', 'lifetime'})
        check(payload['mode'] in ('once', 'persistent', 'expiring'))
        number(payload['lifetime'], 60, 31536000)
    elif op == 'grant_request':
        fields(payload, {'plan_id', 'mode', 'lifetime'})
        check(HEX.fullmatch(payload['plan_id']) and payload['mode'] in ('once', 'persistent', 'expiring'))
        number(payload['lifetime'], 60, 31536000)
    elif op == 'grant_status':
        fields(payload, {'approval_id'})
        check(HEX.fullmatch(payload['approval_id']))
    elif op in ('apply', 'task'):
        key = 'plan_id' if op == 'apply' else 'task_id'
        fields(payload, {key})
        check(isinstance(payload[key], str) and HEX.fullmatch(payload[key]))
    else:
        fields(payload, set())
    return value


def policy(cfg):
    fields(cfg, {'workspace', 'storage', 'images', 'port_range', 'bind_ip',
                 'max_projects', 'max_services', 'max_memory_mb', 'max_cpus',
                 'max_pids', 'health_timeout', 'enabled', 'allow_egress', 'operations'}, {'authorization', 'verification', 'release_groups'})
    check(type(cfg['enabled']) is bool and type(cfg['allow_egress']) is bool)
    check(isinstance(cfg['operations'], list) and cfg['operations']
          and all(isinstance(x, str) and x in OPS for x in cfg['operations']))
    path = PurePosixPath(cfg['workspace'])
    check(path.is_absolute() and '..' not in path.parts and str(path) != '/')
    check(isinstance(cfg['storage'], dict) and cfg['storage'])
    paths = [path]
    for key, item in cfg['storage'].items():
        name(key)
        fields(item, {'path', 'shared', 'uid', 'gid'})
        p = PurePosixPath(item['path'])
        check(p.is_absolute() and '..' not in p.parts and str(p) != '/')
        # Administrator alias configuration is trusted, but ordinary project
        # grants must never expose known host control planes or engine secrets.
        check(str(p) != '/run')
        for prefix in ('/etc', '/proc', '/sys', '/dev', '/var/run', '/root',
                       '/bin', '/sbin', '/lib', '/lib64', '/usr',
                       '/run/docker', '/run/containerd', '/run/compose-cd',
                       '/run/compose-cd-approval', '/run/compose-cd-management', '/run/compose-cd-verification',
                       '/var/lib/compose-cd', '/var/lib/compose-cd-approval',
                       '/var/lib/compose-cd-management', '/var/lib/compose-cd-verification'):
            check(str(p) != prefix and not str(p).startswith(prefix + '/'))
        check(type(item['shared']) is bool)
        number(item['uid'], 1, 2147483647)
        number(item['gid'], 1, 2147483647)
        paths.append(p)
    for i, p in enumerate(paths):
        for other in paths[i + 1:]:
            check(p != other and p not in other.parents and other not in p.parents)
    check(isinstance(cfg['images'], dict) and cfg['images'])
    for repo, image in cfg['images'].items():
        check(IMAGE.fullmatch(repo + '@sha256:' + 'a' * 64) is not None
              and '/' in repo and not any(x in ('', '.', '..') for x in repo.split('/')))
        fields(image, {'digests', 'allow_unsigned', 'healthcheck', 'environment'}, {'identity', 'issuer', 'platform'})
        # Unsigned upstream consumption must be an explicit administrator choice.
        check(type(image['allow_unsigned']) is bool)
        if not image['allow_unsigned']:
            check(set(('identity', 'issuer', 'platform')) <= set(image) and 'verification' in cfg)
            check(isinstance(image['identity'], str) and image['identity'].startswith('https://github.com/')
                  and '/.github/workflows/' in image['identity'] and '@refs/heads/' in image['identity'])
            check(image['issuer'] == 'https://token.actions.githubusercontent.com')
            check(image['platform'] in ('linux/amd64', 'linux/arm64'))
        check(isinstance(image['digests'], list) and all(
            isinstance(x, str) and re.fullmatch('[a-f0-9]{64}', x) for x in image['digests']))
        probe = image['healthcheck']
        check(isinstance(probe, list) and 1 <= len(probe) <= 32
              and all(isinstance(x, str) and 0 < len(x) <= 1024 for x in probe))
        check(isinstance(image['environment'], list) and all(
            isinstance(x, str) and re.fullmatch('[A-Z][A-Z0-9_]{0,63}', x) for x in image['environment']))
    check(isinstance(cfg['port_range'], list) and len(cfg['port_range']) == 2)
    number(cfg['port_range'][0], 1024, 65535)
    number(cfg['port_range'][1], cfg['port_range'][0], 65535)
    address = ipaddress.ip_address(cfg['bind_ip'])
    check(address.version == 4 and not address.is_unspecified and not address.is_multicast
          and not address.is_loopback and address.is_private)
    for key, low, high in [('max_projects', 1, 64), ('max_services', 1, 32),
                           ('max_memory_mb', 32, 65536), ('max_cpus', 1, 64),
                           ('max_pids', 16, 4096), ('health_timeout', 10, 1800)]:
        number(cfg[key], low, high)
    for key in ('authorization', 'verification'):
        if key in cfg:
            item = cfg[key]
            fields(item, {'socket', 'service_key'} | ({'agents'} if key == 'authorization' else set()),
                   {'sandbox'} if key == 'authorization' else ())
            for field in ('socket', 'service_key'):
                check(isinstance(item[field], str) and item[field].startswith('/') and '..' not in PurePosixPath(item[field]).parts)
            if key == 'authorization':
                check(isinstance(item['agents'], dict) and 0 <= len(item['agents']) <= 32)
                for agent, keypath in item['agents'].items():
                    name(agent)
                    check(isinstance(keypath, str) and keypath.startswith('/'))
                # Authorization mode forbids broad unsigned exceptions.
                check(all(not image['allow_unsigned'] or image['digests'] for image in cfg['images'].values()))
                if 'sandbox' in item:
                    profile = item['sandbox']
                    fields(profile, {'repositories', 'memory_mb', 'cpus', 'max_services'})
                    check(isinstance(profile['repositories'], list) and profile['repositories']
                          and all(r in cfg['images'] and not cfg['images'][r]['allow_unsigned'] for r in profile['repositories']))
                    number(profile['memory_mb'], 32, cfg['max_memory_mb'])
                    number(profile['cpus'], 1, cfg['max_cpus'])
                    number(profile['max_services'], 1, cfg['max_services'])
    groups = cfg.get('release_groups', [])
    check(isinstance(groups, list) and len(groups) <= 32)
    members = set()
    for group in groups:
        check(isinstance(group, list) and 2 <= len(group) <= cfg['max_services'])
        for service in group:
            name(service)
            check(service not in members)
            members.add(service)
    return cfg


def compile_project(project, spec, cfg):
    name(project)
    fields(spec, {'services'}, {'egress'})
    check(type(spec.get('egress', cfg['allow_egress'])) is bool)
    allowed(not spec.get('egress', cfg['allow_egress']) or cfg['allow_egress'])
    check(isinstance(spec['services'], dict) and len(spec['services']) >= 1)
    resources(len(spec['services']) <= cfg['max_services'])
    for group in cfg.get('release_groups', []):
        # A trusted coordinated group is either absent or complete, including
        # on the very first project declaration, before any human approval.
        allowed(not set(group).intersection(spec['services']) or set(group) <= set(spec['services']))
    services, used_ports = {}, set()
    memory = cpus = 0
    for service, value in spec['services'].items():
        name(service)
        fields(value, {'image', 'memory_mb', 'cpus'}, {'environment', 'mounts', 'ports', 'signed_index'})
        match = IMAGE.fullmatch(value['image']) if isinstance(value['image'], str) else None
        check(match is not None)
        allowed(match[1] in cfg['images'])
        approved = cfg['images'][match[1]]
        if 'signed_index' in value:
            check(isinstance(value['signed_index'], str) and IMAGE.fullmatch(value['signed_index'])
                  and value['signed_index'].split('@')[0] == match[1] and not approved['allow_unsigned'])
        allowed(not approved['digests'] or match[2] in approved['digests'])
        memory += number(value['memory_mb'], 32, 65536)
        cpus += number(value['cpus'], 1, 64)
        resources(value['memory_mb'] <= cfg['max_memory_mb'] and value['cpus'] <= cfg['max_cpus'])
        environment = value.get('environment', {})
        check(isinstance(environment, dict) and len(environment) <= 64)
        for key, val in environment.items():
            allowed(key in approved['environment'])
            check(isinstance(val, str) and len(val) <= 4096 and '\x00' not in val)
        # Compose interpolation is disabled by escaping every literal dollar.
        env = {k: v.replace('$', '$$') for k, v in environment.items()}
        mounts, targets, identities = [], set(), set()
        check(isinstance(value.get('mounts', []), list) and len(value.get('mounts', [])) <= 16)
        for mount in value.get('mounts', []):
            fields(mount, {'storage', 'slot', 'target', 'read_only'})
            check(type(mount['read_only']) is bool)
            allowed(mount['storage'] in cfg['storage'])
            store = cfg['storage'][mount['storage']]
            identities.add((store['uid'], store['gid']))
            allowed(len(identities) == 1)
            name(mount['slot'])
            target = PurePosixPath(mount['target'])
            check(isinstance(mount['target'], str) and re.fullmatch('/[A-Za-z0-9_./-]+', mount['target'])
                  and str(target) == mount['target'] and not str(target).startswith('//')
                  and target.is_absolute() and '..' not in target.parts and str(target) != '/'
                  and not any(str(target) == p or str(target).startswith(p + '/')
                              for p in ('/proc', '/sys', '/dev', '/run', '/var/run')))
            check(all(target != PurePosixPath(other) and target not in PurePosixPath(other).parents
                      and PurePosixPath(other) not in target.parents for other in targets))
            targets.add(str(target))
            source = PurePosixPath(store['path'])
            if store['shared']:
                check(mount['slot'] == 'shared')
            else:
                source = source / project / mount['slot']
            mounts.append({'type': 'bind', 'source': str(source).replace('$', '$$'), 'target': str(target),
                           'read_only': mount['read_only'], 'bind': {'create_host_path': False}})
        ports = []
        check(isinstance(value.get('ports', []), list) and len(value.get('ports', [])) <= 16)
        for port in value.get('ports', []):
            fields(port, {'published', 'target', 'protocol'})
            number(port['published'], 1, 65535)
            allowed(cfg['port_range'][0] <= port['published'] <= cfg['port_range'][1])
            number(port['target'], 1, 65535)
            check(port['protocol'] in ('tcp', 'udp'))
            key = (port['published'], port['protocol'])
            check(key not in used_ports)
            used_ports.add(key)
            ports.append({**port, 'published': str(port['published']), 'host_ip': cfg['bind_ip']})
        services[service] = {'image': value['image'], 'environment': env, 'volumes': mounts,
            'ports': ports, 'mem_limit': str(value['memory_mb']) + 'm', 'cpus': value['cpus'],
            'pids_limit': cfg['max_pids'], 'cap_drop': ['ALL'],
            'security_opt': ['no-new-privileges:true'], 'restart': 'unless-stopped',
            'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '2'}},
            'healthcheck': {'test': ['CMD', *[x.replace('$', '$$') for x in approved['healthcheck']]], 'interval': '10s',
                            'timeout': '5s', 'retries': 3, 'start_period': '20s'}}
        if identities:
            # Match slot ownership without restoring DAC override capabilities.
            uid, gid = next(iter(identities))
            services[service]['user'] = f'{uid}:{gid}'
    resources(memory <= cfg['max_memory_mb'] and cpus <= cfg['max_cpus'])
    return {'services': services, 'networks': {'default': {'internal': not spec.get('egress', cfg['allow_egress'])}}}, {
        'memory_mb': memory, 'cpus': cpus, 'ports': sorted(used_ports)}


def preview(spec):
    # No paths, environment values, healthcheck output, or original Compose.
    return {key: {'image': value['image'], 'environment_keys': sorted(value.get('environment', {})),
                  'mounts': value.get('mounts', []), 'ports': value.get('ports', []),
                  'memory_mb': value['memory_mb'], 'cpus': value['cpus']}
            for key, value in spec['services'].items()}
