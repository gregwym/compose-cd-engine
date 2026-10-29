"""Fail-closed reusable project boundaries; no implicit host or foreign resource access."""
import json
import os
import re
from pathlib import Path
from runner import policy, compose
from shared.wire import Denied


def canonical(boundary, deploy_root):
    if not isinstance(boundary, dict) or set(boundary) - {'mounts', 'networks'}:
        raise Denied('invalid_boundary')
    mounts = boundary.get('mounts', [])
    networks = boundary.get('networks', [])
    if not isinstance(mounts, list) or len(mounts) > 32 or not isinstance(networks, list):
        raise Denied('invalid_boundary')
    result = []
    for item in mounts:
        if not isinstance(item, dict) or set(item) != {'path', 'mode'}:
            raise Denied('invalid_boundary')
        path, mode = item['path'], item['mode']
        if (not isinstance(path, str) or not path.startswith('/') or mode not in ('ro', 'rw')
                or os.path.realpath(path) != path or not Path(path).is_dir()
                or policy.forbidden_source(path, deploy_root)):
            raise Denied('unsafe_boundary', 'mount roots must be visible canonical safe directories')
        result.append({'path': path, 'mode': mode})
    if any(not isinstance(n, str) or not compose.SERVICE.fullmatch(n) for n in networks):
        raise Denied('invalid_boundary')
    return {'mounts': sorted(result, key=lambda m: (m['path'], m['mode'])), 'networks': sorted(set(networks))}


def source(path, readonly, boundary):
    if not isinstance(path, str) or not path.startswith('/') or os.path.realpath(path) != path:
        raise Denied('boundary_exceeded', 'noncanonical or symlink mount source')
    # Require visibility: the runner must actually be able to check host symlinks.
    if not Path(path).exists():
        raise Denied('boundary_exceeded', 'mount source must exist and be visible to runner')
    if not any(policy.under(path, m['path']) and (readonly or m['mode'] == 'rw') for m in boundary['mounts']):
        raise Denied('boundary_exceeded', 'mount root or write access needs owner approval')


def preflight(data):
    """Reject file-loading Compose features BEFORE Compose reads them.

    Conservative lexical gate (including quoted/escaped YAML keys): reusable
    configs use the ordinary, unescaped YAML/JSON subset. No new YAML dependency.
    """
    text = data.decode() if isinstance(data, bytes) else data
    if chr(92) in text or re.search(r'(?m)^\s*%|!!|!<|[&*][A-Za-z_]', text):
        raise Denied('unsupported_compose', 'escaped keys, YAML tags and aliases are not supported')
    forbidden = ('include', 'extends', 'env_file', 'label_file', 'file', 'build', 'credential_spec', 'provider', 'post_start', 'pre_stop')
    for key in forbidden:
        if re.search(r'(?<![A-Za-z0-9_])' + re.escape(key) + r'''['"]?\s*:''', text):
            raise Denied('unsupported_compose', key + ' is not supported in reusable configurations')


def check(config, identity, boundary, deploy_root):
    boundary = canonical(boundary, deploy_root)
    errors = policy.violations(config, deploy_root)
    if errors:
        raise Denied('policy', errors)
    project = identity['project']
    for kind in ('secrets', 'configs'):
        if config.get(kind):
            raise Denied('policy', kind + ' are not supported by reusable grants')
    for kind in ('volumes', 'networks'):
        for key, spec in (config.get(kind) or {}).items():
            spec = spec or {}
            name = spec.get('name', project + '_' + key)
            external = spec.get('external', False)
            if spec.get('driver_opts') or spec.get('driver') not in (None, 'local' if kind == 'volumes' else 'bridge'):
                raise Denied('policy', 'custom resource drivers/options are not supported')
            if external and kind == 'networks' and name in boundary['networks']:
                continue
            if external:
                raise Denied('boundary_exceeded', 'external resource is not authorized')
            # Prefixes alone are not ownership: check existing Docker resource labels.
            resource = kind[:-1]
            ids = compose.run([compose.DOCKER, resource, 'ls', '--format', '{{.Name}}']).decode().splitlines()
            if name not in ids and name != project + '_' + key:
                raise Denied('boundary_exceeded', 'custom resource must already exist and belong to project')
            if name in ids:
                inspected = json.loads(compose.run([compose.DOCKER, resource, 'inspect', name]))[0]
                if (inspected.get('Labels') or {}).get(compose.LABEL + 'project') != project:
                    raise Denied('boundary_exceeded', 'existing resource belongs to another project')
                expected_driver = 'local' if resource == 'volume' else 'bridge'
                if inspected.get('Driver') != expected_driver or inspected.get('Options'):
                    raise Denied('policy', 'existing resource has unsupported driver/options')
    for service in (config.get('services') or {}).values():
        if any(service.get(k) for k in ('provider', 'post_start', 'pre_stop', 'storage_opt', 'sysctls', 'gpus', 'credential_spec')):
            raise Denied('policy', 'host integration or lifecycle hooks are not supported')
        if (((service.get('deploy') or {}).get('resources') or {}).get('reservations') or {}).get('devices'):
            raise Denied('policy', 'device reservations are not supported')
        for spec in (service.get('networks') or {}).values() if isinstance(service.get('networks'), dict) else []:
            if spec and spec.get('driver_opts'):
                raise Denied('policy', 'network driver options are not supported')
        if service.get('cap_add') or service.get('devices') or service.get('device_cgroup_rules') or service.get('volumes_from'):
            raise Denied('policy', 'host capabilities, devices and inherited volumes are not supported')
        if service.get('network_mode') not in (None, 'none'):
            raise Denied('policy', 'host/container/service network namespaces are not supported')
        if any(service.get(k) not in (None, 'private') for k in ('pid', 'ipc', 'uts', 'userns_mode', 'cgroup')):
            raise Denied('policy', 'shared namespaces are not supported')
        if service.get('security_opt'):
            raise Denied('policy', 'custom security profiles are not supported')
        for mount in service.get('volumes') or []:
            if not isinstance(mount, dict) or mount.get('type') not in ('bind', 'volume', 'tmpfs'):
                raise Denied('policy', 'unsupported mount')
            if mount.get('type') == 'bind':
                source(mount.get('source'), bool(mount.get('read_only')), boundary)
                if (mount.get('bind') or {}).get('propagation') not in (None, 'rprivate'):
                    raise Denied('policy', 'shared mount propagation')
            if mount.get('type') == 'volume' and mount.get('source') not in (config.get('volumes') or {}):
                raise Denied('policy', 'undeclared volume')
    return boundary
