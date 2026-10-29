"""Allowlisted Compose review projection; credentials and executable text stay hidden."""
import difflib
import json
import re

HIDDEN = '[value hidden]'
FIELDS = {'image', 'restart', 'ports', 'expose', 'volumes', 'networks', 'network_mode',
          'read_only', 'privileged', 'cap_add', 'cap_drop', 'devices', 'depends_on',
          'user', 'working_dir', 'init', 'container_name', 'hostname', 'platform'}


def secrets(config):
    found = set()
    for service in (config or {}).get('services', {}).values():
        env = service.get('environment') or {}
        values = env.values() if isinstance(env, dict) else [v.split('=', 1)[1] for v in env if '=' in v]
        found.update(str(v) for v in values if v is not None and str(v))
    return found


def scrub(value, sensitive):
    if isinstance(value, dict):
        return {k: HIDDEN if re.search(r'(?i)password|token|secret|credential', str(k)) else scrub(v, sensitive)
                for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, sensitive) for v in value]
    if isinstance(value, str):
        if value in sensitive:
            return HIDDEN
        for secret in sorted(sensitive, key=len, reverse=True):
            if len(secret) >= 4:
                value = value.replace(secret, HIDDEN)
        if re.search(r'://[^/\s]*@|(?i:password|token|secret|credential)[=:]', value):
            return HIDDEN
    return value


def project(config, sensitive=None):
    config = config or {}
    sensitive = sensitive if sensitive is not None else secrets(config)
    services = {}
    for name, service in sorted((config.get('services') or {}).items()):
        result = {}
        for key, value in sorted(service.items()):
            if key in FIELDS:
                result[key] = scrub(value, sensitive)
            elif key == 'environment' and isinstance(value, dict):
                result[key] = {name: HIDDEN for name in sorted(value)}
            else:
                result[key] = HIDDEN
        services[name] = result
    return {'services': services,
            **{kind: sorted((config.get(kind) or {})) for kind in ('volumes', 'networks', 'secrets', 'configs')
               if config.get(kind)}}


def diff(before, after):
    sensitive = secrets(before) | secrets(after)
    old = json.dumps(project(before, sensitive), indent=2, sort_keys=True).splitlines(True)
    new = json.dumps(project(after, sensitive), indent=2, sort_keys=True).splitlines(True)
    result = ''.join(difflib.unified_diff(old, new, 'current (sensitive values hidden)', 'proposed (sensitive values hidden)'))
    return result or 'Only hidden configuration values or formatting changed.'
