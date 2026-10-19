"""Data-only, service-specific capabilities. No host paths or environment values."""
from deployer import schema


class Denied(ValueError):
    def __init__(self, category):
        super().__init__(category)
        self.category = category


def require(ok, category='not_authorized'):
    if not ok:
        raise Denied(category)


def scope(spec, cfg):
    services = {}
    for name, value in spec['services'].items():
        repo, digest = value['image'].split('@sha256:')
        image = cfg['images'][repo]
        services[name] = {
            'repository': repo,
            'identity': image.get('identity'),
            'issuer': image.get('issuer'),
            # Unsigned exceptions are always pinned, including in persistent grants.
            'unsigned_digest': digest if image['allow_unsigned'] else None,
            'environment': sorted(value.get('environment', {})),
            'mounts': sorted(value.get('mounts', []), key=schema.canonical),
            'ports': sorted(value.get('ports', []), key=schema.canonical),
            'memory_mb': value['memory_mb'], 'cpus': value['cpus']}
    return {'services': services, 'egress': spec.get('egress', cfg['allow_egress']),
            'operations': sorted(set(cfg['operations']) & {'apply', 'start', 'stop', 'restart', 'diagnose', 'retire'})}


def diff(wanted, approved):
    """A nonempty diff means expansion. Never union unrelated grants implicitly."""
    missing = {}
    for key, value in wanted.items():
        old = approved.get(key) if isinstance(approved, dict) else None
        if isinstance(value, dict):
            nested = diff(value, old or {})
            if nested:
                missing[key] = nested
        elif isinstance(value, list):
            added = [v for v in value if v not in (old or [])]
            # Read-only access is a subset of an otherwise identical writable mount.
            if key == 'mounts':
                added = [v for v in added if not (v['read_only'] and {**v, 'read_only': False} in (old or []))]
            if added:
                missing[key] = added
        elif type(value) is int:
            if type(old) is not int or value > old:
                missing[key] = value
        elif key == 'egress':
            if value and old is not True:
                missing[key] = value
        elif value != old:
            missing[key] = value
    return missing


def sandbox(spec, cfg):
    """Administrator preauthorization: disposable, no ingress/data/egress, signed."""
    profile = cfg.get('authorization', {}).get('sandbox')
    if not profile or spec.get('egress', cfg['allow_egress']):
        return False
    return (len(spec['services']) <= profile['max_services']
            and sum(v['memory_mb'] for v in spec['services'].values()) <= profile['memory_mb']
            and sum(v['cpus'] for v in spec['services'].values()) <= profile['cpus']
            and all(not v.get('mounts') and not v.get('ports')
                    and v['image'].split('@')[0] in profile['repositories']
                    and not cfg['images'][v['image'].split('@')[0]]['allow_unsigned']
                    for v in spec['services'].values()))
