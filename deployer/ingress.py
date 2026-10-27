"""Offline, fail-closed Serve candidate generation, not a remote apply API.

Administrator supplies allowed local upstreams; callers cannot select arbitrary
network destinations. Never changes deployed Serve configuration.
"""
import copy
import re
from urllib.parse import urlsplit
from deployer import schema
from authorization.scope import require


def plan(current, *, hostname, port, upstream, allowed_upstreams):
    schema.check(isinstance(current, dict))
    schema.check(isinstance(hostname, str) and re.fullmatch(r'[a-z0-9-]+(?:[.][a-z0-9-]+)*[.]ts[.]net', hostname))
    schema.number(port, 1024, 65535)
    require(port not in (443, 8443), 'reserved_control_plane_port')
    require(isinstance(allowed_upstreams, (list, tuple)) and upstream in allowed_upstreams)
    url = urlsplit(upstream)
    require(url.scheme == 'http' and url.hostname in ('127.0.0.1', 'localhost') and url.port
            and not url.username and not url.password and not url.query and not url.fragment
            and url.path in ('', '/'), 'unsupported_upstream')
    schema.number(url.port, 1024, 65535)
    # Control plane targets must never become application upstreams.
    require(url.port not in (18792, 18793), 'reserved_control_plane_upstream')
    require(set(current) <= {'TCP', 'Web', 'AllowFunnel'}, 'unsupported_serve_config')
    for section in ('TCP', 'Web', 'AllowFunnel'):
        schema.check(isinstance(current.get(section, {}), dict))
    # Refuse a public baseline, do not silently "repair" it.
    require(not any(current.get('AllowFunnel', {}).values()), 'public_ingress_forbidden')
    key = hostname + ':' + str(port)
    require(str(port) not in current.get('TCP', {}) and key not in current.get('Web', {}), 'route_conflict')
    candidate = copy.deepcopy(current)
    candidate.setdefault('TCP', {})[str(port)] = {'HTTPS': True}
    candidate.setdefault('Web', {})[key] = {'Handlers': {'/': {'Proxy': upstream}}}
    return {'baseline_hash': schema.fingerprint(current), 'candidate': candidate,
            'candidate_hash': schema.fingerprint(candidate), 'execute_allowed': False,
            'scope': {'operation': 'ingress_change', 'hostname': hostname, 'https_port': port,
                      'upstream': upstream, 'tailnet_only': True},
            'blockers': ['dedicated shared application ingress must be administrator provisioned',
                         'upstream must exist inside the ingress network namespace',
                         'separate Passkey-bound ingress apply is not implemented']}


def reconcile(candidate_plan, current, *, allowed_upstreams):
    require(candidate_plan['baseline_hash'] == schema.fingerprint(current), 'ingress_drift')
    wanted = candidate_plan['scope']
    schema.fields(wanted, {'operation', 'hostname', 'https_port', 'upstream', 'tailnet_only'})
    require(wanted['operation'] == 'ingress_change' and wanted['tailnet_only'] is True)
    rebuilt = plan(current, hostname=wanted['hostname'], port=wanted['https_port'],
                   upstream=wanted['upstream'], allowed_upstreams=allowed_upstreams)
    require(candidate_plan == rebuilt, 'ingress_drift')
    return copy.deepcopy(rebuilt['candidate'])
