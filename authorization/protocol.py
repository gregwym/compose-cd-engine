"""Versioned agent protocol: HMAC binds principal, operation and exact payload."""
import json
from deployer import schema

ROUTES = {'/v2/plans': 'plan', '/v2/deployments': 'apply', '/v2/tasks': 'task',
          '/v2/grant-requests': 'grant_request', '/v2/grant-requests/status': 'grant_status',
          '/v2/grants': 'grants', '/v2/projects': 'projects', '/v2/projects/status': 'status',
          '/v2/projects/start': 'start', '/v2/projects/stop': 'stop',
          '/v2/projects/restart': 'restart', '/v2/projects/diagnose': 'diagnose',
          '/v2/projects/retire': 'retire'}


def request(raw):
    schema.check(len(raw) <= 60000)
    value = json.loads(raw)
    schema.fields(value, {'version', 'agent', 'project', 'operation', 'request_id', 'timestamp', 'payload'})
    schema.check(value['version'] == 2)
    schema.name(value['agent'])
    schema.request(schema.canonical({k: v for k, v in value.items() if k not in ('version', 'agent')}).encode())
    return value
