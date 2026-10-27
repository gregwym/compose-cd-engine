"""Versioned agent protocol: HMAC binds principal, operation and exact payload."""
import json
from deployer import schema

ROUTES = {'/v2/delegation/requests': 'delegation_request', '/v2/plans': 'plan', '/v2/deployments': 'apply', '/v2/tasks': 'task',
          '/v2/grant-requests': 'grant_request', '/v2/grant-requests/status': 'grant_status',
          '/v2/grants': 'grants', '/v2/projects': 'projects', '/v2/projects/status': 'status',
          '/v2/projects/start': 'start', '/v2/projects/stop': 'stop',
          '/v2/projects/restart': 'restart', '/v2/projects/diagnose': 'diagnose',
          '/v2/projects/retire': 'retire', '/v2/inventory': 'inventory',
          '/v2/inventory-requests': 'inventory_request',
          '/v2/projects/inspect': 'inspect', '/v2/projects/inspect-requests': 'inspect_request',
          '/v2/adoption/plans': 'adoption_plan', '/v2/adoption/requests': 'adoption_request',
          '/v2/adoption/apply': 'adoption_apply', '/v2/adoption/tasks': 'adoption_task'}


def request(raw):
    schema.check(len(raw) <= 60000)
    value = json.loads(raw)
    schema.fields(value, {'version', 'agent', 'project', 'operation', 'request_id', 'timestamp', 'payload'}, {'public_key', 'audience'})
    schema.check(value['version'] == 2)
    schema.name(value['agent'])
    if 'public_key' in value:
        from authorization.agents import identity
        schema.check(identity(value['public_key']) == value['agent'])
        schema.check(isinstance(value.get('audience'), str) and 0 < len(value['audience']) <= 253)
    else:
        schema.check('audience' not in value)
    schema.request(schema.canonical({k: v for k, v in value.items() if k not in ('version', 'agent', 'public_key', 'audience')}).encode())
    return value
