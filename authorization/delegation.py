"""Explicit bounded grants; no ambient union or task-created administrator registry."""
import json
import re
import time
from deployer import schema, registration
from authorization.scope import require

EXCLUSIONS = ['host installation/registry creation', 'image upgrade/pull/build',
              'data deletion', 'arbitrary YAML/environment/paths/commands/namespaces',
              'new public exposure/control routes', 'lifecycle/recovery',
              'logs/environment values/application data']


def envelope(value):
    schema.fields(value, {'agent', 'registration_hash', 'ingress_policy', 'backend', 'backend_hash', 'route', 'max_lifetime'})
    schema.name(value['agent']); schema.name(value['backend'])
    for key in ('registration_hash', 'ingress_policy', 'backend_hash'):
        require(isinstance(value[key], str) and len(value[key]) == 64
                and all(c in '0123456789abcdef' for c in value[key]))
    schema.fields(value['route'], {'hostname', 'https_port', 'root_path'})
    require(value['route']['root_path'] == '/')
    require(isinstance(value['route']['hostname'], str) and
            re.fullmatch(r'[a-z0-9-]+(?:[.][a-z0-9-]+)*[.]ts[.]net', value['route']['hostname']))
    schema.number(value['route']['https_port'],1024,65535)
    require(value['route']['https_port'] not in (443,8443))
    schema.number(value['max_lifetime'], 60, 86400)
    return value


def registered(cfg, project, agent, entry):
    require('task_delegation' in cfg, 'delegation_not_configured')
    # Reuse the root-only, no-symlink loader; this file uses a distinct validator.
    value = registration.load_document(cfg['task_delegation']['registry'])
    schema.fields(value, {'version', 'targets'})
    require(value['version'] == 1 and isinstance(value['targets'], dict) and len(value['targets']) <= 32)
    require(project in value['targets'], 'target_not_registered')
    result = envelope(value['targets'][project])
    require(result['agent'] == agent and result['registration_hash'] == schema.fingerprint(entry), 'registration_drift')
    return result


def scope(project, entry, registered):
    from deployer.transactions import Broker
    return {'type': 'registered_task_v1', 'project': project,
            'operations': ['inspect', 'adoption_observe'] + (['adoption_redeploy'] if entry['allow_redeploy'] else []) + ['shared_ingress_apply'],
            'adoption': Broker.wanted(project, 'observe', entry),
            'identities': [{k:r[k] for k in ('name','service','image_id','mounts','ports','networks')}
                           for r in entry['baseline']['containers']],
            'envelope': registered, 'exclusions': EXCLUSIONS,
            'diagnostics': 'repeat structural inspect (including paths and state); no logs/env values',
            'mode': 'bounded task; repeat supported subplans until expiry or revocation'}


def authorize(store, value):
    schema.fields(value, {'delegation_id', 'agent', 'project', 'kind', 'policy', 'scope', 'plan', 'task'}, {'envelope'})
    require(value['kind'] in ('inspect', 'adoption', 'ingress'))
    for key in ('delegation_id', 'plan', 'task'):
        require(isinstance(value[key], str) and schema.HEX.fullmatch(value[key]))
    with store.db() as db:
        store.require_active_agent(db, value['agent'])
        row = db.execute("SELECT * FROM grants WHERE id=? AND agent=? AND status='active' AND mode='expiring' AND expires>?",
                         (value['delegation_id'], value['agent'], int(time.time()))).fetchone()
        require(row and row['credential'] and db.execute('SELECT 1 FROM credentials WHERE id=? AND active=1', (row['credential'],)).fetchone())
        approved = json.loads(row['scope'])
        require(approved.get('type') == 'registered_task_v1' and approved['project'] == value['project'] == row['project'])
        env = envelope(approved['envelope'])
        require(env['agent'] == value['agent'])
        if value['kind'] == 'ingress':
            wanted = value['scope']
            require(value['policy'] == env['ingress_policy'])
            require(wanted['operations'] == ['shared_ingress_apply'] and wanted['backend'] == env['backend']
                    and wanted['backend_hash'] == env['backend_hash'] and wanted['route'] == env['route']
                    and wanted['tailnet_only'] is True and wanted['no_app_redeploy'] is True and wanted['recovery_of'] is None)
        else:
            require(value.get('envelope') == env, 'registration_drift')
            require(value['policy'] == row['policy'])
            if value['kind'] == 'inspect':
                require(value['scope'] == approved)
            else:
                wanted = dict(value['scope'])
                require(len(wanted['operations']) == 1 and wanted['operations'][0] in approved['operations'])
                wanted['operations'] = ['adoption_observe']
                require(wanted == approved['adoption'])
        binding = schema.fingerprint(value)
        previous = db.execute('SELECT binding FROM delegation_receipts WHERE task=?', (value['task'],)).fetchone()
        require(not previous or previous[0] == binding, 'stale_request')
        if not previous:
            db.execute('INSERT INTO delegation_receipts VALUES (?,?,?)', (value['task'], row['id'], binding))
            store.event(db, value['agent'], 'delegated_' + value['kind'], value['task'],
                        {'delegation_id': row['id'], 'plan': value['plan'], 'binding': binding})
        return {'status': 'authorized', 'grant_id': row['id']}
