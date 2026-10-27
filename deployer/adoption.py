"""Read-only adoption foundation. No Compose execution or host file reads.

The baseline is evidence, not an executable declaration or management grant.
"""
import json
import re
import time
from pathlib import PurePosixPath
from deployer import schema
from authorization.scope import require

LABEL = 'com.docker.compose.'
FIELDS = ['container_id', 'name', 'project', 'service', 'image', 'image_id',
          'working_dir', 'config_files', 'mounts', 'ports', 'networks', 'state']
# Explicit projection in Docker itself; never deserialize Config.Env or full inspect.
FORMAT = ('{"container_id":{{json .Id}},"name":{{json .Name}},'
          '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
          '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
          '"working_dir":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}},'
          '"config_files":{{json (index .Config.Labels "com.docker.compose.project.config_files")}},'
          '"image":{{json .Config.Image}},"image_id":{{json .Image}},'
          '"state":{{json .State.Status}},"mounts":{{json .Mounts}},'
          '"ports":{{json .NetworkSettings.Ports}},'
          '"networks":[{{range $i,$v := .NetworkSettings.Networks}}{{json $i}},{{end}}null]}')


def inspection_scope(project):
    schema.name(project)
    require(project != 'nas-inventory' and not project.startswith('cdp-'))
    return {'operations': ['inspect'], 'read_only': True, 'project': project,
            'fields': FIELDS, 'coverage': 'one existing Compose project; includes host paths',
            'management_access': False}


def inspection_policy(project):
    return schema.fingerprint({'version': 1, 'scope': inspection_scope(project)})


def text(value, maximum=512):
    schema.check(isinstance(value, str) and 0 < len(value) <= maximum
                 and all(c.isprintable() for c in value))
    return value


def path(value):
    text(value, 1024)
    p = PurePosixPath(value)
    schema.check(p.is_absolute() and '..' not in p.parts)
    return value


def project_name(value):
    text(value, 128)
    schema.check(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', value))
    return value


def inspect_project(docker, project, *, budget=6):
    inspection_scope(project)
    deadline = time.monotonic() + budget
    query = docker
    def docker(*args):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'inspection_timeout')
        result = query(*args, timeout=remaining)
        require(time.monotonic() < deadline, 'inspection_timeout')
        return result
    ids = docker('ps', '--all', '--no-trunc', '--quiet', '--last', '33', '--filter',
                 'label=' + LABEL + 'project=' + project).decode().split()
    require(0 < len(ids) <= 32, 'unsupported_project')
    schema.check(len(set(ids)) == len(ids) and all(re.fullmatch('[a-f0-9]{64}', i) for i in ids))
    rows = []
    for cid in sorted(ids):
        raw = docker('inspect', '--format', FORMAT, cid)
        schema.check(len(raw) <= 32768)
        row = json.loads(raw)
        schema.fields(row, set(FIELDS))
        require(row['project'] == project and row['container_id'] == cid, 'identity_drift')
        row['name'] = project_name(row['name'].removeprefix('/'))
        project_name(row['service']); text(row['image'], 256)
        schema.check(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:@-]*', row['image']) and '://' not in row['image'])
        schema.check(re.fullmatch('sha256:[a-f0-9]{64}', row['image_id']))
        path(row['working_dir'])
        row['config_files'] = [path(p) for p in text(row['config_files'], 4096).split(',')]
        require(len(row['config_files']) <= 8, 'unsupported_project')
        require(row['state'] in ('created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead'))
        mounts = []
        schema.check(isinstance(row['mounts'], list) and len(row['mounts']) <= 32)
        for mount in row['mounts']:
            kind = mount['Type']
            require(kind in ('bind', 'volume', 'tmpfs'), 'unsupported_project')
            mounts.append({'type': kind, 'source': path(mount['Source']) if kind != 'tmpfs' else None,
                           'target': path(mount['Destination']), 'read_only': not mount['RW']})
            schema.check(type(mount['RW']) is bool)
        row['mounts'] = mounts
        ports = []
        schema.check(isinstance(row['ports'], dict) and len(row['ports']) <= 64)
        for target, bindings in row['ports'].items():
            schema.check(re.fullmatch(r'[0-9]{1,5}/(tcp|udp|sctp)', target))
            schema.number(int(target.split('/')[0]), 1, 65535)
            schema.check(bindings is None or isinstance(bindings, list) and len(bindings) <= 16)
            for binding in bindings or []:
                import ipaddress
                host = str(ipaddress.ip_address(binding['HostIp']))
                published = int(binding['HostPort']); schema.number(published, 1, 65535)
                ports.append({'target': target, 'host_ip': host, 'published': published})
        row['ports'] = sorted(ports, key=schema.canonical)
        schema.check(isinstance(row['networks'], list) and len(row['networks']) <= 33)
        row['networks'] = sorted(project_name(n) for n in row['networks'] if n is not None)
        rows.append(row)
    # Reconcile membership after inspection; never pass a changed baseline onward.
    after = docker('ps', '--all', '--no-trunc', '--quiet', '--last', '33', '--filter',
                   'label=' + LABEL + 'project=' + project).decode().split()
    require(sorted(ids) == sorted(after), 'identity_drift')
    baseline = {'project': project, 'containers': rows}
    schema.check(len(schema.canonical(baseline)) <= 49152)
    return {**baseline, 'baseline_hash': schema.fingerprint(baseline), 'read_only': True,
            'managed_access_granted': False, 'adoption_ready': False,
            'blockers': ['administrator-reviewed original Compose required',
                         'separate immutable adoption approval required',
                         'administrator target registration required before adoption transaction']}


def validate_inspection_baseline(baseline):
    """Validate read-only structure without imposing adoption eligibility."""
    schema.check(isinstance(baseline,dict))
    inspection_scope(baseline['project'])
    rows = baseline['containers']
    schema.check(isinstance(rows,list) and 1<=len(rows)<=32)
    ids,names=set(),set()
    for row in rows:
        schema.fields(row,set(FIELDS))
        require(row['project']==baseline['project'],'identity_drift')
        schema.check(isinstance(row['container_id'],str) and re.fullmatch('[a-f0-9]{64}',row['container_id']))
        schema.check(isinstance(row['image_id'],str) and re.fullmatch('sha256:[a-f0-9]{64}',row['image_id']))
        project_name(row['name']); project_name(row['service']); text(row['image'],256)
        schema.check(row['container_id'] not in ids and row['name'] not in names)
        ids.add(row['container_id']); names.add(row['name'])
        path(row['working_dir'])
        schema.check(isinstance(row['config_files'],list) and 1<=len(row['config_files'])<=8)
        for item in row['config_files']: path(item)
        schema.check(isinstance(row['mounts'],list) and len(row['mounts'])<=32)
        for mount in row['mounts']:
            schema.fields(mount,{'type','source','target','read_only'})
            require(mount['type'] in ('bind','volume','tmpfs'))
            path(mount['target'])
            if mount['type']!='tmpfs': path(mount['source'])
            else: require(mount['source'] is None)
            schema.check(type(mount['read_only']) is bool)
        schema.check(isinstance(row['ports'],list) and len(row['ports'])<=1024)
        for port in row['ports']:
            schema.fields(port,{'target','published','host_ip'})
            schema.check(re.fullmatch(r'[0-9]{1,5}/(tcp|udp|sctp)',port['target']))
            schema.number(int(port['target'].split('/')[0]),1,65535)
            schema.number(port['published'],1,65535)
            import ipaddress
            ipaddress.ip_address(port['host_ip'])
        schema.check(isinstance(row['networks'],list) and len(row['networks'])<=32)
        for network in row['networks']: project_name(network)
        require(row['state'] in ('created','running','paused','restarting','removing','exited','dead'))
    expected={'project':baseline['project'],'containers':rows}
    require(baseline['baseline_hash']==schema.fingerprint(expected),'baseline_drift')
    return baseline


def validate_baseline(baseline):
    """Adoption requires one container per Compose service in addition to valid structure."""
    validate_inspection_baseline(baseline)
    services = [row['service'] for row in baseline['containers']]
    schema.check(len(services) == len(set(services)))
    return baseline


def adoption_preview(baseline):
    """Immutable comparison evidence only, intentionally not executable."""
    validate_baseline(baseline)
    identities = {(r['working_dir'], tuple(r['config_files'])) for r in baseline['containers']}
    require(len(identities) == 1 and len({r['service'] for r in baseline['containers']}) == len(baseline['containers']),
            'ambiguous_compose_identity')
    return {'project': baseline['project'], 'baseline_hash': baseline['baseline_hash'],
            'preserve_project_identity': True, 'preserve_mounts': True,
            'preserve_image_ids': True, 'execute_allowed': False,
            'required_approval': 'new adoption transaction; inspect grants are insufficient'}
