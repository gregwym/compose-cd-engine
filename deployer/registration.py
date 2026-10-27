"""Administrator-owned canonical registrations. No caller YAML or file references."""
import json
import os
import stat
import re
from deployer import schema
from deployer.adoption import adoption_preview, path
from authorization.scope import require
from management.protocol import protected_file


def load(filename):
    file = protected_file(filename)
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077)
        require(info.st_size <= 1048576)
        raw = os.read(fd, 1048577)
        require(len(raw) <= 1048576)
        value = json.loads(raw)
    finally:
        os.close(fd)
    schema.fields(value, {'version', 'targets'})
    require(value['version'] == 1 and isinstance(value['targets'], dict) and len(value['targets']) <= 32)
    for project, entry in value['targets'].items():
        validate(project, entry)
    return value


def validate(project, entry):
    schema.name(project)
    schema.fields(entry, {'baseline', 'compose', 'declaration_hash', 'allow_redeploy', 'health_timeout'})
    baseline, compose = entry['baseline'], entry['compose']
    require(baseline['project'] == project)
    adoption_preview(baseline)
    require(isinstance(baseline['containers'],list) and 1<=len(baseline['containers'])<=32)
    for row in baseline['containers']:
        require(isinstance(row['container_id'],str) and re.fullmatch('[a-f0-9]{64}',row['container_id']))
        require(isinstance(row['image_id'],str) and re.fullmatch('sha256:[a-f0-9]{64}',row['image_id']))
        require(row['project']==project)
        schema.name(row['service'])
        path(row['working_dir'])
        require(isinstance(row['config_files'],list) and 1<=len(row['config_files'])<=8)
        for filename in row['config_files']: path(filename)
    require(type(entry['allow_redeploy']) is bool)
    schema.number(entry['health_timeout'], 10, 1800)
    schema.fields(compose, {'services', 'networks'})
    require(entry['declaration_hash'] == schema.fingerprint(compose), 'declaration_drift')
    rows = {r['service']: r for r in baseline['containers']}
    require(set(compose['services']) == set(rows) and rows)
    schema.check(isinstance(compose['networks'], dict))
    network_names = set()
    for alias, cfg in compose['networks'].items():
        schema.name(alias)
        schema.fields(cfg, {'external', 'name'})
        require(cfg['external'] is True)
        network_names.add(cfg['name'])
    require(network_names == {n for r in rows.values() for n in r['networks']})
    for service, cfg in compose['services'].items():
        schema.name(service)
        schema.fields(cfg, {'image', 'container_name', 'volumes', 'ports', 'networks'},
                      {'environment', 'restart', 'user', 'cap_add', 'cap_drop', 'security_opt',
                       'healthcheck', 'mem_limit', 'cpus', 'pids_limit', 'read_only', 'init', 'stop_grace_period'})
        row = rows[service]
        require(not cfg.get('cap_add'), 'capability_expansion_forbidden')
        require(set(cfg.get('cap_drop',[])) <= {'ALL'}, 'unsupported_security_options')
        require(set(cfg.get('security_opt',[])) <= {'no-new-privileges:true'}, 'unsupported_security_options')
        require(cfg['image'] == row['image_id'] and cfg['container_name'] == row['name'], 'identity_drift')
        require(isinstance(cfg['networks'], list) and all(n in compose['networks'] for n in cfg['networks']))
        require({compose['networks'][n]['name'] for n in cfg['networks']} == set(row['networks']))
        volumes = []
        schema.check(isinstance(cfg['volumes'], list) and len(cfg['volumes']) <= 32)
        for mount in cfg['volumes']:
            schema.fields(mount, {'type', 'source', 'target', 'read_only', 'bind'})
            require(mount['type'] == 'bind')
            path(mount['source']); path(mount['target'])
            for prefix in ('/etc','/proc','/sys','/dev','/run','/var/run','/root','/usr','/bin','/sbin','/lib'):
                require(mount['source']!=prefix and not mount['source'].startswith(prefix+'/'),'protected_mount')
            require(mount['source']!='/','protected_mount')
            require('docker.sock' not in mount['source'] and 'containerd.sock' not in mount['source'])
            require(type(mount['read_only']) is bool)
            require(mount['bind'] == {'create_host_path': False})
            volumes.append({k:mount[k] for k in ('type','source','target','read_only')})
        require(sorted(volumes,key=schema.canonical) == sorted(row['mounts'],key=schema.canonical), 'mount_drift')
        require(isinstance(cfg['ports'], list) and len(cfg['ports']) <= 64)
        ports = []
        for port in cfg['ports']:
            schema.fields(port, {'target','published','host_ip','protocol'})
            schema.number(port['target'],1,65535); schema.number(port['published'],1,65535)
            require(port['protocol'] in ('tcp','udp','sctp'))
            ports.append({'target': str(port['target'])+'/'+port['protocol'], 'published':port['published'],'host_ip':port['host_ip']})
        require(sorted(ports,key=schema.canonical) == row['ports'], 'port_drift')
        env = cfg.get('environment', {})
        require(isinstance(env,dict) and len(env)<=128)
        for k,v in env.items():
            require(isinstance(k,str) and isinstance(v,str) and len(k)<=128 and len(v)<=8192)
        if entry['allow_redeploy']:
            probe = cfg.get('healthcheck')
            schema.check(isinstance(probe, dict))
            schema.fields(probe, {'test', 'interval', 'timeout', 'retries', 'start_period'})
            test = probe['test']
            require(isinstance(test,list) and len(test)>1 and test[0]=='CMD'
                    and all(isinstance(v,str) and 0<len(v)<=1024 for v in test))
            require(test[1] not in ('true','/bin/true'), 'invalid_readiness')
        require('$' not in schema.canonical(cfg), 'interpolation_forbidden')
    return entry
