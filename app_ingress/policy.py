"""Administrator-only backend registry. Empty bootstrap remains disabled."""
import re
from authorization import agents
from authorization.scope import require
from deployer import schema


def validate(cfg):
    schema.fields(cfg, {'version', 'enabled', 'hostname', 'agents', 'backends'})
    require(cfg['version'] == 1 and type(cfg['enabled']) is bool)
    require(isinstance(cfg['hostname'], str) and (not cfg['hostname'] or re.fullmatch(r'[a-z0-9-]+(?:[.][a-z0-9-]+)*[.]ts[.]net', cfg['hostname'])))
    require(isinstance(cfg['agents'], list) and len(cfg['agents']) <= 32)
    for public in cfg['agents']:
        agents.identity(public)
    require(isinstance(cfg['backends'], dict) and len(cfg['backends']) <= 32)
    ports, local = set(), set()
    for name, backend in cfg['backends'].items():
        schema.name(name)
        schema.fields(backend, {'dns', 'port', 'local_port', 'https_port'})
        # Fixed Docker network alias, never a URL, IP literal, path or control-plane alias.
        require(isinstance(backend['dns'], str) and re.fullmatch(r'app-[a-z][a-z0-9-]{0,40}', backend['dns']))
        schema.number(backend['port'], 1024, 65535)
        schema.number(backend['local_port'], 20000, 29999)
        schema.number(backend['https_port'], 1024, 65535)
        require(backend['https_port'] not in (443, 8443) and backend['https_port'] not in ports)
        require(backend['local_port'] not in local)
        ports.add(backend['https_port']); local.add(backend['local_port'])
    require(not cfg['enabled'] or (cfg['hostname'] and cfg['agents'] and cfg['backends']), 'bootstrap_incomplete')
    return cfg
