#!/usr/bin/env python3
"""Disposable real-container install test with a simulated Tailscale LocalAPI.

Requires CD_DISPOSABLE_CI=1 and a same-path mount of /run/compose-cd-synology-smoke.
Never logs enrollment codes or connects a device to a real tailnet.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def main():
    if os.environ.get('CD_DISPOSABLE_CI') != '1':
        raise SystemExit('disposable CI only')
    base = Path('/run/compose-cd-synology-smoke')
    base.mkdir(exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='install-', dir=base))
    name = root.name
    image = os.environ.get('CD_SMOKE_IMAGE', 'compose-cd-engine:test')
    source = Path(os.environ.get('CD_SOURCE', '/src'))
    model = json.loads(subprocess.check_output(['docker', 'compose', '-f', str(source / 'synology/compose.yaml'), 'config', '--format', 'json']))
    model['name'] = name
    for network in model.get('networks', {}).values():
        network['name'] = name + '-private'
    services = model['services']
    assert len(services) == 7 and all(not s.get('ports') for s in services.values())
    assert services['runner']['network_mode'] == 'none'
    assert [n for n, s in services.items() if any(v.get('source') == '/var/run/docker.sock' for v in s.get('volumes', []))] == ['runner']
    assert all(s.get('read_only') and s['cap_drop'] == ['ALL'] for n, s in services.items() if n != 'tailscale')
    assert '--listen' in services['approval']['command'] and '--listen' in services['management']['command']
    for service_name, service in services.items():
        if service_name != 'tailscale':
            service['image'] = image
        for volume in service.get('volumes', []):
            host = volume.get('source', '')
            for prefix in ('/volume1/docker/compose-deployer', str(source / 'synology')):
                if host == prefix or host.startswith(prefix + '/'):
                    volume['source'] = str(root / 'project') + host[len(prefix):]
                    break
    project = root / 'project'
    project.mkdir()
    control = root / 'control'
    control.mkdir()
    fake = root / 'fake.py'
    fake.write_text('''import http.server, socketserver, json
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self, *args): pass
 def do_GET(self):
  raw=json.dumps({"BackendState":"Running" if Path("/control/logged-in").exists() else "NeedsLogin", "Self":{"DNSName":"deployer.tail123.ts.net."}, "CertDomains":["deployer.tail123.ts.net"]}).encode()
  self.send_response(200); self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
path=Path("/var/run/tailscale/tailscaled.sock")
if path.exists(): path.unlink()
with socketserver.UnixStreamServer(str(path), Handler) as server: server.serve_forever()
''')
    ts = services['tailscale']
    ts['image'] = image
    ts['entrypoint'] = ['python3', '/integration/fake.py']
    ts['volumes'] += [{'type': 'bind', 'source': str(fake), 'target': '/integration/fake.py', 'read_only': True},
                      {'type': 'bind', 'source': str(control), 'target': '/control', 'read_only': True}]
    ts.pop('environment', None)
    config = root / 'compose.json'
    config.write_text(json.dumps(model))
    command = ['docker', 'compose', '-p', name, '-f', str(config)]

    def compose(*args):
        try:
            return subprocess.check_output([*command, *args], stderr=subprocess.STDOUT).decode()
        except subprocess.CalledProcessError as error:
            if args[0] in ('up', 'run'):
                print(error.output.decode(), flush=True)
            raise

    def execute(service, *args):
        return compose('exec', '-T', service, *args)

    def wait(check, description, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(1)
        raise RuntimeError('timeout: ' + description)

    def healthy():
        rows = [json.loads(line) for line in compose('ps', '--format', 'json').splitlines() if line]
        return {x['Service'] for x in rows if x.get('Health') == 'healthy'} >= {'configure', 'approval', 'management', 'runner', 'project-verifier'}

    try:
        compose('up', '-d')
        assert not (project / 'config/approval/policy.json').exists(), 'must wait for login'
        wait(lambda: 'Waiting for Tailscale' in compose('logs', '--no-color', 'approval'), 'approval wait message')
        (control / 'logged-in').touch()
        wait(healthy, 'all five application readiness checks')
        print('PASS: login wait → automatic domain → five healthy services', flush=True)
        cfg = json.loads((project / 'config/approval/policy.json').read_text())
        assert cfg['rp_id'] == 'deployer.tail123.ts.net'
        code_logs = compose('logs', '--no-color', 'approval')
        codes = [line.split('administrator only): ', 1)[1] for line in code_logs.splitlines() if 'administrator only): ' in line]
        assert codes
        # Exercise the existing real WebAuthn verifier over HTTP in the shared
        # namespace. HTTPS certificate issuance remains a separate on-device test.
        ceremony = '''import http.client,json,sys
sys.path.insert(0,"/integration/tests")
from test_authorization import Authenticator
origin="https://deployer.tail123.ts.net"
auth=Authenticator()
cookie=""
csrf=""
def call(path,body=None):
 global cookie,csrf
 c=http.client.HTTPConnection("127.0.0.1",18793,timeout=5)
 headers={"Host":"deployer.tail123.ts.net","Origin":origin,"Cookie":cookie,"X-CSRF-Token":csrf,"Content-Type":"application/json"}
 c.request("GET" if body is None else "POST",path,None if body is None else json.dumps(body),headers)
 r=c.getresponse(); data=json.loads(r.read()); assert r.status==200,(r.status,data)
 if r.getheader("Set-Cookie"): cookie=r.getheader("Set-Cookie").split(";")[0]
 c.close(); return data
csrf=call("/api/session")["csrf"]
token=sys.stdin.read().strip()
start=call("/api/begin",{"action":"enroll","target":"","token":token})
call("/api/finish",{"ceremony_id":start["ceremony_id"],"response":auth.response(start,register=True,origin=origin,rp="deployer.tail123.ts.net")})
start=call("/api/begin",{"action":"login","target":""})
call("/api/finish",{"ceremony_id":start["ceremony_id"],"response":auth.response(start,origin=origin,rp="deployer.tail123.ts.net")})
assert call("/api/session")["authenticated"]
'''
        runner = services['approval']
        fixtures = root / 'auth-fixtures'
        shutil.copytree(source / 'tests', fixtures, ignore=shutil.ignore_patterns('__pycache__'))
        fixtures.chmod(0o755)
        for item in fixtures.rglob('*'):
            item.chmod(0o755 if item.is_dir() else 0o644)
        test_mount = {'type': 'bind', 'source': str(fixtures), 'target': '/integration/tests', 'read_only': True}
        runner['volumes'].append(test_mount)
        config.write_text(json.dumps(model))
        compose('up', '-d', '--no-deps', 'approval')
        wait(healthy, 'approval recreated with test authenticator')
        # Restart rotated the first-owner code; get the current code privately.
        code_logs = compose('logs', '--no-color', 'approval')
        code = [line.split('administrator only): ', 1)[1] for line in code_logs.splitlines() if 'administrator only): ' in line][-1]
        subprocess.run([*command, 'exec', '-T', 'approval', 'python3', '-c', ceremony], input=code.encode(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print('PASS: actual WebAuthn enrollment + login through packaged approval HTTP service', flush=True)
        keys = {str(p.relative_to(project)): hashlib.sha256(p.read_bytes()).hexdigest() for p in project.glob('config/**/key')}
        identity = project / 'state/approval/authorization.sqlite'
        sentinel = project / 'apps/downloads/retained-media'
        sentinel.write_bytes(b'retain app data')
        compose('run', '--rm', '--no-deps', 'init')
        assert keys == {str(p.relative_to(project)): hashlib.sha256(p.read_bytes()).hexdigest() for p in project.glob('config/**/key')}
        import sqlite3
        with sqlite3.connect(identity) as database:
            assert database.execute('SELECT count(*) FROM credentials WHERE active=1').fetchone()[0] == 1
        assert sentinel.read_bytes() == b'retain app data'
        # Restart all services, including Tailscale network namespace consumer.
        compose('restart')
        wait(healthy, 'whole-project restart')
        logs = compose('logs', '--no-color', 'approval')
        assert logs.count('Single-use enrollment code') == code_logs.count('Single-use enrollment code'), 'must not reopen enrollment for an existing identity'
        # The shared network must not expose either raw HTTP service on eth0.
        execute('approval', 'python3', '-c', '''import socket,ipaddress
ip=socket.gethostbyname(socket.gethostname())
assert not ipaddress.ip_address(ip).is_loopback, ip
for port in (18792,18793):
 s=socket.socket(); s.settimeout(2)
 assert s.connect_ex((ip,port))!=0,(ip,port)
 s.close()
''')
        print('PASS: reinitialization/restart preserve keys, enrolled identity and media; raw HTTP is loopback-only', flush=True)
    except Exception:
        # Never print container logs: approval logs contain first-install codes.
        print(compose('ps', '-a'), flush=True)
        print(compose('logs', '--no-color', 'init', 'configure', 'runner', 'project-verifier'), flush=True)
        raise
    finally:
        compose('down', '--remove-orphans')
        shutil.rmtree(root)


if __name__ == '__main__':
    main()
