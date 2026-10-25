"""Discover the logged-in Tailscale domain without TCP listeners or Docker access."""
import argparse
import http.client
import json
import re
import socket
import time
from pathlib import Path
from installer.initialize import check_regular


class LocalAPI(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('local-tailscaled.sock', timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def status(path):
    connection = LocalAPI(path)
    try:
        connection.request('GET', '/localapi/v0/status')
        response = connection.getresponse()
        data = response.read(1024 * 1024 + 1)
        if response.status != 200 or len(data) > 1024 * 1024:
            raise ValueError('Tailscale status unavailable')
        return json.loads(data)
    finally:
        connection.close()


def domain(value):
    if value.get('BackendState') != 'Running':
        return None
    result = value.get('Self', {}).get('DNSName', '').rstrip('.')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ts\.net', result):
        raise ValueError('No valid device MagicDNS domain; enable MagicDNS and HTTPS in Tailscale')
    if result not in [x.rstrip('.') for x in value.get('CertDomains', [])]:
        raise ValueError('HTTPS certificates not enabled for this device; enable HTTPS in Tailscale')
    return result


def configure(policy_path, hostname):
    cfg = {'state': '/var/lib/compose-cd-approval', 'origin': 'https://' + hostname,
           'rp_id': hostname, 'socket': '/run/compose-cd-approval/approval.sock',
           'service_key': '/etc/compose-cd/service-keys/approval-service/key'}
    path = Path(policy_path)
    if path.exists() or path.is_symlink():
        check_regular(path, 0o644, 0)
        existing = json.loads(path.read_text())
        if existing != cfg:
            raise ValueError('Domain or approval configuration changed; identity migration requires administrator review')
        return
    # Publish fully written JSON atomically; approval must never read partial JSON.
    import os
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as target:
        temporary = Path(target.name)
        try:
            target.write(json.dumps(cfg, indent=2) + '\n')
            target.flush()
            os.fchmod(target.fileno(), 0o644)
            os.fsync(target.fileno())
            os.link(temporary, path)  # no overwrite, including a concurrent publication
        finally:
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket', default='/tailscale/tailscaled.sock')
    parser.add_argument('--policy', default='/etc/compose-cd/approval/policy.json')
    args = parser.parse_args()
    previous = None
    failures = 0
    while True:
        try:
            hostname = domain(status(args.socket))
            if hostname is None:
                message = 'Waiting for login. Open the login link in the tailscale container log.'
            else:
                configure(args.policy, hostname)
                message = 'Domain configured: https://' + hostname + '/ — next: approval container log.'
            failures = 0
        except (OSError, ValueError, KeyError, http.client.HTTPException) as error:
            # Do not emit raw status JSON, peer data or authentication links.
            message = 'Setup waiting: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__)
            failures += 1
        if message != previous or failures % 12 == 1:
            print(message, flush=True)
            previous = message
        time.sleep(5)


if __name__ == '__main__':
    main()
