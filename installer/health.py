"""Readiness probes; never create browser sessions or emit credentials."""
import argparse
import http.client
import json
from pathlib import Path
import socket
from installer.configure import status, domain


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('service', choices=['approval', 'management', 'runner', 'project-verifier', 'configure'])
    args = parser.parse_args()
    if args.service == 'configure':
        hostname = domain(status('/tailscale/tailscaled.sock'))
        cfg = json.loads(Path('/etc/compose-cd/approval/policy.json').read_text())
        if not hostname or cfg['rp_id'] != hostname:
            raise SystemExit(1)
    elif args.service in ('runner', 'project-verifier'):
        path = '/run/compose-cd-management/projects.sock' if args.service == 'runner' else '/run/compose-cd-verification/verifier.sock'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(path)
    else:
        approval = args.service == 'approval'
        host = json.loads(Path('/etc/compose-cd/approval/policy.json').read_text())['rp_id'] if approval else 'localhost'
        connection = http.client.HTTPConnection('127.0.0.1', 18793 if approval else 18792, timeout=3)
        connection.request('GET', '/healthz', headers={'Host': host})
        response = connection.getresponse()
        if response.status != 200 or json.loads(response.read()) != {'status': 'ready'}:
            raise SystemExit(1)
        connection.close()
        if approval:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as rpc:
                rpc.settimeout(3)
                rpc.connect('/run/compose-cd-approval/approval.sock')


if __name__ == '__main__':
    main()
