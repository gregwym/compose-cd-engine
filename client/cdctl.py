#!/usr/bin/env python3
"""Agent client for the NAS Compose deployer. Needs Python 3.10+ and `cryptography`.

    cdctl init https://deployer.example.ts.net
    cdctl pair --label openclaw --wait
    cdctl projects
    cdctl request operate jellyfin --days 7 --wait
    cdctl restart jellyfin --wait
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CONTEXT = b'compose-deployer-agent-v1\0'
HOME = Path(os.environ.get('CDCTL_HOME', Path.home() / '.config' / 'cdctl'))
DONE = {'success', 'failed', 'rolled_back', 'stale', 'unknown', 'no_change'}


class Client:
    def __init__(self, home=HOME):
        config = json.loads((home / 'config.json').read_text())
        self.endpoint = config['endpoint'].rstrip('/')
        self.key = serialization.load_pem_private_key((home / 'key.pem').read_bytes(), None)
        self.public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def call(self, op, **args):
        body = json.dumps({'agent': 'agent-' + hashlib.sha256(bytes.fromhex(self.public)).hexdigest()[:24],
                           'public_key': self.public, 'audience': self.endpoint.split('://', 1)[1].split('/')[0],
                           'op': op, 'args': {k: v for k, v in args.items() if v is not None},
                           'request_id': uuid.uuid4().hex, 'timestamp': int(time.time())}).encode()
        request = urllib.request.Request(self.endpoint + '/agent', body, method='POST', headers={
            'Content-Type': 'application/json', 'X-Agent-Signature': 'ed25519=' + self.key.sign(CONTEXT + body).hex()})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read())['result']
        except urllib.error.HTTPError as error:
            reply = json.loads(error.read() or b'{}')
            raise SystemExit(json.dumps({'error': reply.get('error', error.code), 'detail': reply.get('detail')},
                                        ensure_ascii=False))

    def wait_job(self, job, timeout=1800):
        deadline = time.time() + timeout
        while True:
            state = self.call('job', id=job)
            if state['status'] in DONE or time.time() > deadline:
                return state
            time.sleep(3)

    def wait_request(self, rid, timeout=3600):
        deadline = time.time() + timeout
        while True:
            state = self.call('request_status', id=rid)
            waiting = state['status'] == 'pending' or (state['status'] == 'approved' and not state['outcome'])
            if waiting and time.time() < deadline:
                time.sleep(5)
                continue
            job = (state.get('outcome') or {}).get('job')
            if job:
                state['job'] = self.wait_job(job)
            return state


def init(args):
    HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = HOME / 'key.pem'
    if not key.exists():
        pem = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption())
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(pem)
    (HOME / 'config.json').write_text(json.dumps({'endpoint': args.endpoint}) + '\n')
    return {'home': str(HOME), 'endpoint': args.endpoint}


def env_pairs(values):
    out = {}
    for item in values or []:
        key, sep, value = item.partition('=')
        if not sep:
            raise SystemExit('--env-set needs KEY=VALUE')
        out[key] = value
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(prog='cdctl', description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init').add_argument('endpoint')
    pair = sub.add_parser('pair')
    pair.add_argument('--label', default='openclaw')
    pair.add_argument('--wait', action='store_true')
    sub.add_parser('whoami')
    sub.add_parser('projects')
    logs = sub.add_parser('logs')
    logs.add_argument('project')
    logs.add_argument('--service')
    logs.add_argument('--tail', type=int, default=100)
    sub.add_parser('read').add_argument('project')
    for action in ('start', 'stop', 'restart', 'up', 'update'):
        item = sub.add_parser(action)
        item.add_argument('project')
        item.add_argument('services', nargs='*')
        item.add_argument('--wait', action='store_true')
    req = sub.add_parser('request', help='ask the owner to approve something')
    req.add_argument('kind', choices=['operate', 'change', 'create', 'down', 'serve', 'unserve', 'trigger'])
    req.add_argument('project', nargs='?', default='')
    req.add_argument('--days', type=int)
    req.add_argument('--compose', type=Path, help='full new compose.yaml')
    req.add_argument('--env-set', action='append', metavar='KEY=VALUE')
    req.add_argument('--env-unset', action='append', metavar='KEY')
    req.add_argument('--https-port', type=int)
    req.add_argument('--target-port', type=int)
    for name in ('service', 'repository', 'workflow', 'branch', 'image', 'platform'):
        req.add_argument('--' + name)
    req.add_argument('--wait', action='store_true', help='wait for the decision and any resulting job')
    status = sub.add_parser('status')
    status.add_argument('id')
    status.add_argument('--wait', action='store_true')
    job = sub.add_parser('job')
    job.add_argument('id')
    job.add_argument('--wait', action='store_true')
    args = parser.parse_args(argv)

    if args.command == 'init':
        result = init(args)
    else:
        client = Client()
        if args.command == 'pair':
            result = client.call('pair', label=args.label)
            if args.wait and result['status'] == 'pending':
                print(json.dumps(result, ensure_ascii=False), flush=True)
                while client.call('pair', label=args.label)['status'] == 'pending':
                    time.sleep(5)
                result = client.call('whoami')
        elif args.command in ('whoami', 'projects'):
            result = client.call(args.command)
        elif args.command == 'logs':
            result = client.call('logs', project=args.project, service=args.service, tail=args.tail)
        elif args.command == 'read':
            result = client.call('read', project=args.project)
        elif args.command in ('start', 'stop', 'restart', 'up', 'update'):
            result = client.call(args.command, project=args.project, services=args.services)
            if args.wait:
                result = client.wait_job(result['job'])
        elif args.command == 'request':
            fields = {'kind': args.kind, 'project': args.project, 'days': args.days,
                      'compose': args.compose.read_text() if args.compose else None,
                      'env_set': env_pairs(args.env_set) or None, 'env_unset': args.env_unset,
                      'https_port': args.https_port, 'target_port': args.target_port,
                      **{k: getattr(args, k) for k in ('service', 'repository', 'workflow', 'branch', 'image', 'platform')}}
            result = client.call('request', **fields)
            if args.wait:
                print(json.dumps({'approval_url': result['approval_url'], 'id': result['id']}, ensure_ascii=False), flush=True)
                result = client.wait_request(result['id'])
        elif args.command == 'status':
            result = client.wait_request(args.id) if args.wait else client.call('request_status', id=args.id)
        else:
            result = client.wait_job(args.id) if args.wait else client.call('job', id=args.id)
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == '__main__':
    main()
