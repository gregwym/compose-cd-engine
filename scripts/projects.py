#!/usr/bin/env python3
"""Private HTTPS client for constrained project plans and durable tasks."""
import argparse
import hashlib
import hmac
import json
import ssl
import sys
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['plan', 'apply', 'task', 'status', 'start', 'stop', 'restart'])
    parser.add_argument('project')
    parser.add_argument('--spec', help='private JSON declaration; plan only, never raw Compose/YAML')
    parser.add_argument('--id', help='plan ID for apply, task ID for task')
    parser.add_argument('--endpoint', required=True, help='private HTTPS URL ending /v1/projects')
    parser.add_argument('--secret-file', required=True)
    args = parser.parse_args()
    url = urlsplit(args.endpoint)
    if (url.scheme != 'https' or url.path != '/v1/projects' or not url.hostname
            or url.username or url.password or url.query or url.fragment):
        parser.error('private HTTPS /v1/projects endpoint required')
    key = Path(args.secret_file)
    if key.is_symlink() or not key.is_file() or key.stat().st_mode & 0o077:
        parser.error('secret must be a non-symlink mode 0600 file')
    secret = key.read_bytes().strip()
    if len(secret) < 32:
        parser.error('secret must be at least 32 bytes')
    if args.operation == 'plan':
        if not args.spec or args.id:
            parser.error('plan requires --spec and forbids --id')
        path = Path(args.spec)
        if path.is_symlink() or path.stat().st_mode & 0o077 or path.stat().st_size > 60000:
            parser.error('spec must be a private file no larger than 60000 bytes')
        payload = json.loads(path.read_text())
    elif args.operation in ('apply', 'task'):
        if not args.id or args.spec:
            parser.error('apply/task requires --id and forbids --spec')
        payload = {('plan_id' if args.operation == 'apply' else 'task_id'): args.id}
    else:
        if args.spec or args.id:
            parser.error('this operation takes no --spec/--id')
        payload = {}
    value = {'project': args.project, 'operation': args.operation, 'payload': payload,
             'request_id': uuid.uuid4().hex, 'timestamp': int(time.time())}
    # Validate before transmitting; do not print invalid payloads or credentials.
    from deployer.schema import request as validate
    raw = json.dumps(value, separators=(',', ':')).encode()
    validate(raw)
    signature = 'sha256=' + hmac.new(secret, raw, hashlib.sha256).hexdigest()
    request = urllib.request.Request(args.endpoint, data=raw,
        headers={'Content-Type': 'application/json', 'X-Management-Signature': signature}, method='POST')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=15) as response:
            data = response.read(65537)
            if len(data) > 65536:
                raise ValueError('oversized response')
            print(json.dumps(json.loads(data), sort_keys=True))
    except Exception:
        print(json.dumps({'status': 'request_not_confirmed', 'request_id': value['request_id'],
            'next': 'query task/status; apply may be retried with the SAME plan ID and a fresh request ID; never retry lifecycle mutations automatically'}))
        raise SystemExit(1) from None


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError):
        print('{"status":"invalid_local_input"}')
        sys.exit(1)
