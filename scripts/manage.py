#!/usr/bin/env python3
"""Client for the fixed NAS management API. Credential remains on the Mac."""
import argparse
import hashlib
import hmac
import json
import ssl
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['status', 'logs', 'start', 'stop', 'restart', 'diagnose', 'update'])
    parser.add_argument('project')
    parser.add_argument('--endpoint', required=True, help='private HTTPS URL ending /v1/manage')
    parser.add_argument('--secret-file', required=True)
    args = parser.parse_args()
    url = urlsplit(args.endpoint)
    if (url.scheme != 'https' or url.path != '/v1/manage' or not url.hostname
            or url.username or url.password or url.query or url.fragment):
        parser.error('a private HTTPS endpoint ending /v1/manage is required')
    secret_path = Path(args.secret_file)
    if secret_path.is_symlink() or secret_path.stat().st_mode & 0o077:
        parser.error('client secret must be a non-symlink file with mode 0600 or stricter')
    secret = secret_path.read_bytes().strip()
    if len(secret) < 32:
        parser.error('secret must be at least 32 bytes')
    value = {'project': args.project, 'action': args.action,
             'timestamp': int(time.time()), 'request_id': uuid.uuid4().hex}
    raw = json.dumps(value, separators=(',', ':')).encode()
    signature = 'sha256=' + hmac.new(secret, raw, hashlib.sha256).hexdigest()
    request = urllib.request.Request(args.endpoint, data=raw,
        headers={'Content-Type': 'application/json', 'X-Management-Signature': signature}, method='POST')
    # No redirects: never forward a signed administrative operation elsewhere.
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
                          'next': 'query status; do not automatically repeat mutations'}))
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
