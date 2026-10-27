#!/usr/bin/env python3
"""Signed fixed-action client for the optional shared-application ingress broker."""
import argparse
import json
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
import urllib.request
import ssl

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from authorization import agents
from deployer import schema
from scripts.agent import private


def call(endpoint, private_key, operation, payload):
    url = urlsplit(endpoint)
    schema.check(url.scheme == 'https' and url.hostname and url.path in ('', '/')
                 and not url.username and not url.password and not url.query and not url.fragment)
    public = agents.public_key(private_key)
    value = {'version': 1, 'agent': agents.identity(public), 'public_key': public,
             'audience': 'compose-cd-shared-app-ingress-v1', 'operation': operation,
             'payload': payload, 'request_id': uuid.uuid4().hex, 'timestamp': int(time.time())}
    envelope = {'value': value, 'signature': agents.sign(schema.canonical(value).encode(), private_key)}
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(endpoint.rstrip('/') + '/v1/ingress',
        schema.canonical(envelope).encode(), {'Content-Type': 'application/json'}, method='POST')
    with opener.open(request, timeout=35) as response:
        raw = response.read(65537)
        schema.check(len(raw) <= 65536)
        result = json.loads(raw)
        schema.check(isinstance(result, dict))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('operation', choices=('plan', 'request', 'apply', 'receipt', 'recovery_plan'))
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--backend')
    target.add_argument('--plan-id')
    args = parser.parse_args()
    schema.check((args.operation == 'plan') == bool(args.backend))
    payload = {'backend': args.backend} if args.operation == 'plan' else {'plan_id': args.plan_id}
    key = agents.load_private(private(args.key, 16384))
    print(schema.canonical(call(args.endpoint, key, args.operation, payload)))


if __name__ == '__main__':
    main()
