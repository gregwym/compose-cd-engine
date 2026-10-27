#!/usr/bin/env python3
"""Generate an agent-owned identity and request a ten-minute Passkey pairing."""
import argparse
import json
import os
import ssl
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
import urllib.request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authorization import agents
from deployer import schema
from scripts.agent import private


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True, help='private HTTPS approval origin, without a path')
    parser.add_argument('--key-file', required=True, help='private PEM file; generated once, never uploaded')
    parser.add_argument('--label', required=True, help='device label shown to the owner, not proof of identity')
    parser.add_argument('--status', action='store_true', help='check without creating another request')
    args = parser.parse_args()
    url = urlsplit(args.origin)
    schema.check(url.scheme == 'https' and url.hostname and url.path in ('', '/')
                 and not url.username and not url.password and not url.query and not url.fragment)
    path = Path(args.key_file)
    parent = path.parent.lstat()
    schema.check(path.parent.is_dir() and not path.parent.is_symlink()
                 and parent.st_uid == os.geteuid() and not parent.st_mode & 0o077)
    if not path.exists() and not path.is_symlink():
        schema.check(not args.status)
        data = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
    signer = agents.load_private(private(path, 4096))
    public = agents.public_key(signer)
    value = {'agent': agents.identity(public), 'public_key': public, 'audience': url.hostname,
             'operation': 'pair_status' if args.status else 'pair', 'label': args.label,
             'request_id': uuid.uuid4().hex, 'timestamp': int(time.time())}
    from authorization.pairing import pair_request
    raw = schema.canonical(value).encode(); pair_request(raw)
    request = urllib.request.Request(args.origin.rstrip('/') + '/agent/pair', raw,
        {'Content-Type': 'application/json', 'X-Agent-Signature': agents.sign(raw, signer)}, method='POST')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request, timeout=15) as response:
        result = response.read(4097); schema.check(len(result) <= 4096)
    print(schema.canonical(json.loads(result)))


if __name__ == '__main__':
    main()
