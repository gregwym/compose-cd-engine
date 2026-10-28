"""Agent-held Ed25519 keys. The gateway stores only public keys."""
import hashlib
import json
import re
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from shared.wire import Denied

CONTEXT = b'compose-deployer-agent-v1\0'
FIELDS = {'agent', 'public_key', 'audience', 'op', 'args', 'request_id', 'timestamp'}


def identity(public_key):
    if not isinstance(public_key, str) or not re.fullmatch(r'[0-9a-f]{64}', public_key):
        raise Denied('invalid_key')
    return 'agent-' + hashlib.sha256(bytes.fromhex(public_key)).hexdigest()[:24]


def fingerprint(public_key):
    return hashlib.sha256(bytes.fromhex(public_key)).hexdigest()


def verify(raw, signature, audience):
    """Return the request after checking key, signature, audience and clock."""
    try:
        value = json.loads(raw)
    except ValueError:
        raise Denied('invalid_request') from None
    if not isinstance(value, dict) or set(value) != FIELDS or not isinstance(value['args'], dict):
        raise Denied('invalid_request')
    if value['agent'] != identity(value['public_key']):
        raise Denied('invalid_request')
    if (not isinstance(signature, str) or not re.fullmatch(r'ed25519=[0-9a-f]{128}', signature)):
        raise Denied('invalid_signature')
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(value['public_key'])).verify(
            bytes.fromhex(signature[8:]), CONTEXT + raw)
    except InvalidSignature:
        raise Denied('invalid_signature') from None
    if value['audience'] != audience:
        raise Denied('wrong_audience')
    if type(value['timestamp']) is not int or abs(time.time() - value['timestamp']) > 60:
        raise Denied('clock_skew')
    if not isinstance(value['request_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', value['request_id']):
        raise Denied('invalid_request')
    if not isinstance(value['op'], str):
        raise Denied('invalid_request')
    return value
