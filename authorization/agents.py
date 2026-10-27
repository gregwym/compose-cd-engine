"""Agent-owned Ed25519 identity. The NAS stores only the public key."""
import hashlib
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from deployer import schema
from management.protocol import reserve_nonce


def public_key(private):
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def identity(public):
    schema.check(isinstance(public, str) and len(public) == 64 and public == public.lower())
    raw = bytes.fromhex(public)
    schema.check(len(raw) == 32)
    return 'agent-' + hashlib.sha256(raw).hexdigest()[:24]


def sign(raw, private):
    return 'ed25519=' + private.sign(b'compose-cd-agent-v2\0' + raw).hex()


def verify(raw, signature, public):
    identity(public)
    schema.check(isinstance(signature, str) and signature.startswith('ed25519=') and len(signature) == 136)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
            bytes.fromhex(signature[8:]), b'compose-cd-agent-v2\0' + raw)
    except InvalidSignature:
        raise ValueError('invalid agent signature') from None


def authenticate(raw, signature, database, validator, reserve=True):
    schema.check(len(raw) <= 60000)
    value = validator(raw)
    schema.check(value['agent'] == identity(value['public_key']))
    verify(raw, signature, value['public_key'])
    schema.check(abs(int(time.time()) - value['timestamp']) <= 60)
    if reserve:
        reserve_nonce(value, database)
    return value


def load_private(data):
    key = serialization.load_pem_private_key(data, password=None)
    schema.check(isinstance(key, Ed25519PrivateKey))
    return key
