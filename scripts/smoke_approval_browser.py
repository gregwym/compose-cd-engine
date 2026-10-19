#!/usr/bin/env python3
"""Development-only Chromium virtual-authenticator UX test, never real Passkeys.

Run with PYTHONPATH=. and a development environment containing playwright,
then `python -m playwright install chromium`. Not a runtime dependency.
"""
import datetime
import json
import ssl
import tempfile
import threading
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from playwright.sync_api import sync_playwright, expect
from authorization.server import Handler
from authorization.store import Store
from authorization.passkeys import Passkeys
from receiver.receiver import BoundedHTTPServer


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False).sign(key, hashes.SHA256()))
        cert, private = root / 'cert.pem', root / 'key.pem'
        cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private.chmod(0o600)
        server = BoundedHTTPServer(('127.0.0.1', 0), Handler)
        origin = 'https://localhost:' + str(server.server_port)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, private)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.origin = origin
        server.store = Store(root / 'auth.sqlite', origin)
        server.passkeys = Passkeys(server.store, 'localhost', origin)
        server.sessions, server.session_lock = {}, threading.Lock()
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page(ignore_https_errors=True, viewport={'width': 390, 'height': 844})
                cdp = page.context.new_cdp_session(page)
                cdp.send('WebAuthn.enable')
                cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
                    'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': True,
                    'hasUserVerification': True, 'isUserVerified': True, 'automaticPresenceSimulation': True}})
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto(origin + '/enroll')
                expect(page.locator('#message')).to_have_text('Completed.')
                page.locator('#token').fill(server.store.bootstrap('owner'))
                page.get_by_role('button', name='Create Passkey').click()
                expect(page.locator('#message')).to_have_text('Completed.')
                with server.store.db() as db:
                    assert db.execute('SELECT count(*) FROM credentials').fetchone()[0] == 1
                page.get_by_role('button', name='Sign in with Passkey').click()
                expect(page.locator('#refresh')).to_be_visible()
                value = {'project': 'autobangumi-demo', 'agent': 'openclaw', 'plan': 'a' * 32, 'spec_hash': 'b' * 64,
                    'policy': 'c' * 64, 'scope': {'services': {'app': {'repository': 'ghcr.io/example/app',
                        'mounts': [{'storage': 'downloads', 'slot': 'shared', 'target': '/downloads', 'read_only': False}],
                        'memory_mb': 128, 'cpus': 1, 'ports': []}}, 'egress': False, 'operations': ['apply', 'restart']},
                    'mode': 'persistent', 'lifetime': 3600, 'sandbox': False}
                pending = server.store.propose(value)
                page.goto(origin + '/requests/' + pending['request_id'])
                button = page.get_by_role('button', name='Approve these permissions with Passkey')
                expect(button).to_be_visible()
                page.screenshot(path='/tmp/compose-approval-mobile.png', full_page=True)
                button.click()
                expect(page.get_by_role('button', name='Revoke with Passkey')).to_be_visible()
                assert server.store.check(value)['status'] == 'authorized'
                page.get_by_role('button', name='Revoke with Passkey').click()
                expect(page.get_by_text('autobangumi-demo · revoked', exact=True)).to_be_visible()
                assert server.store.check(value)['status'] == 'needs_approval'
                assert not errors, errors
                browser.close()
            print('Mobile Chromium virtual-authenticator UI: HTTPS enrollment, sign-in, immutable request review, explicit approval and revocation passed. Not physical Safari/Face ID validation.')
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    main()
