"""WebAuthn ceremonies. Every decision is its own assertion bound to the exact row it decides."""
import json
import secrets
import time
from fido2.server import Fido2Server
from fido2.webauthn import (AttestedCredentialData, AuthenticationResponse, RegistrationResponse,
                            UserVerificationRequirement)
from shared.wire import Denied, canonical, digest

OWNER = b'owner'
# action -> (table, key column, required status)
TARGETS = {
    'approve': ('requests', 'id', 'pending'), 'deny': ('requests', 'id', 'pending'),
    'pair': ('agents', 'token', 'pending'), 'deny_pair': ('agents', 'token', 'pending'),
    'unpair': ('agents', 'id', 'active'), 'revoke': ('grants', 'id', 'active'),
    'remove_trigger': ('triggers', 'id', 'active'), 'remove_route': ('routes', 'https_port', None),
    'remove_credential': ('credentials', 'hex(id)', None),
}
ACTIONS = ('enroll', 'login', *TARGETS)


class Passkeys:
    def __init__(self, store, rp_id, origin):
        self.store = store
        self.server = Fido2Server({'id': rp_id, 'name': 'Compose Deployer'}, verify_origin=lambda o: o == origin)
        self.server.timeout = 120000

    @staticmethod
    def row(db, action, target):
        table, column, status = TARGETS[action]
        row = db.execute(f'SELECT * FROM {table} WHERE {column}=?', (target,)).fetchone()
        expired = status == 'pending' and row is not None and row['expires'] <= time.time()
        if row is None or (status and row['status'] != status) or expired:
            raise Denied('stale_request')
        return row

    def binding(self, db, action, target):
        if action in ('enroll', 'login'):
            return action
        row = self.row(db, action, target)
        return digest(canonical({k: (row[k].hex() if isinstance(row[k], bytes) else row[k]) for k in row.keys()}))

    def begin(self, session, action, target='', token=None, logged_in=False):
        if action not in ACTIONS or not isinstance(target, str) or len(target) > 128:
            raise Denied('invalid_argument')
        with self.store.db() as db:
            db.execute('DELETE FROM ceremonies WHERE expires<?', (int(time.time()),))
            if db.execute('SELECT count(*) FROM ceremonies').fetchone()[0] >= 100:
                raise Denied('rate_limited')
            credentials = [AttestedCredentialData(r['data']) for r in db.execute('SELECT data FROM credentials WHERE active=1')]
            if action == 'enroll':
                if not logged_in:
                    code = digest((token or '').encode())
                    row = db.execute('SELECT * FROM enrollment WHERE token=?', (code,)).fetchone()
                    if not row or row['expires'] <= time.time():
                        raise Denied('invalid_enrollment_code')
                    db.execute('DELETE FROM enrollment WHERE token=?', (code,))
                if len(credentials) >= 16:
                    raise Denied('rate_limited')
                options, state = self.server.register_begin(
                    {'id': OWNER, 'name': 'owner', 'displayName': 'NAS owner'}, credentials,
                    user_verification=UserVerificationRequirement.REQUIRED, resident_key_requirement='required')
            else:
                if not credentials:
                    raise Denied('not_enrolled')
                options, state = self.server.authenticate_begin(
                    credentials, user_verification=UserVerificationRequirement.REQUIRED)
            cid = secrets.token_urlsafe(24)
            db.execute('INSERT INTO ceremonies VALUES (?,?,?,?,?,?,?)', (cid, session, action, target,
                       self.binding(db, action, target), json.dumps(state), int(time.time()) + 120))
        return {'ceremony_id': cid, 'options': dict(options)}

    def finish(self, session, cid, response):
        """Verify the assertion and apply its decision in one transaction."""
        with self.store.db() as db:
            row = db.execute('SELECT * FROM ceremonies WHERE id=? AND session=?', (cid, session)).fetchone()
            if not row or row['expires'] <= time.time():
                raise Denied('expired_ceremony')
            db.execute('DELETE FROM ceremonies WHERE id=?', (cid,))  # single use, even on failure
        action, target, state = row['action'], row['target'], json.loads(row['state'])
        try:
            parsed = (RegistrationResponse if action == 'enroll' else AuthenticationResponse).from_dict(response)
            client = json.loads(bytes(parsed.response.client_data))
        except Exception:
            raise Denied('invalid_response') from None
        if client.get('crossOrigin') or client.get('topOrigin'):
            raise Denied('invalid_response')
        with self.store.db() as db:
            if self.binding(db, action, target) != row['binding']:
                raise Denied('stale_request')
            try:
                if action == 'enroll':
                    data = self.server.register_complete(state, parsed)
                    credential = data.credential_data
                    db.execute('INSERT INTO credentials VALUES (?,?,?,?,?)', (credential.credential_id, bytes(credential),
                               data.counter, 1, int(time.time())))
                    self.store.event(db, 'owner', 'passkey_enrolled', credential.credential_id.hex())
                    return {'action': action, 'target': ''}
                rows = db.execute('SELECT * FROM credentials WHERE active=1').fetchall()
                credential = self.server.authenticate_complete(state, [AttestedCredentialData(r['data']) for r in rows], parsed)
            except Denied:
                raise
            except Exception:
                raise Denied('verification_failed') from None
            owner = next(r for r in rows if bytes(r['id']) == credential.credential_id)
            if parsed.response.user_handle not in (None, OWNER):
                raise Denied('verification_failed')
            counter = parsed.response.authenticator_data.counter
            if (owner['counter'] or counter) and counter <= owner['counter']:
                raise Denied('verification_failed')
            db.execute('UPDATE credentials SET counter=? WHERE id=?', (counter, credential.credential_id))
            self.decide(db, action, target)
            return {'action': action, 'target': target}

    def decide(self, db, action, target):
        stamp = int(time.time())
        event = lambda name: self.store.event(db, 'owner', name, target)
        if action == 'approve':
            db.execute("UPDATE requests SET status='approved', decided=? WHERE id=?", (stamp, target))
            event('request_approved')
        elif action == 'deny':
            db.execute("UPDATE requests SET status='denied', decided=? WHERE id=?", (stamp, target))
            event('request_denied')
        elif action == 'pair':
            db.execute("UPDATE agents SET status='active', expires=0 WHERE token=?", (target,))
            event('agent_paired')
        elif action == 'deny_pair':
            db.execute("UPDATE agents SET status='denied' WHERE token=?", (target,))
            event('pairing_denied')
        elif action == 'unpair':
            db.execute("UPDATE agents SET status='revoked' WHERE id=?", (target,))
            db.execute("UPDATE grants SET status='revoked' WHERE agent=? AND status='active'", (target,))
            db.execute("UPDATE requests SET status='denied' WHERE agent=? AND status='pending'", (target,))
            event('agent_unpaired')
        elif action == 'revoke':
            db.execute("UPDATE grants SET status='revoked' WHERE id=?", (target,))
            event('grant_revoked')
        elif action == 'remove_trigger':
            db.execute("UPDATE triggers SET status='removed' WHERE id=?", (target,))
            event('trigger_removed')
        elif action == 'remove_route':
            db.execute('DELETE FROM routes WHERE https_port=?', (target,))
            event('route_removed')
        elif action == 'remove_credential':
            if db.execute('SELECT count(*) FROM credentials WHERE active=1').fetchone()[0] <= 1:
                raise Denied('last_passkey')
            db.execute('UPDATE credentials SET active=0 WHERE hex(id)=?', (target,))
            event('passkey_removed')
        else:
            event('owner_signed_in')
