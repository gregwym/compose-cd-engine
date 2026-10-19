"""Fresh, transaction-bound WebAuthn ceremonies using Yubico's verifier."""
import json
import secrets
import time
from fido2.server import Fido2Server
from fido2.webauthn import (AttestedCredentialData, AuthenticationResponse,
                            RegistrationResponse, UserVerificationRequirement)
from authorization.scope import require
from deployer import schema


class Passkeys:
    def __init__(self, store, rp_id, origin):
        self.store = store
        self.server = Fido2Server({'id': rp_id, 'name': 'Compose CD Authorization'},
                                 verify_origin=lambda value: value == origin)
        self.server.timeout = 120000

    @staticmethod
    def binding(db, action, target):
        if action in ('approve', 'deny'):
            row = db.execute('SELECT * FROM requests WHERE id=?', (target,)).fetchone()
            require(row is not None and row['status'] == 'pending' and row['expires'] > time.time(), 'stale_request')
        elif action == 'revoke':
            row = db.execute('SELECT * FROM grants WHERE id=?', (target,)).fetchone()
            require(row is not None and row['status'] == 'active', 'stale_request')
        elif action == 'remove':
            row = db.execute('SELECT admin,hex(id) AS id,active FROM credentials WHERE hex(id)=?', (target.upper(),)).fetchone()
            require(row is not None and row['active'])
        else:
            require(action in ('login', 'enroll'))
            return action
        return schema.fingerprint({k: (v.hex() if isinstance(v, bytes) else v) for k, v in dict(row).items()})

    def begin(self, session, action, target='', token=None, admin=None):
        require(action in ('login', 'enroll', 'approve', 'deny', 'revoke', 'remove'))
        with self.store.db() as db:
            require(db.execute('SELECT count(*) FROM ceremonies WHERE expires>?', (int(time.time()),)).fetchone()[0] < 100)
            db.execute('DELETE FROM ceremonies WHERE expires<?', (int(time.time()),))
            if action == 'enroll':
                require(isinstance(token, str) and len(token) <= 128)
                row = db.execute('SELECT admin,expires FROM bootstrap WHERE token=?', (schema.fingerprint(token),)).fetchone()
                require(row is not None and row['expires'] > time.time())
                admin = row['admin']
                require(db.execute('SELECT count(*) FROM credentials WHERE active=1').fetchone()[0] < 64)
                # Consume independent bootstrap token at ceremony creation.
                db.execute('DELETE FROM bootstrap WHERE token=?', (schema.fingerprint(token),))
                options, state = self.server.register_begin(
                    {'id': admin.encode(), 'name': admin, 'displayName': admin},
                    [AttestedCredentialData(r[0]) for r in db.execute('SELECT data FROM credentials WHERE active=1')],
                    user_verification=UserVerificationRequirement.REQUIRED, resident_key_requirement='required')
                target = admin
            else:
                require(action == 'login' or admin is not None)
                rows = db.execute('SELECT data FROM credentials WHERE active=1' + (' AND admin=?' if admin else ''),
                                  (admin,) if admin else ()).fetchall()
                require(bool(rows))
                options, state = self.server.authenticate_begin([AttestedCredentialData(r[0]) for r in rows],
                                                               user_verification=UserVerificationRequirement.REQUIRED)
            binding = self.binding(db, action, target)
            cid = secrets.token_urlsafe(32)
            db.execute('INSERT INTO ceremonies VALUES (?,?,?,?,?,?,?)',
                       (cid, session, action, target, binding, schema.canonical(state), int(time.time()) + 120))
            return {'ceremony_id': cid, 'options': dict(options)}

    def finish(self, session, cid, response, admin=None):
        with self.store.db() as db:
            row = db.execute('SELECT * FROM ceremonies WHERE id=? AND session=?', (cid, session)).fetchone()
            require(row is not None and row['expires'] > time.time())
            # Commit consumption even on failed verification. No reusable challenges.
            db.execute('DELETE FROM ceremonies WHERE id=?', (cid,))
        action, target = row['action'], row['target']
        require(action in ('login', 'enroll') or admin is not None)
        parsed = (RegistrationResponse if action == 'enroll' else AuthenticationResponse).from_dict(response)
        client = json.loads(bytes(parsed.response.client_data))
        require(client.get('crossOrigin', False) is False and not client.get('topOrigin'))
        state = json.loads(row['state'])
        with self.store.db() as db:
            require(self.binding(db, action, target) == row['binding'], 'stale_request')
            if action == 'enroll':
                data = self.server.register_complete(state, parsed)
                cred = data.credential_data
                db.execute('INSERT INTO credentials VALUES (?,?,?,?,1)',
                           (cred.credential_id, target, bytes(cred), data.counter))
                self.store.event(db, target, 'credential_enrolled', cred.credential_id.hex())
                return {'status': 'enrolled'}
            credentials = db.execute('SELECT * FROM credentials WHERE active=1' + (' AND admin=?' if admin else ''),
                                     (admin,) if admin else ()).fetchall()
            cred = self.server.authenticate_complete(state, [AttestedCredentialData(r['data']) for r in credentials], parsed)
            owner = next(r for r in credentials if r['id'] == cred.credential_id)
            handle = parsed.response.user_handle
            require(handle is None or handle == owner['admin'].encode())
            counter = parsed.response.authenticator_data.counter
            require(not (owner['counter'] or counter) or counter > owner['counter'])
            db.execute('UPDATE credentials SET counter=? WHERE id=?', (counter, cred.credential_id))
            admin = owner['admin']
            if action == 'approve':
                self.store.issue(db, target, admin, cred.credential_id)
            elif action == 'deny':
                db.execute("UPDATE requests SET status='denied' WHERE id=?", (target,))
                self.store.event(db, admin, 'grant_denied', target)
            elif action == 'revoke':
                db.execute("UPDATE grants SET status='revoked',revision=revision+1,revoked=? WHERE id=?", (int(time.time()), target))
                self.store.event(db, admin, 'grant_revoked', target)
            elif action == 'remove':
                require(db.execute('SELECT count(*) FROM credentials WHERE admin=? AND active=1', (admin,)).fetchone()[0] > 1)
                require(db.execute('SELECT admin FROM credentials WHERE hex(id)=?', (target.upper(),)).fetchone()[0] == admin)
                db.execute('UPDATE credentials SET active=0 WHERE hex(id)=?', (target.upper(),))
                self.store.event(db, admin, 'credential_removed', target)
            else:
                self.store.event(db, admin, 'administrator_authenticated', cred.credential_id.hex())
            return {'status': 'success', 'admin': admin}
