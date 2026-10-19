"""Approval-owned SQLite. Agents and managed applications never mount this state."""
import json
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from deployer import schema
from authorization.scope import diff, require


class Store:
    def __init__(self, path, origin):
        self.path, self.origin = str(path), origin
        with self.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS principals(id TEXT PRIMARY KEY, kind TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS credentials(id BLOB PRIMARY KEY, admin TEXT, data BLOB, counter INTEGER, active INTEGER);
                CREATE TABLE IF NOT EXISTS bootstrap(token TEXT PRIMARY KEY, admin TEXT, expires INTEGER);
                CREATE TABLE IF NOT EXISTS ceremonies(id TEXT PRIMARY KEY, session TEXT, action TEXT, target TEXT, binding TEXT, state TEXT, expires INTEGER);
                CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, project TEXT, agent TEXT, plan TEXT, spec_hash TEXT, policy TEXT, scope TEXT, mode TEXT, lifetime INTEGER, created INTEGER, expires INTEGER, status TEXT);
                CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, request TEXT UNIQUE, project TEXT, agent TEXT, admin TEXT, credential BLOB, scope TEXT, policy TEXT, plan TEXT, mode TEXT, created INTEGER, expires INTEGER, revision INTEGER, status TEXT, revoked INTEGER);
                CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, created INTEGER, actor TEXT, action TEXT, subject TEXT, detail TEXT);
                CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
                CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
            ''')

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                db.execute('BEGIN IMMEDIATE')
                yield db
        finally:
            db.close()

    @staticmethod
    def event(db, actor, action, subject, detail=None):
        db.execute('INSERT INTO audit(created,actor,action,subject,detail) VALUES(?,?,?,?,?)',
                   (int(time.time()), actor, action, subject, schema.canonical(detail or {})))

    def bootstrap(self, admin):
        schema.name(admin)
        token = secrets.token_urlsafe(32)
        with self.db() as db:
            db.execute('INSERT OR IGNORE INTO principals VALUES (?,?)', (admin, 'admin'))
            db.execute('INSERT INTO bootstrap VALUES (?,?,?)', (schema.fingerprint(token), admin, int(time.time()) + 600))
            self.event(db, 'local-administrator', 'enrollment_opened', admin)
        return token

    def grants(self, db, agent, project):
        return db.execute("SELECT * FROM grants WHERE agent=? AND project=? AND status='active' AND (expires=0 OR expires>?)",
                          (agent, project, int(time.time()))).fetchall()

    def check(self, value):
        with self.db() as db:
            best, selected = value['scope'], None
            for grant in self.grants(db, value['agent'], value['project']):
                if grant['policy'] != value['policy'] or (grant['mode'] == 'once' and grant['plan'] != value['plan']):
                    continue
                missing = diff(value['scope'], json.loads(grant['scope']))
                if not missing:
                    selected = grant
                    best = {}
                    break
                if len(schema.canonical(missing)) < len(schema.canonical(best)):
                    best = missing
            return {'status': 'authorized' if selected else 'needs_approval', 'grant_diff': best,
                    'grant_id': selected['id'] if selected else None}

    def propose(self, value):
        schema.fields(value, {'project', 'agent', 'plan', 'spec_hash', 'policy', 'scope', 'mode', 'lifetime', 'sandbox'})
        schema.name(value['project']); schema.name(value['agent'])
        require(value['mode'] in ('once', 'persistent', 'expiring'))
        require(type(value['lifetime']) is int and 60 <= value['lifetime'] <= 31536000)
        now = int(time.time())
        with self.db() as db:
            existing = db.execute('SELECT * FROM requests WHERE plan=? AND agent=?', (value['plan'], value['agent'])).fetchone()
            if existing:
                require(existing['spec_hash'] == value['spec_hash'] and existing['policy'] == value['policy'], 'stale_request')
                return self.public_request(existing)
            count = db.execute('SELECT count(*) FROM requests WHERE agent=? AND created>?', (value['agent'], now - 3600)).fetchone()[0]
            require(count < 20, 'rate_limited')
            require(db.execute('SELECT count(*) FROM requests').fetchone()[0] < 10000, 'rate_limited')
            rid = uuid.uuid4().hex
            db.execute('INSERT OR IGNORE INTO principals VALUES (?,?)', (value['agent'], 'agent'))
            db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                       (rid, value['project'], value['agent'], value['plan'], value['spec_hash'], value['policy'],
                        schema.canonical(value['scope']), value['mode'], value['lifetime'], now, now + 3600, 'pending'))
            self.event(db, value['agent'], 'grant_requested', rid, {'spec_hash': value['spec_hash'], 'policy': value['policy']})
            if value['sandbox']:
                self.issue(db, rid, 'administrator-policy:sandbox', None)
            return self.public_request(db.execute('SELECT * FROM requests WHERE id=?', (rid,)).fetchone())

    def public_request(self, row):
        require(row is not None)
        return {'request_id': row['id'], 'project': row['project'], 'agent': row['agent'],
                'status': 'expired' if row['status'] == 'pending' and row['expires'] < time.time() else row['status'],
                'approval_url': self.origin + '/requests/' + row['id'], 'plan_id': row['plan'],
                'scope': json.loads(row['scope']), 'mode': row['mode'], 'lifetime': row['lifetime'],
                'spec_hash': row['spec_hash'], 'policy': row['policy']}

    def issue(self, db, rid, admin, credential):
        row = db.execute('SELECT * FROM requests WHERE id=?', (rid,)).fetchone()
        require(row is not None and row['status'] == 'pending' and row['expires'] > time.time(), 'stale_request')
        now, gid = int(time.time()), uuid.uuid4().hex
        expires = now + row['lifetime'] if row['mode'] == 'expiring' else (row['expires'] if row['mode'] == 'once' else 0)
        db.execute('INSERT INTO grants VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (gid, rid, row['project'], row['agent'], admin, credential, row['scope'], row['policy'], row['plan'],
                    row['mode'], now, expires, 1, 'active', None))
        db.execute("UPDATE requests SET status='approved' WHERE id=?", (rid,))
        self.event(db, admin, 'grant_issued', gid, {'request': rid, 'credential': credential.hex() if credential else None})

    def rpc(self, op, value):
        # Service-key API cannot issue/modify grants or register credentials.
        if op == 'propose':
            return self.propose(value)
        if op == 'check':
            return self.check(value)
        with self.db() as db:
            if op == 'request':
                row = db.execute('SELECT * FROM requests WHERE id=? AND agent=? AND project=?',
                                 (value['request_id'], value['agent'], value['project'])).fetchone()
                return self.public_request(row)
            if op == 'grants':
                return {'grants': [{'grant_id': r['id'], 'project': r['project'], 'scope': json.loads(r['scope']),
                                    'expires': r['expires'], 'revision': r['revision']} for r in self.grants(db, value['agent'], value['project'])]}
            if op == 'event':
                schema.fields(value, {'agent', 'task', 'project', 'status', 'grant_id'})
                require(value['status'] in ('queued', 'success', 'failed', 'recovery_required', 'outcome_unknown'))
                # At-least-once outbox delivery; audit insertion is idempotent.
                action = 'deployment_' + value['status']
                if not db.execute('SELECT 1 FROM audit WHERE actor=? AND action=? AND subject=?',
                                  (value['agent'], action, value['task'])).fetchone():
                    self.event(db, value['agent'], action, value['task'],
                               {'project': value['project'], 'grant_id': value['grant_id']})
                return {'status': 'recorded'}
        require(False)
