"""The only database: Passkeys, agents, requests, grants, jobs, triggers, routes, audit."""
import json
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from shared.wire import Denied, canonical, digest

SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS credentials(id BLOB PRIMARY KEY, data BLOB, counter INTEGER, active INTEGER, created INTEGER);
CREATE TABLE IF NOT EXISTS enrollment(token TEXT PRIMARY KEY, expires INTEGER);
CREATE TABLE IF NOT EXISTS ceremonies(id TEXT PRIMARY KEY, session TEXT, action TEXT, target TEXT,
    binding TEXT, state TEXT, expires INTEGER);
CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY, public_key TEXT, label TEXT, status TEXT,
    token TEXT UNIQUE, created INTEGER, expires INTEGER);
CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, agent TEXT, project TEXT, kind TEXT, detail TEXT,
    status TEXT, created INTEGER, expires INTEGER, decided INTEGER, outcome TEXT);
CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, agent TEXT, project TEXT, identity TEXT,
    created INTEGER, expires INTEGER, status TEXT, request TEXT);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, actor TEXT, project TEXT, op TEXT, status TEXT,
    result TEXT, created INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS triggers(id TEXT PRIMARY KEY, project TEXT, service TEXT, config TEXT,
    identity TEXT, secret TEXT, last TEXT, status TEXT, request TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS routes(https_port INTEGER PRIMARY KEY, project TEXT, target_port INTEGER,
    request TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS nonces(id TEXT PRIMARY KEY, expires INTEGER);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, created INTEGER, actor TEXT, action TEXT,
    subject TEXT, detail TEXT);
CREATE TRIGGER IF NOT EXISTS audit_append_only_u BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_append_only_d BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append only'); END;
'''
REQUEST_TTL = 3600
PAIRING_TTL = 600


def now():
    return int(time.time())


class Store:
    def __init__(self, path):
        self.path = str(path)
        setup = sqlite3.connect(self.path)
        setup.executescript(SCHEMA)
        # Additive migration: old grants remain legacy, never acquire manage/read scope.
        columns = {r[1] for r in setup.execute('PRAGMA table_info(grants)')}
        for name, declaration in [('scope', "TEXT NOT NULL DEFAULT 'legacy'"),
                                  ('boundary', "TEXT NOT NULL DEFAULT '{}'")]:
            if name not in columns:
                setup.execute(f'ALTER TABLE grants ADD COLUMN {name} {declaration}')
        setup.commit()
        setup.close()
        with self.db() as db:
            # A restart loses the thread executing a job; its outcome must be checked, not retried.
            for row in db.execute("SELECT id FROM jobs WHERE status IN ('queued','running')").fetchall():
                db.execute("UPDATE jobs SET status='unknown', updated=? WHERE id=?", (now(), row['id']))
                self.event(db, 'system', 'job_unknown', row['id'])

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN IMMEDIATE')
            try:
                yield db
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise
        finally:
            db.close()

    @staticmethod
    def event(db, actor, action, subject, detail=None):
        db.execute('INSERT INTO audit(created, actor, action, subject, detail) VALUES (?,?,?,?,?)',
                   (now(), actor, action, subject, canonical(detail or {})))

    def meta(self, key, value=None):
        with self.db() as db:
            row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
            if row is None and value is not None:
                db.execute('INSERT INTO meta VALUES (?,?)', (key, value))
                return value
            return row['value'] if row else None

    # Replay protection ----------------------------------------------------
    def nonce(self, value, ttl=130):
        with self.db() as db:
            db.execute('DELETE FROM nonces WHERE expires<?', (now(),))
            if db.execute('SELECT 1 FROM nonces WHERE id=?', (value,)).fetchone():
                raise Denied('replay')
            if db.execute('SELECT count(*) FROM nonces').fetchone()[0] >= 100000:
                raise Denied('rate_limited')
            db.execute('INSERT INTO nonces VALUES (?,?)', (value, now() + ttl))

    # Enrollment -----------------------------------------------------------
    def enrolled(self):
        with self.db() as db:
            return bool(db.execute('SELECT 1 FROM credentials WHERE active=1').fetchone())

    def enrollment_code(self):
        """A single-use 10 minute code, only while no Passkey exists."""
        with self.db() as db:
            if db.execute('SELECT 1 FROM credentials WHERE active=1').fetchone():
                return None
            token = secrets.token_urlsafe(18)
            db.execute('DELETE FROM enrollment')
            db.execute('INSERT INTO enrollment VALUES (?,?)', (digest(token.encode()), now() + 600))
            self.event(db, 'console', 'enrollment_opened', '')
            return token

    # Agents ---------------------------------------------------------------
    def pair(self, agent, public_key, label):
        with self.db() as db:
            row = db.execute('SELECT * FROM agents WHERE id=?', (agent,)).fetchone()
            if row and row['status'] == 'active':
                return dict(row)
            if row and row['status'] == 'pending' and row['expires'] > now():
                return dict(row)
            recent = db.execute('SELECT count(*) FROM agents WHERE created>?', (now() - 3600,)).fetchone()[0]
            if recent >= 20:
                raise Denied('rate_limited')
            token = secrets.token_urlsafe(24)
            db.execute('INSERT OR REPLACE INTO agents VALUES (?,?,?,?,?,?,?)',
                       (agent, public_key, label, 'pending', token, now(), now() + PAIRING_TTL))
            self.event(db, agent, 'pairing_requested', agent, {'label': label})
            return dict(db.execute('SELECT * FROM agents WHERE id=?', (agent,)).fetchone())

    def agent(self, agent):
        with self.db() as db:
            row = db.execute('SELECT * FROM agents WHERE id=?', (agent,)).fetchone()
            return dict(row) if row else None

    def active_agent(self, agent, public_key):
        row = self.agent(agent)
        if not row or row['status'] != 'active' or row['public_key'] != public_key:
            raise Denied('not_paired')
        return row

    # Requests -------------------------------------------------------------
    def create_request(self, agent, project, kind, detail):
        with self.db() as db:
            pending = db.execute("SELECT count(*) FROM requests WHERE agent=? AND status='pending' AND expires>?",
                                 (agent, now())).fetchone()[0]
            if pending >= 20:
                raise Denied('rate_limited')
            rid = secrets.token_urlsafe(18)
            db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (rid, agent, project, kind, canonical(detail), 'pending', now(), now() + REQUEST_TTL, None, None))
            self.event(db, agent, 'request_created', rid, {'kind': kind, 'project': project})
            return rid

    @staticmethod
    def decode(row):
        if row is None:
            return None
        item = dict(row)
        for key in ('detail', 'outcome', 'identity', 'result', 'config', 'last', 'boundary'):
            if item.get(key):
                item[key] = json.loads(item[key])
        if item.get('status') == 'pending' and item.get('expires') and item['expires'] <= now():
            item['status'] = 'expired'
        return item

    def request(self, rid):
        with self.db() as db:
            return self.decode(db.execute('SELECT * FROM requests WHERE id=?', (rid,)).fetchone())

    def finish_request(self, rid, outcome):
        with self.db() as db:
            db.execute('UPDATE requests SET outcome=? WHERE id=?', (canonical(outcome), rid))

    # Grants ---------------------------------------------------------------
    def add_grant(self, db, agent, project, identity, lifetime, request, scope='legacy', boundary=None):
        if scope not in ('legacy', 'read', 'manage', 'elevated'):
            raise Denied('invalid_argument', 'scope')
        if scope == 'elevated' and (type(lifetime) is not int or not 1 <= lifetime <= 3600):
            raise Denied('invalid_argument', 'elevated lifetime')
        expires = None if lifetime is None else now() + lifetime
        db.execute("UPDATE grants SET status='replaced' WHERE agent=? AND project=? AND scope=? AND status='active'",
                   (agent, project, scope))
        gid = uuid.uuid4().hex
        db.execute('INSERT INTO grants(id,agent,project,identity,created,expires,status,request,scope,boundary) '
                   'VALUES (?,?,?,?,?,?,?,?,?,?)',
                   (gid, agent, project, canonical(identity), now(), expires, 'active', request, scope,
                    canonical(boundary or {})))
        self.event(db, 'owner', 'grant_issued', gid, {'agent': agent, 'project': project, 'scope': scope, 'expires': expires})
        return gid

    def grant(self, agent, project, scope=None):
        candidates = [g for g in self.grants(agent) if g['project'] == project
                      and (g['scope'] == scope if scope else g['scope'] in ('manage', 'legacy'))]
        return next(iter(sorted(candidates, key=lambda g: g['scope'] != 'manage')), None)

    def grants(self, agent=None):
        with self.db() as db:
            rows = db.execute("SELECT * FROM grants WHERE status='active' AND (expires IS NULL OR expires>?)" +
                              (' AND agent=?' if agent else '') + ' ORDER BY created DESC',
                              (now(), agent) if agent else (now(),)).fetchall()
            return [self.decode(r) for r in rows]

    # Jobs -----------------------------------------------------------------
    def create_job(self, actor, project, op):
        jid = uuid.uuid4().hex
        with self.db() as db:
            db.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?)', (jid, actor, project, op, 'queued', None, now(), now()))
            self.event(db, actor, 'job_' + op, jid, {'project': project})
        return jid

    def update_job(self, jid, status, result=None):
        with self.db() as db:
            db.execute('UPDATE jobs SET status=?, result=?, updated=? WHERE id=?',
                       (status, canonical(result) if result is not None else None, now(), jid))
            if status not in ('queued', 'running'):
                self.event(db, 'runner', 'job_' + status, jid)

    def job(self, jid):
        with self.db() as db:
            return self.decode(db.execute('SELECT * FROM jobs WHERE id=?', (jid,)).fetchone())

    # Read models for the owner's page ------------------------------------
    def dashboard(self):
        with self.db() as db:
            q = lambda sql, *a: [self.decode(r) for r in db.execute(sql, a).fetchall()]
            return {
                'requests': q("SELECT * FROM requests WHERE status='pending' AND expires>? ORDER BY created DESC", now()),
                'agents': q("SELECT id, label, status, created FROM agents WHERE status IN ('active','pending') ORDER BY created DESC"),
                'grants': q("SELECT * FROM grants WHERE status='active' AND (expires IS NULL OR expires>?) ORDER BY created DESC", now()),
                'triggers': q("SELECT id, project, service, config, status, last, created FROM triggers ORDER BY created DESC"),
                'routes': q('SELECT * FROM routes ORDER BY https_port'),
                'jobs': q('SELECT * FROM jobs ORDER BY created DESC LIMIT 30'),
                'credentials': [bytes(r['id']).hex() for r in db.execute('SELECT id FROM credentials WHERE active=1')],
                'audit': q('SELECT * FROM audit ORDER BY seq DESC LIMIT 100'),
            }
