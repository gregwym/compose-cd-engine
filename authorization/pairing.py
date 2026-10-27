"""Passkey-owned pairing registry and a separate host-inventory capability."""
import hashlib
import json
import time
import uuid
from urllib.parse import urlsplit
from authorization import agents
from authorization.scope import require
from deployer import schema

INVENTORY_SCOPE = {'operations': ['inventory'], 'read_only': True,
                   'fields': ['project', 'service', 'name', 'image', 'state'],
                   'coverage': 'all Docker containers, including unmanaged applications'}
INVENTORY_POLICY = schema.fingerprint({'version': 1, 'scope': INVENTORY_SCOPE})
INVENTORY_PROJECT = 'nas-inventory'


def pair_request(raw):
    value = json.loads(raw)
    schema.fields(value, {'agent', 'public_key', 'audience', 'operation', 'label', 'request_id', 'timestamp'})
    schema.check(value['operation'] in ('pair', 'pair_status'))
    schema.check(isinstance(value['label'], str) and 1 <= len(value['label']) <= 80
                 and all(c.isprintable() for c in value['label']))
    schema.check(isinstance(value['request_id'], str) and schema.HEX.fullmatch(value['request_id'])
                 and type(value['timestamp']) is int)
    return value


class PairingStore:
    @staticmethod
    def init_pairing(db):
        db.executescript('''
            CREATE TABLE IF NOT EXISTS paired_agents(id TEXT PRIMARY KEY, public_key TEXT, label TEXT,
                admin TEXT, credential BLOB, created INTEGER, status TEXT);
            CREATE TABLE IF NOT EXISTS pairings(id TEXT PRIMARY KEY, agent TEXT, public_key TEXT, label TEXT,
                created INTEGER, expires INTEGER, status TEXT);
        ''')

    def pair(self, raw, signature):
        value = agents.authenticate(raw, signature, self.path + '.pair-nonces', pair_request)
        require(value['audience'] == urlsplit(self.origin).hostname)
        now = int(time.time())
        agent = value['agent']
        with self.db() as db:
            require(db.execute('SELECT 1 FROM credentials WHERE active=1 LIMIT 1').fetchone())
            active = db.execute("SELECT 1 FROM paired_agents WHERE id=? AND public_key=? AND status='active'",
                                (agent, value['public_key'])).fetchone()
            if active:
                return {'status': 'paired', 'agent': agent}
            db.execute("UPDATE pairings SET status='expired' WHERE status='pending' AND expires<=?", (now,))
            row = db.execute("SELECT * FROM pairings WHERE agent=? ORDER BY created DESC,rowid DESC LIMIT 1", (agent,)).fetchone()
            if value['operation'] == 'pair' and (not row or row['status'] != 'pending'):
                require(db.execute('SELECT count(*) FROM pairings WHERE created>?', (now-3600,)).fetchone()[0] < 40, 'rate_limited')
                require(db.execute('SELECT count(*) FROM pairings').fetchone()[0] < 10000, 'rate_limited')
                rid = uuid.uuid4().hex
                db.execute('INSERT INTO pairings VALUES (?,?,?,?,?,?,?)',
                           (rid, agent, value['public_key'], value['label'], now, now + 600, 'pending'))
                self.event(db, agent, 'pairing_requested', rid)
                row = db.execute('SELECT * FROM pairings WHERE id=?', (rid,)).fetchone()
            require(row is not None)
            return {'status': row['status'], 'agent': agent, 'fingerprint': hashlib.sha256(bytes.fromhex(row['public_key'])).hexdigest(),
                    'approval_url': self.origin + '/pairings/' + row['id'], 'expires': row['expires']}

    def paired(self, agent, public, audience):
        require(agent == agents.identity(public))
        require(audience == urlsplit(self.origin).hostname)
        with self.db() as db:
            require(db.execute("SELECT 1 FROM paired_agents WHERE id=? AND public_key=? AND status='active'",
                               (agent, public)).fetchone())
        return {'status': 'paired'}

    def approve_pair(self, db, rid, admin, credential):
        row = db.execute('SELECT * FROM pairings WHERE id=?', (rid,)).fetchone()
        require(row and row['status'] == 'pending' and row['expires'] > time.time(), 'stale_request')
        require(db.execute("SELECT count(*) FROM paired_agents WHERE status='active'").fetchone()[0] < 64, 'rate_limited')
        db.execute('INSERT OR REPLACE INTO paired_agents VALUES (?,?,?,?,?,?,?)',
                   (row['agent'], row['public_key'], row['label'], admin, credential, int(time.time()), 'active'))
        db.execute("UPDATE pairings SET status='approved' WHERE id=?", (rid,))
        self.event(db, admin, 'agent_paired', row['agent'])

    def inventory_request(self, value):
        schema.fields(value, {'agent', 'mode', 'lifetime'})
        return self.propose({'agent': value['agent'], 'project': INVENTORY_PROJECT,
            'plan': uuid.uuid4().hex, 'spec_hash': schema.fingerprint(INVENTORY_SCOPE),
            'policy': INVENTORY_POLICY, 'scope': INVENTORY_SCOPE, 'sandbox': False,
            'mode': value['mode'], 'lifetime': value['lifetime']})

    def inventory_access(self, agent):
        with self.db() as db:
            self.require_active_agent(db, agent)
            for row in self.grants(db, agent, INVENTORY_PROJECT):
                if row['policy'] == INVENTORY_POLICY and json.loads(row['scope']) == INVENTORY_SCOPE:
                    if row['mode'] == 'once':
                        db.execute("UPDATE grants SET status='consumed',revision=revision+1 WHERE id=?", (row['id'],))
                    self.event(db, agent, 'inventory_read', row['id'])
                    return {'status': 'authorized'}
        require(False)
