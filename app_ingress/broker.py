"""Network-isolated, signed fixed-action ingress broker; no Docker or exec authority."""
import copy
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from authorization import agents, rpc
from authorization.scope import require, Denied
from deployer import schema, ingress
from app_ingress.policy import validate


class Broker:
    def __init__(self, database, config, transport, authorize):
        self.database, self.config, self.transport, self.authorize = str(database), config, transport, authorize
        with self.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY, agent TEXT, backend TEXT, created INTEGER, policy TEXT, document TEXT);
                CREATE TABLE IF NOT EXISTS receipts(seq INTEGER PRIMARY KEY, plan TEXT, status TEXT, detail TEXT, created INTEGER);
                CREATE TRIGGER IF NOT EXISTS immutable_plans_update BEFORE UPDATE ON plans BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_plans_delete BEFORE DELETE ON plans BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_receipts_update BEFORE UPDATE ON receipts BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_receipts_delete BEFORE DELETE ON receipts BEGIN SELECT RAISE(ABORT,'immutable'); END;
            ''')
        # In-flight mutations are never blindly replayed; recovery requires fresh signed approval.
        with self.db() as db:
            pending = db.execute("SELECT p.id FROM plans p WHERE (SELECT status FROM receipts WHERE plan=p.id ORDER BY seq DESC LIMIT 1)='applying'").fetchall()
            for (pid,) in pending:
                self.record(db, pid, 'outcome_unknown', {'reason':'interrupted'})

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.database, timeout=10)
        try:
            with db:
                db.execute('BEGIN IMMEDIATE')
                yield db
        finally:
            db.close()

    @staticmethod
    def record(db, pid, status, detail):
        db.execute('INSERT INTO receipts(plan,status,detail,created) VALUES (?,?,?,?)',
                   (pid, status, schema.canonical(detail), int(time.time())))

    def wire(self, envelope):
        schema.fields(envelope, {'value', 'signature'})
        def validator(raw):
            value = json.loads(raw)
            schema.fields(value, {'version','agent','public_key','audience','operation','payload','request_id','timestamp'})
            require(value['version'] == 1 and value['audience'] == 'compose-cd-shared-app-ingress-v1')
            require(type(value['timestamp']) is int and isinstance(value['request_id'], str) and schema.HEX.fullmatch(value['request_id']))
            return value
        value = agents.authenticate(schema.canonical(envelope['value']).encode(), envelope['signature'], self.database, validator, reserve=False)
        cfg = validate(self.config())
        require(cfg['enabled'], 'ingress_disabled')
        require(value['public_key'] in cfg['agents'])
        from management.protocol import reserve_nonce
        reserve_nonce(value, self.database)
        return self.dispatch(value['agent'], value['operation'], value['payload'], cfg)

    def dispatch(self, agent, operation, payload, cfg=None):
        cfg = validate(self.config()) if cfg is None else cfg
        require(cfg['enabled'], 'ingress_disabled')
        require(operation in ('plan','request','apply','receipt','recovery_plan'))
        schema.fields(payload, {'backend'} if operation == 'plan' else {'plan_id'},
                      {'delegation_id','project'} if operation in ('plan','apply') else ())
        require(('delegation_id' in payload) == ('project' in payload))
        if 'delegation_id' in payload:
            require(isinstance(payload['delegation_id'],str) and schema.HEX.fullmatch(payload['delegation_id']))
            schema.name(payload['project'])
        policy = schema.fingerprint(cfg)
        with self.db() as db:
            if operation == 'plan':
                backend = payload['backend']
                require(isinstance(backend, str) and backend in cfg['backends'], 'unknown_backend')
                require(db.execute('SELECT count(*) FROM plans').fetchone()[0] < 10000, 'rate_limited')
                require(not self.blocked(db), 'recovery_required')
                baseline, _ = self.transport.snapshot()
                entry = cfg['backends'][backend]
                upstream = 'http://127.0.0.1:' + str(entry['local_port'])
                built = ingress.plan(baseline, hostname=cfg['hostname'], port=entry['https_port'], upstream=upstream, allowed_upstreams=[upstream])
                document = {'baseline':baseline, 'candidate':built['candidate'], 'baseline_hash':built['baseline_hash'],
                            'candidate_hash':built['candidate_hash'], 'backend_hash':schema.fingerprint(entry), 'recovery_of':None,
                            'route':{'hostname':cfg['hostname'],'https_port':entry['https_port'],'root_path':'/'}}
                if 'delegation_id' in payload:
                    document['delegation_id'] = payload['delegation_id']
                    document['project'] = payload['project']
                return self.save(db, agent, backend, policy, document)
            pid = payload['plan_id']
            require(isinstance(pid, str) and schema.HEX.fullmatch(pid))
            row = db.execute('SELECT backend,created,policy,document FROM plans WHERE id=? AND agent=?', (pid,agent)).fetchone()
            require(row is not None)
            backend, created, ph, raw = row
            document = json.loads(raw)
            receipt = db.execute('SELECT status,detail FROM receipts WHERE plan=? ORDER BY seq DESC LIMIT 1', (pid,)).fetchone()
            if operation == 'receipt':
                return {'plan_id':pid, 'status':receipt[0] if receipt else 'planned', 'detail':json.loads(receipt[1]) if receipt else {}}
            require(ph == policy and backend in cfg['backends'], 'policy_drift')
            require(document['backend_hash'] == schema.fingerprint(cfg['backends'][backend]), 'backend_drift')
            if operation == 'recovery_plan':
                require(receipt and receipt[0] in ('outcome_unknown','recovery_required'))
                require(not document['recovery_of'], 'administrator_recovery_required')
                actual, _ = self.transport.snapshot()
                # Restore only from a known old/new document. Unrelated manual drift needs administrator investigation.
                require(actual in (document['baseline'], document['candidate']), 'unrecognized_serve_state')
                recovery = {'baseline':actual, 'candidate':document['baseline'], 'baseline_hash':schema.fingerprint(actual),
                    'candidate_hash':document['baseline_hash'], 'backend_hash':document['backend_hash'], 'recovery_of':pid, 'route':document['route']}
                return self.save(db, agent, backend, policy, recovery)
            if operation == 'apply' and receipt and receipt[0] in ('success','recovered'):
                return {'plan_id':pid,'status':receipt[0]}
            require(created + 3600 > time.time(), 'stale_plan')
            require(not receipt, 'recovery_required')
            require(not self.blocked(db, document['recovery_of']), 'recovery_required')
            delegation = document.get('delegation_id')
            require(payload.get('delegation_id') == delegation and payload.get('project') == document.get('project'))
            wanted = self.scope(backend, document)
            auth = {'agent':agent,'project':'shared-app-ingress','plan':pid,'policy':policy,'scope':wanted}
            if operation == 'request':
                return self.authorize('propose', {**auth,'spec_hash':schema.fingerprint(document), 'mode':'once','lifetime':3600,'sandbox':False})
            require(operation == 'apply')
            actual, tag = self.transport.snapshot()
            require(actual == document['baseline'], 'ingress_drift')
            require(schema.fingerprint(validate(self.config())) == policy, 'policy_drift')
            if delegation:
                require(self.authorize('delegation_authorize', {**auth,'task':pid,
                    'project':document['project'],'kind':'ingress','delegation_id':delegation}).get('status') == 'authorized')
            else:
                require(self.authorize('ingress_authorize', {**auth,'task':pid}).get('status') == 'authorized')
            self.record(db,pid,'applying',{'baseline_hash':document['baseline_hash'],'candidate_hash':document['candidate_hash']})
        # Intent is durably committed BEFORE attempting the CAS. Server is serial and holds a process lock.
        try:
            self.transport.replace(document['candidate'], tag)
            actual, _ = self.transport.snapshot()
            require(actual == document['candidate'], 'verification_failed')
            status = 'recovered' if document['recovery_of'] else 'success'
        except Exception:
            status = 'outcome_unknown'
        with self.db() as db:
            self.record(db, pid, status, {'candidate_hash':document['candidate_hash']})
            if status == 'recovered':
                self.record(db, document['recovery_of'], 'recovered', {'recovery_plan':pid})
        return {'plan_id':pid,'status':status}

    @staticmethod
    def blocked(db, except_plan=None):
        return db.execute("SELECT p.id FROM plans p WHERE p.id!=? AND (SELECT status FROM receipts WHERE plan=p.id ORDER BY seq DESC LIMIT 1) IN ('applying','outcome_unknown','recovery_required')", (except_plan or '',)).fetchone()

    @staticmethod
    def scope(backend, document):
        return {'operations':['shared_ingress_apply'], 'backend':backend, 'baseline_hash':document['baseline_hash'],
                'candidate_hash':document['candidate_hash'], 'backend_hash':document['backend_hash'],
                'tailnet_only':True, 'recovery_of':document['recovery_of'], 'no_app_redeploy':True, 'route':document['route']}

    def save(self, db, agent, backend, policy, document):
        pid = uuid.uuid4().hex
        db.execute('INSERT INTO plans VALUES (?,?,?,?,?,?)', (pid,agent,backend,int(time.time()),policy,schema.canonical(document)))
        delegated = document.get('delegation_id')
        if delegated:
            require(self.authorize('delegation_authorize', {'agent':agent,'project':document['project'],
                'plan':pid,'task':uuid.uuid5(uuid.NAMESPACE_URL,'ingress-plan:'+pid).hex,
                'policy':policy,'scope':self.scope(backend,document),'kind':'ingress',
                'delegation_id':delegated}).get('status') == 'authorized')
        return {'plan_id':pid,'status':'authorized' if delegated else 'needs_approval',
                'scope':self.scope(backend,document),'expires_in':3600}
