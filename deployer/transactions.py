"""Original-project transactions using only administrator registered declarations."""
import json
import re
import subprocess
import time
import uuid
from pathlib import PurePosixPath
from deployer import schema, registration
from deployer.adoption import inspect_project
from authorization import rpc
from authorization.scope import require, Denied

OPS = {'adoption_plan', 'adoption_request', 'adoption_apply', 'adoption_task'}


class Broker:
    def __init__(self, service):
        self.s = service
        with service.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS adoption_plans(id TEXT PRIMARY KEY, project TEXT, agent TEXT,
                    created INTEGER, policy TEXT, registration TEXT, action TEXT, scope TEXT, task TEXT);
                CREATE TABLE IF NOT EXISTS adoption_tasks(id TEXT PRIMARY KEY, plan TEXT UNIQUE, project TEXT,
                    agent TEXT, state TEXT, category TEXT, created INTEGER);
                CREATE TABLE IF NOT EXISTS adopted_projects(project TEXT PRIMARY KEY, agent TEXT,
                    baseline TEXT, recovery INTEGER, task TEXT);
            ''')
            for project, agent, task in db.execute("SELECT project,agent,id FROM adoption_tasks WHERE state='running'").fetchall():
                db.execute('INSERT OR REPLACE INTO adopted_projects VALUES (?,?,?,1,?)', (project, agent, '', task))
            db.execute("UPDATE adoption_tasks SET state='outcome_unknown',category='interrupted' WHERE state='running'")

    def target(self, cfg, project):
        require('adoption' in cfg and 'authorization' in cfg, 'adoption_not_configured')
        targets = registration.load(cfg['adoption']['registry'])['targets']
        require(project in targets, 'target_not_registered')
        entry=targets[project]
        protected=[cfg['workspace'],cfg['adoption']['registry'],cfg['authorization']['service_key'],
                   str(self.s.policy_path),str(self.s.runner.STATE_DIR)]
        for service in entry['compose']['services'].values():
            for mount in service['volumes']:
                source=PurePosixPath(mount['source'])
                for value in protected:
                    target=PurePosixPath(value)
                    require(source!=target and source not in target.parents and target not in source.parents,
                            'engine_storage_overlap')
        return entry

    @staticmethod
    def wanted(project, action, entry):
        return {'operations': ['adoption_' + action], 'project': project,
                'baseline_hash': entry['baseline']['baseline_hash'],
                'declaration_hash': entry['declaration_hash'], 'registration_hash': schema.fingerprint(entry),
                'preserve_original_project': True, 'pull_images': False, 'delete_data': False,
                'image_ids': sorted({r['image_id'] for r in entry['baseline']['containers']}),
                'container_names': sorted(r['name'] for r in entry['baseline']['containers']),
                'configuration_changes': {s:sorted(set(v)-{'image','container_name','volumes','ports','networks'})
                                          for s,v in entry['compose']['services'].items()},
                'configuration_notice': 'Administrator-reviewed configuration may differ from running runtime; exact declaration hash binds all private values.',
                'mode': 'single immutable transaction'}

    def verify(self, project, entry):
        actual = inspect_project(self.s.docker, project)
        require(actual['baseline_hash'] == entry['baseline']['baseline_hash'], 'baseline_drift')

    def record(self, db, agent, task, project, state):
        db.execute('INSERT INTO audit_outbox(value) VALUES (?)', (schema.canonical(
            {'agent':agent,'task':task,'project':project,'status':state,'grant_id':None}),))

    def dispatch(self, cfg, project, agent, op, payload):
        require(agent is not None and 'authorization' in cfg)
        if op == 'adoption_task':
            with self.s.db() as db:
                row = db.execute('SELECT state,category,plan FROM adoption_tasks WHERE id=? AND project=? AND agent=?',
                                 (payload['task_id'],project,agent)).fetchone()
            require(row is not None)
            return {'task_id':payload['task_id'],'status':row[0],'category':row[1],'plan_id':row[2]}
        if op == 'adoption_apply':
            with self.s.db() as db:
                previous=db.execute('SELECT task FROM adoption_plans WHERE id=? AND project=? AND agent=?',
                                    (payload['plan_id'],project,agent)).fetchone()
            if previous and previous[0]:
                return {'status':'accepted','task_id':previous[0]}
        with self.s.lock():
            cfg = self.s.policy(require_enabled=False)
            entry = self.target(cfg,project)
            rh, ph = schema.fingerprint(entry), schema.fingerprint(cfg)
            with self.s.db() as db:
                current = db.execute('SELECT agent,recovery FROM adopted_projects WHERE project=?', (project,)).fetchone()
                require(not current or not current[1], 'recovery_required')
                require(not current or current[0] == agent)
                require(not db.execute('SELECT 1 FROM projects WHERE id=?', (project,)).fetchone(), 'project_conflict')
                if op == 'adoption_plan':
                    require(payload['action'] != 'redeploy' or entry['allow_redeploy'], 'redeploy_not_approved')
                    require(not db.execute("SELECT 1 FROM adoption_tasks WHERE project=? AND state IN ('queued','running')", (project,)).fetchone(), 'busy')
                    require(db.execute('SELECT count(*) FROM adoption_plans').fetchone()[0]<10000,'rate_limited')
                    self.verify(project,entry)
                    pid = uuid.uuid4().hex
                    wanted = self.wanted(project,payload['action'],entry)
                    db.execute('INSERT INTO adoption_plans VALUES (?,?,?,?,?,?,?,?,NULL)',
                               (pid,project,agent,int(time.time()),ph,rh,payload['action'],schema.canonical(wanted)))
                    return {'status':'needs_approval','plan_id':pid,'scope':wanted,'expires_in':3600}
                row = db.execute('SELECT created,policy,registration,action,scope,task FROM adoption_plans WHERE id=? AND project=? AND agent=?',
                                 (payload['plan_id'],project,agent)).fetchone()
                require(row is not None)
                if op == 'adoption_apply' and row[5]:
                    return {'status':'accepted','task_id':row[5]}
                require(row[0]+3600>time.time() and row[1]==ph and row[2]==rh,'stale_request')
                auth = {'agent':agent,'project':project,'plan':payload['plan_id'],'policy':ph,'scope':json.loads(row[4])}
                if op == 'adoption_request':
                    return rpc.call(cfg['authorization'],'propose',{**auth,'spec_hash':rh,
                                    'mode':'once','lifetime':3600,'sandbox':False})
                require(op=='adoption_apply')
                require(not db.execute("SELECT 1 FROM adoption_tasks WHERE project=? AND state IN ('queued','running')", (project,)).fetchone(),'busy')
                self.verify(project,entry)
                task = uuid.uuid5(uuid.NAMESPACE_URL, 'compose-cd-adoption:'+project+':'+agent+':'+payload['plan_id']).hex
                rpc.call(cfg['authorization'],'transaction_authorize',{**auth,'task':task})
                db.execute('INSERT INTO adoption_tasks VALUES (?,?,?,?,?,?,?)',
                           (task,payload['plan_id'],project,agent,'queued','none',int(time.time())))
                db.execute('UPDATE adoption_plans SET task=? WHERE id=?',(task,payload['plan_id']))
                self.record(db,agent,task,project,'queued')
            self.s.event.set()
            return {'status':'accepted','task_id':task}

    def run_one(self):
        with self.s.lock(blocking=True):
            with self.s.db() as db:
                row = db.execute("SELECT t.id,t.plan,t.project,t.agent,p.policy,p.registration,p.action,p.scope,p.created FROM adoption_tasks t JOIN adoption_plans p ON t.plan=p.id WHERE t.state='queued' ORDER BY t.rowid LIMIT 1").fetchone()
                if not row:
                    return False
                task,pid,project,agent,ph,rh,action,wanted,created = row
                db.execute("UPDATE adoption_tasks SET state='running' WHERE id=?",(task,))
            mutated = False
            try:
                require(created+3600>time.time(),'stale_request')
                cfg = self.s.policy(require_enabled=False)
                require(schema.fingerprint(cfg)==ph,'policy_drift')
                entry = self.target(cfg,project)
                require(schema.fingerprint(entry)==rh,'registration_drift')
                with self.s.db() as db:
                    current=db.execute('SELECT recovery FROM adopted_projects WHERE project=?',(project,)).fetchone()
                    require(not current or not current[0],'recovery_required')
                self.verify(project,entry)
                auth={'agent':agent,'project':project,'plan':pid,'policy':ph,'scope':json.loads(wanted),'task':task}
                rpc.call(cfg['authorization'],'transaction_authorize',auth)
                if action=='redeploy':
                    require(entry['allow_redeploy'])
                    argv,env=self.prepare(task,project,entry)
                    # Recheck baseline, config and revocation after preparation.
                    fresh=self.s.policy(require_enabled=False)
                    require(schema.fingerprint(fresh)==ph,'policy_drift')
                    require(schema.fingerprint(self.target(fresh,project))==rh,'registration_drift')
                    self.verify(project,entry)
                    rpc.call(cfg['authorization'],'transaction_authorize',auth)
                    with self.s.db() as db:
                        db.execute('INSERT OR REPLACE INTO adopted_projects VALUES (?,?,?,1,?)',
                                   (project,agent,entry['baseline']['baseline_hash'],task))
                    mutated=True
                    subprocess.run(argv+['up','-d','--no-build','--pull','never','--no-deps',
                        '--wait','--wait-timeout',str(entry['health_timeout']),*sorted(entry['compose']['services'])],
                        env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                        timeout=entry['health_timeout']+120,check=True)
                    self.health(project,entry)
                with self.s.db() as db:
                    db.execute('INSERT OR REPLACE INTO adopted_projects VALUES (?,?,?,0,?)',
                               (project,agent,entry['baseline']['baseline_hash'],task))
                    db.execute("UPDATE adoption_tasks SET state='success',category='none' WHERE id=?",(task,))
                    self.record(db,agent,task,project,'success')
            except Exception as exc:
                state='recovery_required' if mutated else 'failed'
                category=exc.category if isinstance(exc,Denied) else 'operation_failed'
                with self.s.db() as db:
                    db.execute('UPDATE adoption_tasks SET state=?,category=? WHERE id=?',(state,category,task))
                    self.record(db,agent,task,project,state)
            return True

    def prepare(self, task, project, entry):
        # Revalidate independently at the execution boundary; no tagged images.
        registration.validate(project,entry)
        require(all(re.fullmatch('sha256:[a-f0-9]{64}',v['image']) for v in entry['compose']['services'].values()))
        directory=self.s.root/('adoption-'+task)
        directory.mkdir(mode=0o700)
        self.s.runner.write_json(directory/'compose.json',entry['compose'])
        argv=[self.s.runner.DOCKER,'--host','unix:///var/run/docker.sock','compose',
              '--project-name',project,'--project-directory',str(directory),
              '--file',str(directory/'compose.json')]
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/nonexistent','COMPOSE_DISABLE_ENV_FILE':'1'}
        subprocess.run(argv+['config','--quiet'],env=env,stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=True)
        return argv,env

    def health(self,project,entry):
        deadline=time.monotonic()+6
        def query(*args):
            remaining=deadline-time.monotonic()
            require(remaining>0,'readiness_timeout')
            return self.s.docker(*args,timeout=remaining)
        ids=query('ps','--all','--no-trunc','--quiet','--filter','label=com.docker.compose.project='+project).decode().split()
        require(len(ids)==len(entry['compose']['services']),'readiness_mismatch')
        observed=set()
        for cid in ids:
            require(re.fullmatch('[a-f0-9]{64}',cid))
            service=json.loads(query('inspect','--format',
                        '{{json (index .Config.Labels "com.docker.compose.service")}}',cid))
            require(service in entry['compose']['services'] and service not in observed,'readiness_mismatch')
            observed.add(service)
            cfg=entry['compose']['services'][service]
            require(query('inspect','--format','{{.Image}}',cid).decode().strip()==cfg['image'],'image_drift')
            require(json.loads(query('inspect','--format','{{json .Config.Healthcheck.Test}}',cid))==cfg['healthcheck']['test'],'readiness_mismatch')
            require(query('inspect','--format','{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}',cid).strip()==b'running healthy','readiness_failed')
