import copy
import json
import unittest
import time
import uuid
from authorization import agents
from deployer.transactions import Broker as Adoption
from unittest.mock import patch
from authorization.passkeys import Passkeys
from authorization.scope import Denied
from deployer import schema
from app_ingress.broker import Broker as Ingress
from test_authorization import Authenticator, ORIGIN, RP
from test_adoption_transactions import Transactions
from test_app_ingress import Transport


class Combined(Transactions):
    def setUp(self):
        super().setUp()
        self.cfg['operations'] += ['delegation_request']
        self.cfg['task_delegation'] = {'registry':'/etc/task-delegations.json'}
        self.icfg = {'version':1,'enabled':True,'hostname':'apps.example.ts.net','agents':[self.public],
                     'backends':{'autobangumi':{'dns':'app-autobangumi','port':7892,'local_port':21001,'https_port':9444}}}
        self.env = {'agent':self.agent,'registration_hash':schema.fingerprint(self.target),
                    'ingress_policy':schema.fingerprint(self.icfg),'backend':'autobangumi',
                    'backend_hash':schema.fingerprint(self.icfg['backends']['autobangumi']),
                    'route':{'hostname':'apps.example.ts.net','https_port':9444,'root_path':'/'},'max_lifetime':3600}
        self.registry = patch('deployer.registration.load_document',side_effect=lambda _: {'version':1,'targets':{'existing-app':self.env}})
        self.registry.start(); self.addCleanup(self.registry.stop)
        self.passkeys = Passkeys(self.store,RP,ORIGIN)
        self.owner = Authenticator()
        start = self.passkeys.begin('owner','enroll',token=self.store.bootstrap('owner'))
        self.passkeys.finish('owner',start['ceremony_id'],self.owner.response(start,register=True))
        self.transport = Transport()
        self.ingress = Ingress(self.service.root/'task-ingress.sqlite',lambda:self.icfg,self.transport,self.store.rpc)

    def grant(self):
        req = self.call('delegation_request',{'lifetime':3600})
        self.assertNotIn('must-not-return',json.dumps(req))
        start = self.passkeys.begin('owner','approve',req['request_id'],admin='owner')
        self.passkeys.finish('owner',start['ceremony_id'],self.owner.response(start),admin='owner')
        self.gid = self.store.rpc('grants',{'agent':self.agent,'project':'existing-app'})['grants'][-1]['grant_id']
        return self.gid

    def dplan(self,action='observe'):
        return self.call('adoption_plan',{'action':action,'delegation_id':self.gid})

    def apply(self,plan):
        return self.call('adoption_apply',{'plan_id':plan['plan_id'],'delegation_id':self.gid})

    def icall(self, operation, payload):
        value = {'version':1,'agent':self.agent,'public_key':self.public,
                 'audience':'compose-cd-shared-app-ingress-v1','operation':operation,'payload':payload,
                 'request_id':uuid.uuid4().hex,'timestamp':int(time.time())}
        return self.ingress.wire({'value':value,'signature':agents.sign(schema.canonical(value).encode(),self.key)})

    def iplan(self):
        return self.icall('plan',{'backend':'autobangumi','delegation_id':self.gid,'project':'existing-app'})

    def iapply(self,plan):
        return self.icall('apply',{'plan_id':plan['plan_id'],'delegation_id':self.gid,'project':'existing-app'})

    def test_single_passkey_inspect_adoption_ingress_without_more_requests(self):
        self.grant()
        with patch('deployer.service.rpc.call',side_effect=lambda cfg,op,value:self.store.rpc(op,value)),patch('deployer.adoption.inspect_project',return_value=self.target['baseline']):
            for _ in range(2): self.call('inspect',{'delegation_id':self.gid})
        task = self.apply(self.dplan()); self.service.run_one()
        self.assertEqual(self.task(task['task_id'])['status'],'success')
        self.assertEqual(self.iapply(self.iplan())['status'],'success')
        with self.store.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM requests').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM grants').fetchone()[0],1)
            self.assertGreaterEqual(db.execute('SELECT count(*) FROM delegation_receipts').fetchone()[0],5)

    def test_revoke_expiry_unpair_credential_stop_runner_and_broker(self):
        for state in ('revoke','expiry','unpair','credential'):
            with self.subTest(state=state):
                self.grant(); task = self.apply(self.dplan()); ip = self.iplan()
                with self.store.db() as db:
                    if state == 'revoke': db.execute("UPDATE grants SET status='revoked' WHERE id=?",(self.gid,))
                    if state == 'expiry': db.execute('UPDATE grants SET expires=1 WHERE id=?',(self.gid,))
                    if state == 'unpair': db.execute("UPDATE paired_agents SET status='revoked'")
                    if state == 'credential': db.execute('UPDATE credentials SET active=0')
                self.service.run_one()
                with self.service.db() as db:
                    self.assertEqual(db.execute('SELECT state FROM adoption_tasks WHERE id=?',(task['task_id'],)).fetchone()[0],'failed')
                with self.assertRaises(Denied): self.iapply(ip)
                with self.store.db() as db:
                    db.execute("UPDATE paired_agents SET status='active'")
                    db.execute('UPDATE credentials SET active=1')
        self.assertEqual(self.transport.count,0)

    def test_envelope_agent_registration_backend_and_project_mismatch(self):
        self.grant(); original = copy.deepcopy(self.env)
        for key,value in [('agent','other'),('registration_hash','d'*64)]:
            self.env[key] = value
            with self.assertRaises(Denied): self.dplan()
            self.env = copy.deepcopy(original)
        p = self.iplan()
        with self.assertRaises(Denied):
            self.ingress.dispatch(self.agent,'apply',{'plan_id':p['plan_id'],'delegation_id':self.gid,'project':'other'})
        self.icfg['backends']['autobangumi']['port'] += 1
        with self.assertRaises(Denied): self.iapply(p)
        self.icfg['backends']['autobangumi']['port'] -= 1
        with self.assertRaises(Denied):
            self.ingress.dispatch('other','apply',{'plan_id':p['plan_id'],'delegation_id':self.gid,'project':'existing-app'})

    def test_redeploy_transition_repeat_and_semantic_drift(self):
        self.grant(); task = self.apply(self.dplan('redeploy'))
        new = copy.deepcopy(self.target['baseline'])
        new['containers'][0]['container_id'] = 'e'*64
        new['containers'][0]['working_dir'] = '/private/generated'
        new['containers'][0]['config_files'] = ['/private/generated/compose.json']
        new['baseline_hash'] = schema.fingerprint({k:new[k] for k in ('project','containers')})
        def redeploy(*args,**kw):
            self.observer.stop()
            self.observer = patch('deployer.transactions.inspect_project',return_value=new)
            self.observer.start()
        with patch.object(self.service.adoption,'prepare',return_value=(['docker','compose'],{})),patch.object(self.service.adoption,'health'),patch('deployer.transactions.subprocess.run',side_effect=redeploy) as run:
            self.service.run_one()
        self.assertEqual(self.task(task['task_id'])['status'],'success')
        argv = run.call_args.args[0]
        self.assertIn('--no-build',argv); self.assertEqual(argv[argv.index('--pull')+1],'never')
        self.assertNotIn('down',argv); self.assertNotIn('--volumes',argv)
        self.apply(self.dplan()); self.service.run_one(); self.dplan()
        new['baseline_hash'] = 'drift'
        with self.assertRaises(Denied):self.dplan()

    def test_explicit_opt_in_no_ambient_union_or_policy_bypass(self):
        self.grant()
        with self.assertRaises(Denied):self.call('inspect')
        normal = self.plan()
        with self.assertRaises(Denied):self.call('adoption_apply',{'plan_id':normal['plan_id']})
        plain = self.icall('plan',{'backend':'autobangumi'})
        with self.assertRaises(Denied):self.icall('apply',{'plan_id':plain['plan_id']})
        self.cfg['operations'].remove('adoption_plan')
        with self.assertRaises(Denied):self.dplan()
        with self.assertRaises(Denied):self.call('delegation_request',{'lifetime':3600})
        with self.store.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM requests').fetchone()[0],1)

    def test_registry_envelope_widening_fails_at_worker(self):
        self.grant(); task = self.apply(self.dplan('redeploy'))
        self.env['max_lifetime'] = 7200
        with patch('deployer.transactions.subprocess.run') as run:
            self.service.run_one(); run.assert_not_called()
        self.assertEqual(self.task(task['task_id'])['status'],'failed')

    def test_interrupted_delegated_runner_no_replay(self):
        self.grant(); p = self.dplan('redeploy'); task = self.apply(p)
        with self.service.db() as db:
            db.execute("UPDATE adoption_tasks SET state='running' WHERE id=?",(task['task_id'],))
        Adoption(self.service)
        self.assertEqual(self.task(task['task_id'])['status'],'outcome_unknown')
        self.assertFalse(self.service.adoption.run_one())
        with self.assertRaises(Denied):self.dplan()
        self.assertEqual(self.apply(p)['task_id'],task['task_id'])

    def test_revoke_after_prepare_prevents_mutation(self):
        self.grant(); task = self.apply(self.dplan('redeploy'))
        def prepare(*args):
            with self.store.db() as db:db.execute("UPDATE grants SET status='revoked' WHERE id=?",(self.gid,))
            return ['docker','compose'],{}
        with patch.object(self.service.adoption,'prepare',side_effect=prepare),patch('deployer.transactions.subprocess.run') as run:
            self.service.run_one();run.assert_not_called()
        self.assertEqual(self.task(task['task_id'])['status'],'failed')

    def test_post_redeploy_mount_drift_latches_recovery(self):
        self.grant(); task = self.apply(self.dplan('redeploy'))
        new = copy.deepcopy(self.target['baseline'])
        new['containers'][0]['mounts'][0]['source']='/srv/other'
        def mutation(*args,**kwargs):
            self.observer.stop()
            self.observer=patch('deployer.transactions.inspect_project',return_value=new)
            self.observer.start()
        with patch.object(self.service.adoption,'prepare',return_value=(['docker','compose'],{})),patch.object(self.service.adoption,'health'),patch('deployer.transactions.subprocess.run',side_effect=mutation):
            self.service.run_one()
        self.assertEqual(self.task(task['task_id'])['status'],'recovery_required')
        with self.assertRaises(Denied):self.dplan()

    def test_immutable_subplans_and_receipts(self):
        import sqlite3
        self.grant(); self.dplan()
        with self.service.db() as db:
            for sql in ("UPDATE adoption_plans SET scope='{}'", 'DELETE FROM delegated_plans'):
                with self.assertRaises(sqlite3.IntegrityError):db.execute(sql)
        with self.store.db() as db:
            for sql in ('DELETE FROM delegation_receipts',"UPDATE delegation_receipts SET binding='evil'"):
                with self.assertRaises(sqlite3.IntegrityError):db.execute(sql)

    def test_unknown_ingress_no_blind_retry_or_delegated_recovery(self):
        self.grant(); p = self.iplan(); self.transport.lost = True
        self.assertEqual(self.iapply(p)['status'],'outcome_unknown')
        with self.assertRaises(Denied): self.iapply(p)
        recovery = self.ingress.dispatch(self.agent,'recovery_plan',{'plan_id':p['plan_id']})
        with self.assertRaises(Denied): self.iapply(recovery)
        self.assertEqual(self.transport.count,1)


if __name__ == '__main__': unittest.main()
