import copy
import json
import subprocess
import time
import uuid
import unittest
from unittest.mock import Mock, patch
from deployer import schema, registration
from deployer.transactions import Broker
from deployer.adoption import inspect_project
from authorization.scope import Denied
import test_adoption_foundation as foundation
import test_pairing_inventory as pairing


def entry():
    docker=Mock(side_effect=[foundation.CID.encode(),json.dumps(foundation.row()).encode(),foundation.CID.encode()])
    baseline=inspect_project(docker,'existing-app')
    compose={'services':{'web':{'image':'sha256:'+'b'*64,'container_name':'existing_web',
        'volumes':[{'type':'bind','source':'/srv/data','target':'/data','read_only':False,'bind':{'create_host_path':False}}],
        'ports':[{'target':8080,'published':18080,'protocol':'tcp','host_ip':'0.0.0.0'}],
        'networks':['existing'],'environment':{'PRIVATE_SETTING':'must-not-return'},
        'healthcheck':{'test':['CMD','python3','-c','import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080")'],
                       'interval':'1s','timeout':'1s','retries':10,'start_period':'1s'}}},
        'networks':{'existing':{'external':True,'name':'existing_default'}}}
    return {'baseline':baseline,'compose':compose,'declaration_hash':schema.fingerprint(compose),
            'allow_redeploy':True,'health_timeout':10}


class RegistrationBoundary(unittest.TestCase):
    def test_canonical_and_privilege_rejections(self):
        original=entry(); registration.validate('existing-app',original)
        for key,value in [('privileged',True),('command',['evil']),('network_mode','host'),
                          ('cap_add',['ALL']),('security_opt',['seccomp:unconfined']),('environment',{'TOKEN':'$HOST_SECRET'})]:
            changed=copy.deepcopy(original); changed['compose']['services']['web'][key]=value
            changed['declaration_hash']=schema.fingerprint(changed['compose'])
            with self.subTest(key=key),self.assertRaises((Denied,ValueError)):
                registration.validate('existing-app',changed)
        changed=copy.deepcopy(original)
        changed['baseline']['containers'][0]['image_id']='example.invalid/app:latest'
        changed['baseline']['baseline_hash']=schema.fingerprint({k:changed['baseline'][k] for k in ('project','containers')})
        changed['compose']['services']['web']['image']='example.invalid/app:latest'
        changed['declaration_hash']=schema.fingerprint(changed['compose'])
        with self.assertRaises(ValueError): registration.validate('existing-app',changed)

    def test_mount_port_image_and_declaration_drift(self):
        for mutate in (lambda e:e['compose']['services']['web'].update(image='sha256:'+'c'*64),
                       lambda e:e['compose']['services']['web']['volumes'][0].update(source='/srv/other'),
                       lambda e:e['compose']['services']['web']['ports'][0].update(published=18081)):
            e=entry(); mutate(e); e['declaration_hash']=schema.fingerprint(e['compose'])
            with self.assertRaises(Denied): registration.validate('existing-app',e)
        e=entry();e['declaration_hash']='changed'
        with self.assertRaises(Denied): registration.validate('existing-app',e)


class Transactions(unittest.TestCase):
    wire = pairing.RunnerBoundary.wire
    def setUp(self):
        pairing.RunnerBoundary.setUp(self)
        self.cfg['adoption']={'registry':'/etc/registered-targets.json'}
        self.target=entry()
        self.loader=patch('deployer.registration.load',side_effect=lambda path:{'version':1,'targets':{'existing-app':self.target}})
        self.loader.start()
        self.observer=patch('deployer.transactions.inspect_project',side_effect=lambda *a,**kw:copy.deepcopy(self.target['baseline']))
        self.observer.start()
        with self.store.db() as db:
            db.execute('INSERT INTO paired_agents VALUES (?,?,?,?,?,?,?)',
                       (self.agent,self.public,'test','owner',None,int(time.time()),'active'))

    def tearDown(self):
        self.observer.stop();self.loader.stop();pairing.RunnerBoundary.tearDown(self)

    def call(self,op,payload=None,**kwargs):
        return self.service.dispatch_wire(self.wire(op,payload,project='existing-app',**kwargs))

    def plan(self,action='observe'):
        return self.call('adoption_plan',{'action':action})

    def approve(self,pid):
        req=self.call('adoption_request',{'plan_id':pid})
        with self.store.db() as db:self.store.issue(db,req['request_id'],'owner',None)
        return req

    def task(self,tid):
        return self.call('adoption_task',{'task_id':tid})

    def test_independent_approval_idempotent_adoption_without_mutation(self):
        p=self.plan(); self.assertNotIn('must-not-return',json.dumps(p))
        with self.assertRaises(Denied):self.call('adoption_apply',{'plan_id':p['plan_id']})
        self.approve(p['plan_id'])
        task=self.call('adoption_apply',{'plan_id':p['plan_id']})
        with patch.object(self.service,'docker') as docker:
            self.assertTrue(self.service.run_one());docker.assert_not_called()
        self.assertEqual(self.task(task['task_id'])['status'],'success')
        self.assertEqual(task,self.call('adoption_apply',{'plan_id':p['plan_id']}))
        with self.service.db() as db:self.assertEqual(db.execute('SELECT agent,recovery FROM adopted_projects').fetchone(),(self.agent,0))

    def test_lost_binding_response_reuses_same_task_without_new_authority(self):
        p=self.plan();self.approve(p['plan_id'])
        first=True
        def lost(cfg,op,value):
            nonlocal first
            result=self.store.rpc(op,value)
            if op=='transaction_authorize' and first:
                first=False
                raise OSError('lost response')
            return result
        with patch('deployer.transactions.rpc.call',side_effect=lost):
            with self.assertRaises(OSError):self.call('adoption_apply',{'plan_id':p['plan_id']})
            task=self.call('adoption_apply',{'plan_id':p['plan_id']})
        with self.store.db() as db:
            self.assertEqual(db.execute('SELECT task FROM transaction_grants').fetchone()[0],task['task_id'])
        with self.service.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM adoption_tasks').fetchone()[0],1)

    def test_baseline_drift_and_other_agent_plan_visibility(self):
        p=self.plan()
        self.approve(p['plan_id'])
        with patch('deployer.transactions.inspect_project',return_value={'baseline_hash':'drift'}):
            with self.assertRaises(Denied):self.call('adoption_apply',{'plan_id':p['plan_id']})
        with self.service.db() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM adoption_tasks').fetchone())
        with self.assertRaises(Denied):
            self.service.adoption.dispatch(self.cfg,'existing-app','other','adoption_request',{'plan_id':p['plan_id']})

    def test_binding_revocation_and_cross_task_reuse(self):
        p=self.plan();self.approve(p['plan_id']);task=self.call('adoption_apply',{'plan_id':p['plan_id']})
        with self.store.db() as db:
            bound=db.execute('SELECT grant_id FROM transaction_grants WHERE task=?',(task['task_id'],)).fetchone()[0]
            db.execute("UPDATE grants SET status='revoked' WHERE id=?",(bound,))
        self.service.run_one()
        self.assertEqual(self.task(task['task_id'])['status'],'failed')
        with self.service.db() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM adopted_projects').fetchone())

    def test_baseline_and_registry_drift_fail_before_mutation(self):
        p=self.plan();self.approve(p['plan_id']);task=self.call('adoption_apply',{'plan_id':p['plan_id']})
        self.target['health_timeout']=20
        with patch('deployer.transactions.subprocess.run') as run:
            self.service.run_one();run.assert_not_called()
        self.assertEqual(self.task(task['task_id'])['category'],'registration_drift')

    def test_redeploy_failure_latches_recovery_and_no_replay(self):
        p=self.plan('redeploy');self.approve(p['plan_id']);task=self.call('adoption_apply',{'plan_id':p['plan_id']})
        with patch.object(self.service.adoption,'prepare',return_value=(['docker','compose'],{})),patch('deployer.transactions.subprocess.run',side_effect=subprocess.CalledProcessError(1,['docker'])) as run:
            self.service.run_one()
        argv=run.call_args.args[0]
        self.assertIn('--no-build',argv);self.assertEqual(argv[argv.index('--pull')+1],'never')
        self.assertNotIn('down',argv)
        self.assertEqual(self.task(task['task_id'])['status'],'recovery_required')
        self.assertEqual(self.call('adoption_apply',{'plan_id':p['plan_id']})['task_id'],task['task_id'])
        with self.assertRaises(Denied):self.plan()
        with self.service.db() as db:
            db.execute("UPDATE adoption_tasks SET state='running' WHERE id=?",(task['task_id'],))
        Broker(self.service)
        self.assertEqual(self.task(task['task_id'])['status'],'outcome_unknown')
        self.assertFalse(self.service.adoption.run_one())

    def test_payload_paths_and_unknown_targets_denied(self):
        with self.assertRaises(ValueError):self.call('adoption_plan',{'action':'observe','compose':'/etc/shadow'})
        self.loader.stop()
        with patch('deployer.registration.load',return_value={'version':1,'targets':{}}):
            with self.assertRaises(Denied):self.plan()
        self.loader.start()


class TransactionPasskeys(unittest.TestCase):
    setUp=pairing.PairingInventory.setUp
    tearDown=pairing.PairingInventory.tearDown
    ceremony=pairing.PairingInventory.ceremony
    pair=pairing.PairingInventory.pair
    paired=pairing.PairingInventory.paired

    def test_real_passkey_exact_task_binding_revocation_and_unpair(self):
        self.paired()
        plan=uuid.uuid4().hex
        wanted=Broker.wanted('existing-app','observe',entry())
        auth={'agent':self.agent,'project':'existing-app','plan':plan,'policy':'a'*64,'scope':wanted}
        req=self.store.propose({**auth,'spec_hash':'b'*64,'mode':'once','lifetime':3600,'sandbox':False})
        task=uuid.uuid4().hex
        with self.assertRaises(Denied):self.store.rpc('transaction_authorize',{**auth,'task':task})
        self.ceremony('approve',req['request_id'])
        granted=self.store.rpc('transaction_authorize',{**auth,'task':task})
        self.assertEqual(granted,self.store.rpc('transaction_authorize',{**auth,'task':task}))
        with self.assertRaises(Denied):self.store.rpc('transaction_authorize',{**auth,'task':uuid.uuid4().hex})
        with self.assertRaises(Denied):self.store.rpc('transaction_authorize',{**auth,'scope':{**wanted,'delete_data':True},'task':task})
        self.ceremony('revoke',granted['grant_id'])
        with self.assertRaises(Denied):self.store.rpc('transaction_authorize',{**auth,'task':task})
        newauth={**auth,'plan':uuid.uuid4().hex}
        newreq=self.store.propose({**newauth,'spec_hash':'b'*64,'mode':'once','lifetime':3600,'sandbox':False})
        self.ceremony('approve',newreq['request_id'])
        self.ceremony('unpair',self.agent)
        self.paired()
        with self.assertRaises(Denied):self.store.rpc('transaction_authorize',{**newauth,'task':uuid.uuid4().hex})


class LocalRegistryFiles(unittest.TestCase):
    def test_root_protection_permissions_symlinks_and_generator_no_overwrite(self):
        import os
        import tempfile
        from pathlib import Path
        from scripts.register_existing import private_json
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input.json'
            path.write_text('{}');path.chmod(0o600)
            self.assertEqual(private_json(path),{})
            path.chmod(0o644)
            with self.assertRaises(ValueError):private_json(path)
            link=Path(directory)/'link';link.symlink_to(path)
            with self.assertRaises(OSError):private_json(link)
        if os.geteuid()!=0:
            return
        with tempfile.TemporaryDirectory(dir='/run') as directory:
            path=Path(directory)/'registry.json'
            path.write_text(json.dumps({'version':1,'targets':{'existing-app':entry()}}));path.chmod(0o600)
            self.assertIn('existing-app',registration.load(path)['targets'])
            path.chmod(0o644)
            with self.assertRaises(Denied):registration.load(path)
