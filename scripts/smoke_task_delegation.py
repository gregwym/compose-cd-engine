#!/usr/bin/env python3
"""Disposable real Docker task delegation; software Passkey, simulated Serve CAS."""
import json
import os
import subprocess
import uuid
from pathlib import Path
from unittest.mock import patch
from deployer import schema
from deployer.service import Service
from deployer.adoption import inspect_project
from authorization.store import Store
from authorization.passkeys import Passkeys
from authorization import agents
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app_ingress.broker import Broker as Ingress
from test_authorization import Authenticator, ORIGIN, RP
from test_app_ingress import Transport
from runner import runner


def main():
    assert os.environ.get('CD_DISPOSABLE_CI')=='1' and os.geteuid()==0
    nonce=uuid.uuid4().hex[:12]
    project='adopt-'+nonce
    root=Path('/run')/project;root.mkdir(mode=0o700)
    for directory in ('private','config','data','state'):(root/directory).mkdir(mode=0o700)
    docker=[runner.DOCKER,'--host','unix:///var/run/docker.sock']
    builder=project+'-builder';web=project+'-web';network=project+'-net'
    subprocess.run(docker+['create','--name',builder,os.environ.get('CD_SMOKE_IMAGE','compose-cd-engine:test')],check=True,stdout=subprocess.DEVNULL)
    try:
        image=subprocess.check_output(docker+['commit','--change','CMD ["python3","-m","http.server","8080"]',builder]).decode().strip()
    finally:subprocess.run(docker+['rm',builder],check=True,stdout=subprocess.DEVNULL)
    subprocess.run(docker+['network','create',network],check=True,stdout=subprocess.DEVNULL)
    try:
        compose={'services':{'web':{'image':image,'container_name':web,'volumes':[],'ports':[],'networks':['app'],
            'healthcheck':{'test':['CMD','python3','-c','import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080")'],
                           'interval':'1s','timeout':'1s','retries':15,'start_period':'1s'}}},
            'networks':{'app':{'external':True,'name':network}}}
        original=root/'original.json';original.write_text(json.dumps(compose));original.chmod(0o600)
        argv=docker+['compose','-p',project,'-f',str(original)]
        subprocess.run(argv+['up','-d','--no-build','--pull','never','--wait'],check=True,stdout=subprocess.DEVNULL)
        # Unrelated fixture proves this worker is selective.
        unrelated=project+'-unrelated'
        subprocess.run(docker+['create','--name',unrelated,image],check=True,stdout=subprocess.DEVNULL)
        uid=subprocess.check_output(docker+['inspect','--format','{{.Id}}',unrelated])
        cfg={'workspace':str(root/'private'),'storage':{'data':{'path':str(root/'data'),'shared':True,'uid':10001,'gid':10001}},
             'images':{'example.invalid/app':{'digests':['a'*64],'allow_unsigned':True,'healthcheck':['python3','-V'],'environment':[]}},
             'port_range':[20000,20001],'bind_ip':'192.168.50.2','max_projects':1,'max_services':1,
             'max_memory_mb':128,'max_cpus':1,'max_pids':64,'health_timeout':30,'enabled':False,'allow_egress':False,
             'operations':sorted(schema.OPS),'authorization':{'socket':'/run/test.sock','service_key':'/etc/test.key','agents':{'test':'/etc/test-agent.key'}},
             'adoption':{'registry':str(root/'registry.json')}}
        policy=root/'policy.json';policy.write_text(json.dumps(cfg));policy.chmod(0o600)
        runner.STATE_DIR=root/'state'
        service=Service(str(policy),runner)
        baseline=inspect_project(service.docker,project)
        # Deliberately reviewed health-only declaration change forces real recreation.
        compose['services']['web']['healthcheck']['interval']='2s'
        entry={'baseline':baseline,'compose':compose,'declaration_hash':schema.fingerprint(compose),'allow_redeploy':True,'health_timeout':30}
        registry=root/'registry.json';registry.write_text(json.dumps({'version':1,'targets':{project:entry}}));registry.chmod(0o600)
        store=Store(root/'approval.sqlite','https://disposable.invalid')
        def rpc(_cfg,op,value):return store.rpc(op,value)
        broker=service.adoption
        private=Ed25519PrivateKey.generate()
        public=agents.public_key(private); agent=agents.identity(public)
        with store.db() as db:
            db.execute('INSERT INTO paired_agents VALUES (?,?,?,?,?,?,?)',
                       (agent,public,'disposable','owner',None,0,'active'))
        passkeys=Passkeys(store,RP,ORIGIN); owner=Authenticator()
        start=passkeys.begin('browser','enroll',token=store.bootstrap('owner'))
        passkeys.finish('browser',start['ceremony_id'],owner.response(start,register=True))
        icfg={'version':1,'enabled':True,'hostname':'apps.example.ts.net','agents':[public],
              'backends':{'fixture':{'dns':'app-fixture','port':8080,'local_port':21001,'https_port':9444}}}
        taskfile=root/'tasks.json'
        envelope={'agent':agent,'registration_hash':schema.fingerprint(entry),
            'ingress_policy':schema.fingerprint(icfg),'backend':'fixture',
            'backend_hash':schema.fingerprint(icfg['backends']['fixture']),
            'route':{'hostname':icfg['hostname'],'https_port':9444,'root_path':'/'},'max_lifetime':3600}
        taskfile.write_text(json.dumps({'version':1,'targets':{project:envelope}})); taskfile.chmod(0o600)
        cfg['task_delegation']={'registry':str(taskfile)}
        policy.write_text(json.dumps(cfg))
        service.cfg=cfg
        transport=Transport()
        ingress=Ingress(root/'ingress.sqlite',lambda:icfg,transport,store.rpc)
        with patch('deployer.transactions.rpc.call',side_effect=rpc):
            request=broker.dispatch(cfg,project,agent,'delegation_request',{'lifetime':3600})
            ceremony=passkeys.begin('browser','approve',request['request_id'],admin='owner')
            passkeys.finish('browser',ceremony['ceremony_id'],owner.response(ceremony),admin='owner')
            gid=store.rpc('grants',{'agent':agent,'project':project})['grants'][0]['grant_id']
            broker.inspect_access(cfg,project,agent,gid)
            planned=broker.dispatch(cfg,project,agent,'adoption_plan',{'action':'redeploy','delegation_id':gid})
            task=broker.dispatch(cfg,project,agent,'adoption_apply',{'plan_id':planned['plan_id'],'delegation_id':gid})
            assert service.run_one()
            result=broker.dispatch(cfg,project,agent,'adoption_task',{'task_id':task['task_id']})
            assert result['status']=='success',result
            after=inspect_project(service.docker,project)
            assert after['containers'][0]['container_id'] != baseline['containers'][0]['container_id']
            follow=broker.dispatch(cfg,project,agent,'adoption_plan',{'action':'observe','delegation_id':gid})
            assert follow['status']=='authorized'
            ip=ingress.dispatch(agent,'plan',{'backend':'fixture','project':project,'delegation_id':gid})
            result=ingress.dispatch(agent,'apply',{'plan_id':ip['plan_id'],'project':project,'delegation_id':gid})
            assert result['status']=='success',result
            with store.db() as db:
                assert db.execute('SELECT count(*) FROM requests').fetchone()[0]==1
                assert db.execute('SELECT count(*) FROM grants').fetchone()[0]==1
        assert subprocess.check_output(docker+['inspect','--format','{{.Image}}',web]).decode().strip()==image
        assert subprocess.check_output(docker+['inspect','--format','{{.Id}}',unrelated])==uid
        assert subprocess.check_output(docker+['inspect','--format','{{index .Config.Labels "com.docker.compose.project"}}',web]).decode().strip()==project
        print('PASS one software-Passkey task grant: inspect, real same-local-image redeploy/health, expected runtime transition, simulated ingress CAS; unrelated container retained. NOT live NAS/tailnet acceptance.')
    finally:
        # Exact disposable fixtures only, no down/prune/volume/data operation.
        subprocess.run(docker+['rm','--force',web,project+'-unrelated'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(docker+['network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__=='__main__':main()
