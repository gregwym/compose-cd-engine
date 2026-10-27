#!/usr/bin/env python3
"""Disposable Docker acceptance for exact-project redeploy, never production."""
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
        entry={'baseline':baseline,'compose':compose,'declaration_hash':schema.fingerprint(compose),'allow_redeploy':True,'health_timeout':30}
        registry=root/'registry.json';registry.write_text(json.dumps({'version':1,'targets':{project:entry}}));registry.chmod(0o600)
        store=Store(root/'approval.sqlite','https://disposable.invalid')
        def rpc(_cfg,op,value):return store.rpc(op,value)
        broker=service.adoption
        with patch('deployer.transactions.rpc.call',side_effect=rpc):
            planned=broker.dispatch(cfg,project,'test','adoption_plan',{'action':'redeploy'})
            request=broker.dispatch(cfg,project,'test','adoption_request',{'plan_id':planned['plan_id']})
            # Software-owner issuance adapter; physical Passkey tested separately.
            with store.db() as db:store.issue(db,request['request_id'],'test-owner',None)
            task=broker.dispatch(cfg,project,'test','adoption_apply',{'plan_id':planned['plan_id']})
            assert service.run_one()
            result=broker.dispatch(cfg,project,'test','adoption_task',{'task_id':task['task_id']})
            assert result['status']=='success',result
            assert broker.dispatch(cfg,project,'test','adoption_apply',{'plan_id':planned['plan_id']})==task
        assert subprocess.check_output(docker+['inspect','--format','{{.Image}}',web]).decode().strip()==image
        assert subprocess.check_output(docker+['inspect','--format','{{.Id}}',unrelated])==uid
        assert subprocess.check_output(docker+['inspect','--format','{{index .Config.Labels "com.docker.compose.project"}}',web]).decode().strip()==project
        print('PASS original-project same-local-image redeploy, real health, independent transaction, idempotency, unrelated identity preserved')
    finally:
        # Exact disposable fixtures only, no down/prune/volume/data operation.
        subprocess.run(docker+['rm','--force',web,project+'-unrelated'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(docker+['network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__=='__main__':main()
