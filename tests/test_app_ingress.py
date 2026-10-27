import copy
import json
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authorization import agents
from authorization.store import Store
from authorization.passkeys import Passkeys
from authorization.scope import Denied
from deployer import schema
from app_ingress.broker import Broker
from app_ingress.policy import validate
from app_ingress.proxy import Relay
from app_ingress.transport import Serve
from app_ingress.init import initialize
from test_authorization import Authenticator, ORIGIN, RP


class Transport:
    def __init__(self):
        self.value={'TCP':{'443':{'HTTPS':True}},'Web':{'unrelated.example.ts.net:443':{'Handlers':{'/':{'Proxy':'http://127.0.0.1:3000'}}}}}
        self.count=0
        self.lost=False
    def snapshot(self):
        return copy.deepcopy(self.value), str(self.count)
    def replace(self,value,tag):
        if tag != str(self.count):
            raise ValueError('CAS mismatch')
        self.value=copy.deepcopy(value); self.count+=1
        if self.lost:
            raise OSError('lost response')


class Ingress(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.private=Ed25519PrivateKey.generate()
        public=agents.public_key(self.private)
        self.agent=agents.identity(public)
        self.cfg={'version':1,'enabled':True,'hostname':'apps.example.ts.net','agents':[public],
                  'backends':{'autobangumi':{'dns':'app-autobangumi','port':7892,'local_port':21001,'https_port':9444}}}
        self.store=Store(root/'approval.sqlite',ORIGIN)
        self.passkeys=Passkeys(self.store,RP,ORIGIN)
        self.authenticator=Authenticator()
        token=self.store.bootstrap('owner')
        start=self.passkeys.begin('browser','enroll',token=token)
        self.passkeys.finish('browser',start['ceremony_id'],self.authenticator.response(start,register=True))
        with self.store.db() as db:
            db.execute('INSERT INTO paired_agents VALUES (?,?,?,?,?,?,?)',
                       (self.agent,public,'test','owner',None,int(time.time()),'active'))
        self.transport=Transport()
        self.original=copy.deepcopy(self.transport.value)
        self.broker=Broker(root/'ingress.sqlite',lambda:self.cfg,self.transport,self.store.rpc)

    def call(self,operation,payload,private=None):
        private=private or self.private
        public=agents.public_key(private)
        value={'version':1,'agent':agents.identity(public),'public_key':public,'audience':'compose-cd-shared-app-ingress-v1',
               'operation':operation,'payload':payload,'timestamp':int(time.time()),'request_id':uuid.uuid4().hex}
        envelope={'value':value,'signature':agents.sign(schema.canonical(value).encode(),private)}
        return self.broker.wire(envelope)

    def plan(self):
        return self.call('plan',{'backend':'autobangumi'})['plan_id']

    def approve(self,pid):
        req=self.call('request',{'plan_id':pid})
        start=self.passkeys.begin('browser','approve',req['request_id'],admin='owner')
        self.passkeys.finish('browser',start['ceremony_id'],self.authenticator.response(start),admin='owner')
        return req

    def test_passkey_immutable_apply_preserves_baseline_and_receipts(self):
        pid=self.plan()
        with self.assertRaises(Denied):self.call('apply',{'plan_id':pid})
        self.assertEqual(self.transport.count,0)
        self.approve(pid)
        self.assertEqual(self.call('apply',{'plan_id':pid})['status'],'success')
        self.assertEqual(self.transport.value['TCP']['443'],self.original['TCP']['443'])
        self.assertEqual(self.transport.value['Web']['unrelated.example.ts.net:443'],self.original['Web']['unrelated.example.ts.net:443'])
        self.assertEqual(self.transport.value['Web']['apps.example.ts.net:9444']['Handlers'],{'/':{'Proxy':'http://127.0.0.1:21001'}})
        self.assertNotIn('AllowFunnel',self.transport.value)
        self.call('apply',{'plan_id':pid}); self.assertEqual(self.transport.count,1)
        self.assertEqual(self.call('receipt',{'plan_id':pid})['status'],'success')
        with self.broker.db() as db:
            for sql in ('UPDATE plans SET document="evil"','DELETE FROM receipts'):
                with self.assertRaises(sqlite3.IntegrityError):db.execute(sql)

    def test_scope_requires_passkey_not_sandbox_or_other_grant(self):
        pid=self.plan();req=self.call('request',{'plan_id':pid})
        with self.store.db() as db:self.store.issue(db,req['request_id'],'administrator-policy:sandbox',None)
        with self.assertRaises(Denied):self.call('apply',{'plan_id':pid})
        self.assertEqual(self.transport.count,0)

    def test_revoked_agent_credential_and_grant_cannot_mutate(self):
        for revoke in ('agent', 'credential', 'grant'):
            with self.subTest(revoke=revoke):
                pid=self.plan();self.approve(pid)
                with self.store.db() as db:
                    if revoke == 'agent': db.execute("UPDATE paired_agents SET status='revoked'")
                    elif revoke == 'credential': db.execute('UPDATE credentials SET active=0')
                    else: db.execute("UPDATE grants SET status='revoked'")
                with self.assertRaises(Denied):self.call('apply',{'plan_id':pid})
                self.assertEqual(self.transport.count,0)
                with self.store.db() as db:
                    db.execute("UPDATE paired_agents SET status='active'")
                    db.execute('UPDATE credentials SET active=1')

    def test_drift_and_config_expansion_rejected(self):
        pid=self.plan();self.approve(pid)
        self.transport.value['TCP']['9999']={'HTTPS':True}
        with self.assertRaises(Denied):self.call('apply',{'plan_id':pid})
        self.transport.value=copy.deepcopy(self.original)
        self.cfg['backends']['autobangumi']['port']=9000
        with self.assertRaises(Denied):self.call('apply',{'plan_id':pid})
        self.assertEqual(self.transport.count,0)

    def test_lost_write_requires_independent_recovery_approval(self):
        pid=self.plan();self.approve(pid);self.transport.lost=True
        self.assertEqual(self.call('apply',{'plan_id':pid})['status'],'outcome_unknown')
        with self.assertRaises(Denied):self.plan()
        restored=Broker(self.broker.database,lambda:self.cfg,self.transport,self.store.rpc)
        self.broker=restored
        recovery=self.call('recovery_plan',{'plan_id':pid})['plan_id']
        with self.assertRaises(Denied):self.call('apply',{'plan_id':recovery})
        self.approve(recovery);self.transport.lost=False
        self.assertEqual(self.call('apply',{'plan_id':recovery})['status'],'recovered')
        self.assertEqual(self.transport.value,self.original)
        self.assertEqual(self.call('receipt',{'plan_id':pid})['status'],'recovered')

    def test_interrupted_intent_does_not_replay(self):
        pid=self.plan()
        with self.broker.db() as db:self.broker.record(db,pid,'applying',{})
        self.broker=Broker(self.broker.database,lambda:self.cfg,self.transport,self.store.rpc)
        self.assertEqual(self.call('receipt',{'plan_id':pid})['status'],'outcome_unknown')
        self.assertEqual(self.transport.count,0)

    def test_unknown_backend_extra_fields_and_other_identity(self):
        for payload in ({'backend':'unknown'},{'backend':'autobangumi','command':['id']},{'backend':'http://127.0.0.1:18793'}):
            with self.assertRaises((Denied,ValueError)):self.call('plan',payload)
        with self.assertRaises(Denied):self.call('plan',{'backend':'autobangumi'},Ed25519PrivateKey.generate())
        pid=self.plan()
        with self.assertRaises((Denied,ValueError)):self.call('apply',{'plan_id':pid,'upstream':'evil'})

    def test_reserved_ports_funnel_and_unrecognized_recovery(self):
        for port in (443,8443):
            cfg=copy.deepcopy(self.cfg);cfg['backends']['autobangumi']['https_port']=port
            with self.assertRaises((Denied,ValueError)):validate(cfg)
        self.transport.value['AllowFunnel']={'apps.example.ts.net:9444':True}
        with self.assertRaises(Denied):self.plan()

    def test_replayed_signature_and_audience(self):
        value={'version':1,'agent':self.agent,'public_key':agents.public_key(self.private),
               'audience':'compose-cd-shared-app-ingress-v1','operation':'plan','payload':{'backend':'autobangumi'},
               'timestamp':int(time.time()),'request_id':uuid.uuid4().hex}
        wire={'value':value,'signature':agents.sign(schema.canonical(value).encode(),self.private)}
        self.broker.wire(wire)
        with self.assertRaises(ValueError):self.broker.wire(wire)
        value['audience']='compose-cd-runner';value['request_id']=uuid.uuid4().hex
        wire['signature']=agents.sign(schema.canonical(value).encode(),self.private)
        with self.assertRaises(Denied):self.broker.wire(wire)


class DisposableNetworking(unittest.TestCase):
    def test_real_http_and_bidirectional_upgrade_through_loopback_relay(self):
        import socketserver
        class Backend(socketserver.BaseRequestHandler):
            def handle(self):
                data=self.request.recv(8192)
                if b'Upgrade: websocket' in data:
                    self.request.sendall(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n')
                    self.request.sendall(self.request.recv(100))
                else:
                    self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nroot')
        with socketserver.ThreadingTCPServer(('127.0.0.1',0),Backend) as backend:
            thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
            with Relay(('127.0.0.1',0),backend.server_address) as proxy:
                threading.Thread(target=proxy.serve_forever,daemon=True).start()
                for upgrade in (False,True):
                    with socket.create_connection(proxy.server_address,timeout=3) as client:
                        client.settimeout(3)
                        client.sendall(b'GET / HTTP/1.1\r\nHost: apps.example.ts.net\r\n'+(b'Upgrade: websocket\r\n' if upgrade else b'')+b'\r\n')
                        data=client.recv(8192)
                        self.assertIn(b'101' if upgrade else b'200',data)
                        if upgrade:
                            client.sendall(b'bidirectional');self.assertEqual(client.recv(100),b'bidirectional')
                        else:self.assertIn(b'root',data)
                proxy.shutdown()
            backend.shutdown()


class Bootstrap(unittest.TestCase):
    def test_fresh_repeat_unrelated_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            # Path protection is tested separately; use a private disposable root in unit tests.
            with patch('app_ingress.init.protected_directory',side_effect=lambda p:Path(p)), patch('management.protocol.protected_file',side_effect=lambda p:Path(p)):
                root=base/'ingress';initialize(str(root))
                before=(root/'policy/policy.json').read_bytes()
                initialize(str(root));self.assertEqual((root/'policy/policy.json').read_bytes(),before)
                bad=base/'unrelated';bad.mkdir(mode=0o755);(bad/'important').write_text('preserve')
                mode=bad.stat().st_mode
                with self.assertRaises(Denied):initialize(str(bad))
                self.assertEqual((bad/'important').read_text(),'preserve');self.assertEqual(bad.stat().st_mode,mode)
                link=base/'link';link.symlink_to(root)
                with self.assertRaises(Denied):initialize(str(link))
                for forbidden in ('/volume1','/volume1/@docker/foo','relative/path'):
                    with self.assertRaises(Denied):initialize(forbidden)
