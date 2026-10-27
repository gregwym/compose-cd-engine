#!/usr/bin/env python3
"""Disposable Docker proof, no pulls/builds/host ports/production app operations.
Uses only the locally cached engine image specified with --image.
"""
import argparse
import json
import subprocess
import time
import uuid
from pathlib import Path


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--image',required=True)
    args=parser.parse_args()
    root=str(Path(__file__).resolve().parents[1])
    prefix='ingress-test-'+uuid.uuid4().hex[:10]
    appnet,controlnet=prefix+'-apps',prefix+'-control'
    backend,node,proxy,broker=prefix+'-backend',prefix+'-node',prefix+'-proxy',prefix+'-broker'
    volume=prefix+'-policy'
    state_volume,run_volume=prefix+'-state',prefix+'-run'
    def docker(*argv):
        return subprocess.check_output(['docker',*argv],stderr=subprocess.STDOUT,text=True).strip()
    def run(name,network,code,extra=()):
        return docker('run','-d','--pull','never','--name',name,'--network',network,'--user','0:0',
            '--cap-drop','ALL','--security-opt','no-new-privileges','--read-only',
            '-e','PYTHONDONTWRITEBYTECODE=1','-v',root+':/app:ro','--workdir','/app',*extra,
            '--entrypoint','python3',args.image,'-c',code)
    def check(network,code,extra=()):
        return docker('run','--rm','--pull','never','--network',network,*extra,'--entrypoint','python3',args.image,'-c',code)
    try:
        docker('image','inspect',args.image)
        docker('network','create',appnet);docker('network','create',controlnet)
        for item in (volume,state_volume,run_volume):docker('volume','create',item)
        cfg={'version':1,'enabled':False,'hostname':'','agents':[],
             'backends':{'autobangumi':{'dns':'app-autobangumi','port':7892,'local_port':21001,'https_port':9444}}}
        docker('run','--rm','--pull','never','--user','0:0','--network','none','-v',volume+':/etc/app-ingress',
            '--entrypoint','python3',args.image,'-c',
            'import pathlib; p=pathlib.Path("/etc/app-ingress/policy.json");p.write_text('+repr(json.dumps(cfg))+');p.chmod(0o644)')
        run(backend,appnet,'import http.server;http.server.HTTPServer(("0.0.0.0",7892),http.server.SimpleHTTPRequestHandler).serve_forever()',('--network-alias','app-autobangumi'))
        run(node,appnet,'import time;time.sleep(300)')
        run(proxy,'container:'+node,'from app_ingress.proxy import main;main()',('--user','10007:10007','-v',volume+':/etc/app-ingress:ro'))
        for _ in range(20):
            try:
                output=check('container:'+node,r"import socket;s=socket.create_connection(('127.0.0.1',21001),2);s.sendall(b'GET / HTTP/1.0\r\n\r\n');assert b'200' in s.recv(4096);print('loopback relay -> fixed backend: HTTP 200')")
                break
            except subprocess.CalledProcessError:
                time.sleep(.25)
        else:raise RuntimeError('proxy did not become ready')
        print(output)
        nodeip=json.loads(docker('inspect',node))[0]['NetworkSettings']['Networks'][appnet]['IPAddress']
        deny="import socket; s=socket.socket();s.settimeout(2);r=s.connect_ex(("+repr(nodeip)+",21001));assert r!=0;print('non-loopback relay connection denied')"
        print(check(appnet,deny))
        # Control-plane namespace is not joined to the application bridge.
        print(check(controlnet,"import socket;s=socket.socket();s.settimeout(2);assert s.connect_ex(('"+nodeip+"',21001))!=0;print('independent control bridge denied')"))
        for name in (backend,node,proxy):
            row=json.loads(docker('inspect',name))[0]
            assert not row['HostConfig'].get('PortBindings')
            assert all('docker.sock' not in m['Destination'] and 'approval' not in m['Destination'] for m in row['Mounts'])
        # Real cap-dropped broker startup plus credential-free gateway UID/group access.
        check('none', 'import os;os.chmod("/state",0o700);os.chmod("/run",0o755)',
              ('--user','0:0','-v',state_volume+':/state','-v',run_volume+':/run'))
        run(broker,'none','from app_ingress.server import main;main()',
            ('--group-add','30006','-v',state_volume+':/var/lib/app-ingress',
             '-v',run_volume+':/run/app-ingress','-v',volume+':/etc/app-ingress:ro'))
        for _ in range(20):
            try:
                result=check('none', r'import socket,json;s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect("/run/app-ingress/broker.sock");s.sendall(b"{}\n");assert "error" in json.loads(s.recv(4096));print("cap-dropped broker socket: gateway group connected, unsigned operation denied")',
                             ('--user','10008:30006','-v',run_volume+':/run/app-ingress:ro'))
                break
            except subprocess.CalledProcessError:time.sleep(.25)
        else:raise RuntimeError('broker socket permissions/startup failed')
        print(result)
        print('PASS: no published ports, Docker socket or approval credentials in app topology')
        print('NOT TESTED: real tailscaled HTTPS/certificates, tailnet ACLs, NAS mappings, AutoBangumi workflows')
    finally:
        for name in (broker,proxy,node,backend):
            subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for network in (controlnet,appnet):
            subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for item in (volume,state_volume,run_volume):
            subprocess.run(['docker','volume','rm',item],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__=='__main__':main()
