#!/usr/bin/env python3
"""Network-enabled verifier with NO Docker socket or production data mounts.

Untrusted data is never executed. Only locally approved sources produce fixed
service-to-image candidate maps for the isolated privileged runner.
"""
import hashlib,json,os,re,socket,subprocess,sys,threading,time
from pathlib import Path
sys.path.insert(0,'/app')
from shared.registry import resolve,labels,request,DIGEST
POLICIES=Path(os.environ.get('CD_SOURCES_DIR','/etc/compose-cd/sources'))
INBOX=Path(os.environ.get('CD_INBOX_DIR','/var/lib/compose-cd/inbox'))
CHECKOUT=Path(os.environ.get('CD_CANDIDATES_DIR','/var/lib/compose-cd/candidates'))
COSIGN=os.environ.get('CD_COSIGN','/usr/local/bin/cosign')
GITHUB='https://api.github.com/repos/'
ISSUER='https://token.actions.githubusercontent.com'

def atomic(path,data):
 tmp=path.with_suffix('.next');tmp.write_text(json.dumps(data,sort_keys=True)+'\n');os.chmod(tmp,0o640);tmp.replace(path)

def cosign(*args):
 subprocess.run([COSIGN,*args],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=180)

def identity(cfg):
 return 'https://github.com/'+cfg['repository']+'/'+cfg['workflow']+'@refs/heads/'+cfg['branch']

def api(path):
 return json.loads(request(GITHUB+path,{'Accept':'application/vnd.github+json','User-Agent':'compose-cd-verifier'})[0])

def verify_signed_record(cfg,record):
 required={'schema_version','project','image','tag','platform','digest','run_id','run_attempt','source_sha','mode'}
 if set(record)!=required or record['schema_version']!=1 or record['project']!=cfg['id'] or record['image']!=cfg['image'] or record['tag']!=cfg['tag'] or record['platform']!=cfg['platform'] or not DIGEST.fullmatch(record['digest']) or type(record['run_id']) is not int or type(record['run_attempt']) is not int or record['run_id']<=0 or record['run_attempt']<=0 or not re.fullmatch('[a-f0-9]{40}',record['source_sha']) or record['mode'] not in ('check','deploy'):
  raise ValueError('invalid signed candidate')
 return record

def registry_candidate(cfg):
 folder=CHECKOUT/cfg['id']
 # Copy both atomically-published inputs to a private directory so a concurrent
 # fetch cannot swap candidate bytes after signature verification.
 import tempfile
 with tempfile.TemporaryDirectory() as directory:
  record_path=Path(directory)/'candidate.json';bundle=Path(directory)/'candidate.bundle.json'
  record_path.write_bytes((folder/'candidate.json').read_bytes());bundle.write_bytes((folder/'candidate.bundle.json').read_bytes())
  cosign('verify-blob','--bundle',str(bundle),'--certificate-identity',identity(cfg),'--certificate-oidc-issuer',ISSUER,str(record_path))
  record=verify_signed_record(cfg,json.loads(record_path.read_text()))
 # Independently re-fetch this exact upstream digest, including platform check.
 digest,_=resolve(cfg['image'],record['digest'],cfg['platform'])
 if digest!=record['digest']:raise ValueError('registry platform mismatch')
 return record,record['digest']

def build_candidate(cfg):
 workflow=cfg['workflow'].split('/')[-1]
 info=api(cfg['repository'])
 if info['id']!=cfg['repository_id']:raise ValueError('repository identity changed')
 head=api(cfg['repository']+'/branches/'+cfg['branch'])['commit']['sha']
 runs=api(cfg['repository']+'/actions/workflows/'+workflow+'/runs?branch='+cfg['branch']+'&per_page=15')['workflow_runs']
 valid=[r for r in runs if r['status']=='completed' and r['conclusion']=='success' and r['event'] in ('push','workflow_dispatch') and r['head_branch']==cfg['branch'] and r['head_sha']==head and r['head_repository']['id']==cfg['repository_id'] and r['path']==cfg['workflow']]
 if not valid:raise ValueError('current source head has no successful trusted build')
 run=max(valid,key=lambda r:(r['id'],r.get('run_attempt',1)))
 tag=f"run-{run['id']}-{run.get('run_attempt',1)}"
 # Signature is over the entire published index. Deploy the selected platform
 # digest only after proving that it belongs to that signed index.
 from shared.registry import manifest,auth
 doc,index=manifest(cfg['image'],tag,auth(cfg['image']))
 cosign('verify','--certificate-identity',identity(cfg),'--certificate-oidc-issuer',ISSUER,cfg['image']+'@'+index)
 digest,doc=resolve(cfg['image'],index,cfg['platform'])
 meta=labels(cfg['image'],doc)
 if meta.get('org.opencontainers.image.revision')!=head or meta.get('org.opencontainers.image.source')!='https://github.com/'+cfg['repository']:
  raise ValueError('image/source mismatch')
 return {'run_id':run['id'],'run_attempt':run.get('run_attempt',1),'source_sha':head,'mode':'deploy'},digest

LOCK=threading.Lock()
def reconcile(cfg):
 with LOCK:
  state_file=INBOX/(cfg['id']+'.verified.json')
  prior=json.loads(state_file.read_text()) if state_file.exists() else {}
  record,digest=(registry_candidate(cfg) if cfg['type']=='registry' else build_candidate(cfg))
  order=[record['run_id'],record['run_attempt']]
  if order<prior.get('order',[0,0]):raise ValueError('stale candidate')
  value={'schema_version':1,'project':cfg['id'],'order':order,'source_sha':record['source_sha'],'mode':record['mode'],'images':{s:cfg['image']+'@'+digest for s in cfg['services']}}
  # A verified candidate is data only: no argv, paths or target selectors.
  if value!=prior:
   atomic(state_file,value)
   atomic(INBOX/(cfg['id']+'.json'),value)
  if cfg.get('observe',True):
   print('verified observation project='+cfg['id'],flush=True);return
  with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sock:sock.sendto(b'check',cfg['runner_socket'])
  print('verified candidate signalled project='+cfg['id'],flush=True)

def handle(cfg):
 try:
  reconcile(cfg)
  atomic(INBOX/(cfg['id']+'.verification-status.json'),{'project':cfg['id'],'status':'verified','updated_at':int(time.time())})
 except Exception as exc:
  atomic(INBOX/(cfg['id']+'.verification-status.json'),{'project':cfg['id'],'status':'verification_deferred','reason':type(exc).__name__,'updated_at':int(time.time())})
  print('verification deferred project='+cfg['id']+' reason='+type(exc).__name__,flush=True)

def serve(cfg):
 path=Path(cfg['socket']);path.unlink(missing_ok=True)
 with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sock:
  sock.bind(str(path));os.chmod(path,0o660);sock.settimeout(30)
  due=0;last_files=None
  while True:
   wake=False
   try:wake=sock.recv(64)==b'check'
   except socket.timeout:pass
   if cfg['type']=='registry':
    paths=[CHECKOUT/cfg['id']/n for n in ['candidate.json','candidate.bundle.json']]
    fingerprint=tuple(p.stat().st_mtime_ns if p.exists() else 0 for p in paths)
    if fingerprint!=last_files:last_files=fingerprint;wake=True
   if wake or time.monotonic()>=due:
    handle(cfg);due=time.monotonic()+1800

def main():
 os.umask(0o027);INBOX.mkdir(exist_ok=True)
 for path in POLICIES.glob('*.json'):
  st=path.stat()
  if path.is_symlink() or st.st_uid!=0 or st.st_mode&0o022:raise ValueError('unsafe source policy')
  cfg=json.loads(path.read_text())
  threading.Thread(target=serve,args=(cfg,),daemon=True).start()
 threading.Event().wait()
if __name__=='__main__':main()
