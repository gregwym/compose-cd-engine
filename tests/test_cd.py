import importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
runner=module('runner','runner/runner.py')
verifier=module('verifier','verifier/verifier.py')
class Policies(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
  self.cfg={'id':'test','services':['app'],'allowed_images':{'app':'docker.io/example/app'},'candidate_file':str(self.root/'candidate.json')}
  self.good={'schema_version':1,'project':'test','order':[10,1],'source_sha':'a'*40,'mode':'deploy','images':{'app':'docker.io/example/app@sha256:'+'b'*64}}
 def tearDown(self):self.tmp.cleanup()
 def check(self,value):
  Path(self.cfg['candidate_file']).write_text(json.dumps(value));return runner.candidate(self.cfg)
 def test_approved_digest(self):self.assertEqual(self.check(self.good),self.good)
 def test_tag_rejected(self):
  self.good['images']['app']='docker.io/example/app:latest'
  with self.assertRaises(ValueError):self.check(self.good)
 def test_wrong_registry_rejected(self):
  self.good['images']['app']='docker.io/attacker/app@sha256:'+'b'*64
  with self.assertRaises(ValueError):self.check(self.good)
 def test_remote_command_rejected(self):
  self.good['command']='id'
  with self.assertRaises(ValueError):self.check(self.good)
 def test_cross_target_rejected(self):
  self.good['project']='other'
  with self.assertRaises(ValueError):self.check(self.good)
 def test_check_only_never_touches_docker(self):
  self.good['mode']='check';self.check(self.good);self.cfg['observe']=False
  with patch.object(runner,'STATE_DIR',self.root),patch.object(runner,'current_containers',side_effect=AssertionError('Docker touched')):
   runner.deploy(self.cfg)
  self.assertEqual(json.loads((self.root/'test.receipt').read_text())['status'],'checked')
 def test_stale_event_cannot_rollback(self):
  self.check(self.good);(self.root/'test.receipt').write_text(json.dumps({'order':[11,1],'status':'success'}))
  with patch.object(runner,'STATE_DIR',self.root),patch.object(runner,'current_containers',side_effect=AssertionError('Docker touched')):
   with self.assertRaises(ValueError):runner.deploy(self.cfg)
 def test_failure_receipt_after_rollback(self):
  self.check(self.good);self.cfg.update(observe=False,snapshot_paths=[],files=['compose.yml'])
  old={'app':{'image_id':'old','image_ref':'old','container':'old'}}
  with patch.object(runner,'STATE_DIR',self.root),patch.object(runner,'current_containers',return_value=old),patch.object(runner,'preflight_space'),patch.object(runner.subprocess,'run') as sp,patch.object(runner,'command',side_effect=RuntimeError('fail')),patch.object(runner,'restore') as restore:
   sp.return_value.stdout=b'new\n'
   with self.assertRaises(RuntimeError):runner.deploy(self.cfg)
   restore.assert_called_once()
  self.assertEqual(json.loads((self.root/'test.receipt').read_text())['status'],'rolled_back')
class MediaRollback(unittest.TestCase):
 def test_excluded_media_survive_real_filesystem_restore(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);state=root/'state';state.mkdir();data=root/'data';data.mkdir();(data/'images').mkdir();(data/'images/a.jpg').write_bytes(b'old media');(data/'db').write_bytes(b'old db')
   cfg={'id':'test','snapshot_paths':[str(data)],'snapshot_exclude':['images'],'snapshot_retention':2}
   with patch.object(runner,'STATE_DIR',state):
    snap=runner.snapshot_data(cfg)
    (data/'db').write_bytes(b'changed db');(data/'images/a.jpg').write_bytes(b'new media');(data/'extra').write_bytes(b'new')
    runner.restore_data(cfg,snap)
   self.assertEqual((data/'db').read_bytes(),b'old db');self.assertEqual((data/'images/a.jpg').read_bytes(),b'new media');self.assertFalse((data/'extra').exists())
class SignedCandidates(unittest.TestCase):
 def test_signed_record_still_needs_source_allowlist(self):
  cfg={'id':'test','image':'docker.io/example/app','tag':'latest','platform':'linux/amd64'}
  rec={'schema_version':1,'project':'test','image':cfg['image'],'tag':'latest','platform':'linux/amd64','digest':'sha256:'+'b'*64,'run_id':12,'run_attempt':1,'source_sha':'a'*40,'mode':'deploy'}
  self.assertEqual(verifier.verify_signed_record(cfg,rec),rec)
  rec['image']='docker.io/attacker/app'
  with self.assertRaises(ValueError):verifier.verify_signed_record(cfg,rec)
if __name__=='__main__':unittest.main()

class WebhookValidation(unittest.TestCase):
 def setUp(self):
  import time
  from datetime import datetime,timezone
  self.receiver=module('receiver','receiver/receiver.py');self.secret=b'a'*48
  self.policy={'repository':'owner/repo','repository_id':12,'branch':'main','workflow':'.github/workflows/check.yml'}
  self.payload={'repository':{'id':12,'full_name':'owner/repo'},'action':'completed','workflow_run':{'status':'completed','conclusion':'success','head_branch':'main','event':'schedule','path':'.github/workflows/check.yml','head_repository':{'id':12},'updated_at':datetime.now(timezone.utc).isoformat()}}
 def validate(self,payload,signature=True):
  import hmac,hashlib
  body=json.dumps(payload).encode();sig='sha256='+hmac.new(self.secret,body,hashlib.sha256).hexdigest() if signature else 'invalid'
  return self.receiver.validate(body,sig,'workflow_run',self.secret,policy=self.policy)
 def test_native_schedule_validates(self):self.assertIsInstance(self.validate(self.payload),bytes)
 def test_bad_hmac_rejected(self):
  with self.assertRaises(ValueError):self.validate(self.payload,False)
 def test_pr_never_signals(self):
  self.payload['workflow_run']['event']='pull_request';self.assertIsNone(self.validate(self.payload))
 def test_foreign_head_never_signals(self):
  self.payload['workflow_run']['head_repository']['id']=99;self.assertIsNone(self.validate(self.payload))
 def test_wrong_repository_rejected(self):
  self.payload['repository']['id']=99
  with self.assertRaises(ValueError):self.validate(self.payload)

class DeploymentState(unittest.TestCase):
 def test_check_receipt_preserves_last_successful_deployment(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);cfg={'id':'test'};value={'order':[1,1],'source_sha':'a'*40,'images':{'app':'image@sha256:'+'b'*64}}
   with patch.object(runner,'STATE_DIR',root):
    first=runner.receipt(cfg,value,'success',running_images={'app':'actual'})
    value['order']=[2,1];last=runner.receipt(cfg,value,'checked')
   self.assertEqual(last['last_deployment'],first)
   self.assertEqual(json.loads((root/'test.deployed.json').read_text()),first)
