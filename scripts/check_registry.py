#!/usr/bin/env python3
import argparse,json,os,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from shared.registry import resolve
p=argparse.ArgumentParser(); p.add_argument('project'); a=p.parse_args()
projects=json.loads(Path('config/projects.json').read_text())['projects']
cfg=projects[a.project]
if not cfg['enabled']: raise SystemExit('project disabled')
digest,_=resolve(cfg['image'],cfg['tag'],cfg['platform'])
record={'schema_version':1,'project':a.project,'image':cfg['image'],'tag':cfg['tag'],'platform':cfg['platform'],'digest':digest,'run_id':int(os.environ['GITHUB_RUN_ID']),'run_attempt':int(os.environ['GITHUB_RUN_ATTEMPT']),'source_sha':os.environ['GITHUB_SHA'],'mode':os.environ.get('CHECK_MODE','deploy')}
Path('candidate.json').write_text(json.dumps(record,sort_keys=True)+'\n')
print('Registry candidate resolved; deployment result is recorded asynchronously, not implied by this run.')
