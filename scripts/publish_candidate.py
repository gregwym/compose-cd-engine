#!/usr/bin/env python3
"""Publish only signed data to one project's isolated state branch."""
import json,os,subprocess,tempfile
from pathlib import Path
record=json.loads(Path('candidate.json').read_text())
project=record['project']; branch='candidate-'+project
url=f'https://github.com/{os.environ["GITHUB_REPOSITORY"]}.git'
# Checkout's ephemeral credential helper authenticates this local push. No PAT.
def run(*args,**kw):return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kw)
with tempfile.TemporaryDirectory() as d:
 p=Path(d)
 run('git','init','-q',d)
 run('git','-C',d,'config','user.name','github-actions[bot]')
 run('git','-C',d,'config','user.email','41898282+github-actions[bot]@users.noreply.github.com')
 # Reuse the checkout local HTTP header through environment; never print it.
 config=run('git','config','--get-regexp',r'http\..*\.extraheader').stdout.decode().strip().split(' ',1)
 env=os.environ.copy()
 if len(config)==2:
  env.update(GIT_CONFIG_COUNT='1',GIT_CONFIG_KEY_0=config[0],GIT_CONFIG_VALUE_0=config[1])
 run('git','-C',d,'remote','add','origin',url)
 prior=subprocess.run(['git','-C',d,'fetch','--depth=1','origin',branch],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 if prior.returncode==0:
  run('git','-C',d,'checkout','-q','-B',branch,'FETCH_HEAD')
 else:run('git','-C',d,'checkout','-q','--orphan',branch)
 for name in ['candidate.json','candidate.bundle.json']:(p/name).write_bytes(Path(name).read_bytes())
 run('git','-C',d,'add','candidate.json','candidate.bundle.json')
 run('git','-C',d,'commit','-q','-m',f'Candidate {project} run {record["run_id"]}')
 run('git','-C',d,'push','origin',f'HEAD:refs/heads/{branch}',env=env)
 print('Signed candidate published. This is not a deployment-success status.')
