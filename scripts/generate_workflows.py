#!/usr/bin/env python3
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PINS={'actions/checkout': '11d5960a326750d5838078e36cf38b85af677262', 'actions/upload-artifact': 'ea165f8d65b6e75b540449e92b4886f43607fa02', 'docker/setup-qemu-action': 'c7c53464625b32c7a7e944ae62b3e17d2b600130', 'docker/setup-buildx-action': '8d2750c68a42422c14e847fe6c8ac0403b4cbd6f', 'docker/login-action': 'c94ce9fb468520275223c153574b00df6fe4bcc9', 'docker/build-push-action': '10e90e3645eae34f1e60eeb005ba3a3d33f178e8', 'docker/metadata-action': 'c299e40c65443455700f0fdfc63efafe5b349051', 'sigstore/cosign-installer': '6f9f17788090df1f26f669e9d70d6ae9567deba6'}
def render(project,cfg):
 schedule=('  schedule:\n    - cron: '+json.dumps(cfg['cron'])+'\n') if cfg['enabled'] else ''
 return """# Generated from config/projects.json; do not edit by hand.
name: Check PROJECT image
on:
SCHEDULE  workflow_dispatch:
    inputs:
      mode:
        description: Check only, or publish a deployment candidate
        type: choice
        options: [deploy, check]
        default: deploy
permissions:
  contents: read
concurrency:
  group: registry-PROJECT
  cancel-in-progress: false
jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@CHECKOUT
        with:
          ref: main
      - name: Resolve approved registry source
        env:
          CHECK_MODE: ${{ inputs.mode || 'deploy' }}
        run: python3 scripts/check_registry.py PROJECT
      - uses: sigstore/cosign-installer@COSIGN
        with:
          cosign-release: v3.1.3
      - name: Sign candidate using workflow identity
        run: cosign sign-blob --yes --bundle candidate.bundle.json candidate.json >/dev/null 2>&1
      - name: Publish signed candidate, not deployment success
        run: python3 scripts/publish_candidate.py
""".replace('SCHEDULE',schedule).replace('PROJECT',project).replace('CHECKOUT',PINS['actions/checkout']).replace('COSIGN',PINS['sigstore/cosign-installer'])
def main():
 p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');p.add_argument('--config',type=Path,default=ROOT/'config/projects.json');p.add_argument('--output-dir',type=Path,default=ROOT/'.github/workflows');a=p.parse_args()
 a.output_dir.mkdir(parents=True,exist_ok=True)
 for project,cfg in json.loads(a.config.read_text())['projects'].items():
  if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}',project):raise ValueError('invalid project id')
  path=a.output_dir/f'check-{project}.yml';text=render(project,cfg)
  if a.check:
   if not path.exists() or path.read_text()!=text:raise SystemExit('generated workflow drift: '+project)
  else:path.write_text(text)
if __name__=='__main__':main()
