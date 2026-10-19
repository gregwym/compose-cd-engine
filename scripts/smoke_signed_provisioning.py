#!/usr/bin/env python3
"""Network-only CI: verify a previously published, signed public engine release.

Does not deploy an engine, mount Docker, enroll real credentials or access NAS.
"""
import json
import os
from pathlib import Path
from deployer import schema
from shared.registry import resolve
from verifier.provisioning import ProvisioningVerifier


def main():
    if os.environ.get('CD_DISPOSABLE_CI') != '1':
        raise SystemExit('disposable CI only')
    repo = 'ghcr.io/kurisu-agi/compose-cd-engine'
    index = 'sha256:46cebfe795707fb9a32d9724e8c3d9c06985fc8a65b9d3bcdcdc963860fcb8ff'
    digest, _ = resolve(repo, index, 'linux/amd64')
    cfg = json.loads(Path('/integration/policy.json').read_text())
    image = next(iter(cfg['images'].values()))
    image.update(identity='https://github.com/kurisu-agi/compose-cd-engine/.github/workflows/engine.yml@refs/heads/main')
    cfg['images'] = {repo: image}
    path = Path('/run/policy.json')
    path.write_text(json.dumps(cfg)); path.chmod(0o600)
    spec = {'services': {'engine': {'image': repo + '@' + digest, 'signed_index': repo + '@' + index, 'memory_mb': 64, 'cpus': 1}}}
    value = {'project': 'signature-ci', 'spec': spec, 'policy': schema.fingerprint(cfg)}
    verifier = ProvisioningVerifier(str(path))
    assert verifier.dispatch('verify', value)['status'] == 'verified'
    spec['services']['engine']['image'] = repo + '@sha256:' + '0' * 64
    try:
        verifier.dispatch('verify', value)
    except Exception:
        pass
    else:
        raise AssertionError('mismatched platform digest accepted')
    print('Public signed-index/platform provisioning verification and mismatched digest rejection passed. No application was deployed.')


if __name__ == '__main__':
    main()
