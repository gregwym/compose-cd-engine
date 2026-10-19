"""Network-only verification RPC for provisioning. No Docker or app data mounts."""
import json
import os
import re
from pathlib import Path
from authorization import rpc
from authorization.scope import require
from deployer import schema
from management.protocol import trusted_json
from shared.registry import resolve, config_document
from verifier.verifier import cosign


class ProvisioningVerifier:
    def __init__(self, policy):
        self.path = policy

    def dispatch(self, op, value):
        require(op == 'verify', 'verification_failed')
        schema.fields(value, {'project', 'spec', 'policy'})
        cfg = schema.policy(trusted_json(self.path))
        require(schema.fingerprint(cfg) == value['policy'], 'verification_failed')
        schema.compile_project(value['project'], value['spec'], cfg)
        revisions = {}
        sources = {}
        results = {}
        for service, item in value['spec']['services'].items():
            repo, digest = item['image'].split('@')
            image = cfg['images'][repo]
            if image['allow_unsigned']:
                require(digest[7:] in image['digests'], 'verification_failed')
                results[service] = 'administrator_unsigned_exception'
                continue
            signed = item.get('signed_index', item['image'])
            require(signed.split('@')[0] == repo, 'verification_failed')
            cosign('verify', '--certificate-identity', image['identity'],
                   '--certificate-oidc-issuer', image['issuer'], signed)
            resolved, manifest = resolve(repo, signed.split('@')[1], image['platform'])
            require(resolved == digest, 'verification_failed')
            doc = config_document(repo, manifest)
            require(doc.get('os') + '/' + doc.get('architecture') == image['platform'], 'verification_failed')
            labels = doc.get('config', {}).get('Labels', {}) or {}
            revision = labels.get('org.opencontainers.image.revision', '')
            source = labels.get('org.opencontainers.image.source', '')
            expected_source = image['identity'].split('/.github/workflows/')[0]
            require(source == expected_source and re.fullmatch('[a-f0-9]{40}', revision), 'verification_failed')
            # Images built from the same source must agree across service images.
            require(source not in revisions or revisions[source] == revision, 'verification_failed')
            revisions[source] = revision
            sources[service] = source
            results[service] = 'signed_platform_digest'
        for group in cfg.get('release_groups', []):
            if set(group).intersection(value['spec']['services']):
                require(all(s in sources for s in group) and len({sources[s] for s in group}) == 1,
                        'verification_failed')
        return {'status': 'verified', 'services': results}


def main():
    os.umask(0o077)
    path = os.environ['CD_PROVISIONER_VERIFY_POLICY']
    cfg = schema.policy(trusted_json(path))['verification']
    verifier = ProvisioningVerifier(path)
    def dispatch(op, value):
        try:
            return verifier.dispatch(op, value)
        except Exception:
            from authorization.scope import Denied
            raise Denied('verification_failed') from None
    rpc.serve(cfg, dispatch,
              str(Path(os.environ.get('CD_VERIFY_STATE', '/var/lib/compose-cd-verification')) / 'nonces.sqlite'))


if __name__ == '__main__':
    main()
