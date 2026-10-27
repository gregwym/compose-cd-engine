"""Idempotent opt-in bootstrap; rejects unrelated roots before ANY mutation."""
import json
import os
import re
from pathlib import Path
from authorization.scope import require
from deployer.service import protected_directory

MARKER = 'shared-app-ingress-v1'
LEAVES = {'policy':0o755,'state':0o700,'run':0o755,'tailscale-state':0o700,'tailscale-run':0o755}


def initialize(path):
    root = Path(path)
    require(root.is_absolute() and str(root) == os.path.normpath(str(root)))
    require(len(root.parts) >= 3 and root.name not in ('docker','homes','web','etc','var','tmp'))
    require(not any(part.startswith('@') or part in ('.','..') for part in root.parts))
    # Only a dedicated administrator-selected subdirectory, never /volumeN itself.
    protected_directory(root.parent)
    if root.exists():
        require(not root.is_symlink() and root.is_dir())
        contents = set(p.name for p in root.iterdir())
        if contents:
            require(contents <= set(LEAVES) | {'.app-ingress-root'}, 'unrelated_root_contents')
            marker = root / '.app-ingress-root'
            require(marker.is_file() and not marker.is_symlink() and marker.read_text() == MARKER + '\n' + str(root), 'root_identity_mismatch')
            protected_directory(root)
            for name in LEAVES:
                require((root/name).is_dir(), 'incomplete_bootstrap')
                protected_directory(root/name)
            from management.protocol import protected_file
            protected_file(root/'policy'/'policy.json')
            return root
    else:
        root.mkdir(mode=0o700)
    # All rejection checks precede mkdir/chmod; never chown unrelated content.
    os.chmod(root,0o700)
    (root/'.app-ingress-root').write_text(MARKER + '\n' + str(root))
    os.chmod(root/'.app-ingress-root',0o600)
    for name, mode in LEAVES.items():
        (root/name).mkdir(mode=mode)
    policy = {'version':1,'enabled':False,'hostname':'','agents':[],'backends':{}}
    (root/'policy'/'policy.json').write_text(json.dumps(policy,indent=2)+'\n')
    os.chmod(root/'policy'/'policy.json',0o644)
    return root


if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',required=True)
    initialize(parser.parse_args().root)
