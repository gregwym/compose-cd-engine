#!/usr/bin/env python3
"""Build the GUI installation bundle. No source checkout or host tools needed on DSM."""
import argparse
from pathlib import Path
import zipfile


def build(output):
    root = Path(__file__).resolve().parent.parent
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for source, name in [('synology/compose.yaml', 'compose.yaml'),
                             ('docs/synology-deployment.zh-CN.md', 'README.md')]:
            archive.write(root / source, 'compose-deployer/' + name)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='/tmp/compose-deployer-synology.zip')
    print(build(parser.parse_args().output))
