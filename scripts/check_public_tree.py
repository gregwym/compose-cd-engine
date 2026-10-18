#!/usr/bin/env python3
"""Bounded pre-publication check; not a proof of absence of every secret format."""
import re
import subprocess
from pathlib import Path

def main():
    failures = []
    names = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
    secret = re.compile(rb'(?:-----BEGIN (?:OPENSSH|RSA|EC|PRIVATE).*?KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})')
    for name in filter(None, names):
        path = Path(name)
        if not path.is_file(): continue
        if any(part in ('private', 'secrets', 'state', 'inbox', 'candidates') for part in path.parts) or path.name in ('.env', 'candidate.json', 'candidate.bundle.json'):
            failures.append(name)
        if secret.search(path.read_bytes()): failures.append(name)
    if failures: raise SystemExit('Public-tree check rejected paths: ' + ', '.join(sorted(set(failures))))
    print('Public-tree check passed (bounded path/token checks)')
if __name__ == '__main__': main()
