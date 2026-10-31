"""Webhook triggers: find the image to deploy and check where it came from.

Two ways to deploy:
- pin (GitHub, no tag): the signed `sha-<commit>` build of the branch head; the runner pins the
  service to its digest in compose.yaml/.env.
- pull (a tag): the files keep `image: <image>:<tag>`; the runner pulls that tag and recreates the
  services that use it, after checking the pulled digest is the one verified here. A GitHub
  source requires the tag's image to be signed by the workflow on the branch; a registry source
  (upstream images such as RSSHub or RustDesk) only follows the tag.
"""
import hashlib
import hmac
import json
import re
import subprocess
from shared import registry
from shared.wire import Denied

GITHUB = 'https://api.github.com/repos/'
ISSUER = 'https://token.actions.githubusercontent.com'
COSIGN = '/usr/local/bin/cosign'
REPOSITORY = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
WORKFLOW = re.compile(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml')
BRANCH = re.compile(r'[A-Za-z0-9_./-]{1,100}')
IMAGE = re.compile(r'(ghcr\.io|docker\.io)/[a-z0-9._/-]+')
TAG = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}')
PLATFORMS = ('linux/amd64', 'linux/arm64')
FIELDS = ('source', 'repository', 'workflow', 'branch', 'image', 'tag', 'platform')


def github(path):
    body, _ = registry.request(GITHUB + path, {'Accept': 'application/vnd.github+json', 'User-Agent': 'compose-deployer'})
    return json.loads(body)


def pulls(config):
    """True when the trigger pulls a tag instead of pinning a digest in the files."""
    return bool(config.get('tag'))


def label(config):
    """The image reference a pull trigger follows, as shown to people."""
    return f"{config['image']}:{config['tag']}" if pulls(config) else config['image']


def validate(config):
    """Check shape and pin the repository's numeric id (renames cannot redirect it)."""
    if not isinstance(config, dict) or set(config) - set(FIELDS) or any(not isinstance(v, str) for v in config.values()):
        raise Denied('invalid_argument', 'trigger')
    config = {'source': 'github', 'platform': 'linux/amd64', **config}
    if 'image' in config:
        config['image'] = registry.repository(config['image'])  # diygod/rsshub -> docker.io/diygod/rsshub
    if config['source'] == 'registry':
        config.setdefault('tag', 'latest')
        if set(config) != {'source', 'image', 'tag', 'platform'}:
            raise Denied('invalid_argument', 'a registry trigger takes image, tag and platform')
    elif config['source'] != 'github' or not {'repository', 'workflow', 'branch', 'image'} <= set(config):
        raise Denied('invalid_argument', 'trigger')
    if (not IMAGE.fullmatch(config['image']) or config['platform'] not in PLATFORMS
            or ('tag' in config and not TAG.fullmatch(config['tag']))):
        raise Denied('invalid_argument', 'trigger')
    if config['source'] == 'registry':
        return config
    if (not REPOSITORY.fullmatch(config['repository']) or not WORKFLOW.fullmatch(config['workflow'])
            or not BRANCH.fullmatch(config['branch']) or '..' in config['branch']):
        raise Denied('invalid_argument', 'trigger')
    try:
        config['repository_id'] = github(config['repository'])['id']
    except (OSError, ValueError, KeyError):
        raise Denied('github_unavailable') from None
    return config


def identity(config):
    if config.get('source', 'github') != 'github':
        return None
    return f"https://github.com/{config['repository']}/{config['workflow']}@refs/heads/{config['branch']}"


def verify(config, image, digest):
    """Cosign: the image must be signed by the approved workflow on the approved branch."""
    try:
        result = subprocess.run([COSIGN, 'verify', '--certificate-identity', identity(config),
                                 '--certificate-oidc-issuer', ISSUER, f'{image}@{digest}'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=180)
    except subprocess.TimeoutExpired:
        raise Denied('signature_timeout') from None  # a per-trigger failure, not the end of the polling pass
    if result.returncode:
        raise Denied('signature_invalid', result.stderr.decode('utf-8', 'replace')[-500:])


def same_repository(config):
    if github(config['repository'])['id'] != config['repository_id']:
        raise Denied('repository_changed')


def latest(config):
    """Pin mode: (commit, image@platform-digest) for the verified build of the branch head."""
    same_repository(config)
    commit = github(f"{config['repository']}/branches/{config['branch']}")['commit']['sha']
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise Denied('github_unavailable')
    image = config['image']
    _, index = registry.manifest(image, 'sha-' + commit, registry.auth(image))
    verify(config, image, index)
    digest, manifest = registry.resolve(image, index, config['platform'])
    labels = registry.labels(image, manifest)
    if labels.get('org.opencontainers.image.revision') != commit:
        raise Denied('revision_mismatch')
    return commit, f'{image}@{digest}'


def tagged(config, known=()):
    """Pull mode: where the tag points now.

    Returns {'digest'} alone when it still points to one of `known` (one HEAD request, which Docker Hub
    does not count as a pull). Otherwise {'digest', 'digests', 'image', 'size', 'commit'}: the
    tag's digest and its platform digest (either may show up in the pulled image's RepoDigests),
    the pinned platform reference, its compressed size and, when labelled, the source revision.
    """
    image, tag = config['image'], config['tag']
    github_source = config.get('source', 'github') == 'github'
    if github_source:
        same_repository(config)
    token = registry.auth(image)
    try:
        current = registry.head(image, tag, token)
    except (OSError, ValueError):
        current = None  # some registries refuse HEAD; the GET below still decides
    if current and current in known:
        return {'digest': current}
    _, index = registry.manifest(image, tag, token)
    if github_source:
        verify(config, image, index)
    digest, manifest = registry.resolve(image, index, config['platform'])
    try:
        commit = registry.labels(image, manifest).get('org.opencontainers.image.revision')
    except (OSError, ValueError, KeyError):
        commit = None
    return {'digest': index, 'digests': sorted({index, digest}), 'image': f'{image}@{digest}',
            'size': registry.size(manifest), 'commit': commit if isinstance(commit, str) else None}


def webhook(body, signature, event, secret, config):
    """True when an authenticated delivery should wake the trigger now."""
    expected = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
        raise Denied('invalid_signature')
    if config.get('source', 'github') == 'registry':
        return True  # any signed POST; the registry is polled and checked independently anyway
    payload = json.loads(body)
    if payload.get('repository', {}).get('id') != config['repository_id']:
        raise Denied('repository_mismatch')
    if event != 'workflow_run':
        return False
    run = payload.get('workflow_run') or {}
    return (payload.get('action') == 'completed' and run.get('conclusion') == 'success'
            and run.get('head_branch') == config['branch'] and run.get('path') == config['workflow'])
