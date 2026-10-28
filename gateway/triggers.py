"""Webhook triggers: find the signed image GitHub built for the branch head."""
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


def github(path):
    body, _ = registry.request(GITHUB + path, {'Accept': 'application/vnd.github+json', 'User-Agent': 'compose-deployer'})
    return json.loads(body)


def validate(config):
    """Check shape and pin the repository's numeric id (renames cannot redirect it)."""
    fields = {'repository', 'workflow', 'branch', 'image', 'platform'}
    if not isinstance(config, dict) or set(config) - fields or not {'repository', 'workflow', 'branch', 'image'} <= set(config):
        raise Denied('invalid_argument', 'trigger')
    config = {'platform': 'linux/amd64', **config}
    if (not REPOSITORY.fullmatch(config['repository']) or not WORKFLOW.fullmatch(config['workflow'])
            or not BRANCH.fullmatch(config['branch']) or '..' in config['branch']
            or not IMAGE.fullmatch(config['image']) or config['platform'] not in ('linux/amd64', 'linux/arm64')):
        raise Denied('invalid_argument', 'trigger')
    try:
        config['repository_id'] = github(config['repository'])['id']
    except (OSError, ValueError, KeyError):
        raise Denied('github_unavailable') from None
    return config


def identity(config):
    return f"https://github.com/{config['repository']}/{config['workflow']}@refs/heads/{config['branch']}"


def latest(config):
    """Return (commit, image@platform-digest) for the verified build of the branch head."""
    info = github(config['repository'])
    if info['id'] != config['repository_id']:
        raise Denied('repository_changed')
    commit = github(f"{config['repository']}/branches/{config['branch']}")['commit']['sha']
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise Denied('github_unavailable')
    image = config['image']
    _, index = registry.manifest(image, 'sha-' + commit, registry.auth(image))
    result = subprocess.run([COSIGN, 'verify', '--certificate-identity', identity(config),
                             '--certificate-oidc-issuer', ISSUER, f'{image}@{index}'],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=180)
    if result.returncode:
        raise Denied('signature_invalid', result.stderr.decode('utf-8', 'replace')[-500:])
    digest, manifest = registry.resolve(image, index, config['platform'])
    labels = registry.labels(image, manifest)
    if labels.get('org.opencontainers.image.revision') != commit:
        raise Denied('revision_mismatch')
    return commit, f'{image}@{digest}'


def webhook(body, signature, event, secret, config):
    """True when an authenticated delivery should wake the trigger now."""
    expected = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
        raise Denied('invalid_signature')
    payload = json.loads(body)
    if payload.get('repository', {}).get('id') != config['repository_id']:
        raise Denied('repository_mismatch')
    if event != 'workflow_run':
        return False
    run = payload.get('workflow_run') or {}
    return (payload.get('action') == 'completed' and run.get('conclusion') == 'success'
            and run.get('head_branch') == config['branch'] and run.get('path') == config['workflow'])
