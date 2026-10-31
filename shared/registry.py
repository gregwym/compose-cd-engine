"""Small HTTPS-only OCI reader; never executes registry/upstream content."""
import hashlib
import json
import re
import urllib.parse
import urllib.request

DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
ACCEPT = ', '.join(['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'])

def request(url, headers=None, limit=8*1024*1024):
    if not url.startswith('https://'):
        raise ValueError('HTTPS required')
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=30) as r:
        if not r.url.startswith('https://'):
            raise ValueError('HTTPS required')
        body = r.read(limit+1)
        if len(body) > limit:
            raise ValueError('response too large')
        return body, r.headers

def locate(image):
    if image.startswith('docker.io/'):
        return 'registry-1.docker.io', image[len('docker.io/'):]
    if image.startswith('ghcr.io/'):
        return 'ghcr.io', image[len('ghcr.io/'):]
    raise ValueError('registry not approved')

def auth(image):
    host, name = locate(image)
    if host == 'registry-1.docker.io':
        url = 'https://auth.docker.io/token?' + urllib.parse.urlencode({'service':'registry.docker.io','scope':f'repository:{name}:pull'})
    else:
        url = 'https://ghcr.io/token?' + urllib.parse.urlencode({'service':'ghcr.io','scope':f'repository:{name}:pull'})
    return json.loads(request(url)[0])['token']

def manifest(image, ref, token):
    host, name = locate(image)
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+', ref):
        raise ValueError('bad reference')
    raw, headers = request(f'https://{host}/v2/{name}/manifests/{ref}', {'Authorization':'Bearer '+token, 'Accept':ACCEPT})
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    if headers.get('Docker-Content-Digest', digest) != digest or (ref.startswith('sha256:') and ref != digest):
        raise ValueError('manifest digest mismatch')
    return json.loads(raw), digest

def head(image, ref, token):
    """Digest a tag points to, without downloading the manifest (HEAD is not a Docker Hub pull)."""
    host, name = locate(image)
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+', ref):
        raise ValueError('bad reference')
    request = urllib.request.Request(f'https://{host}/v2/{name}/manifests/{ref}', method='HEAD',
                                     headers={'Authorization': 'Bearer ' + token, 'Accept': ACCEPT})
    with urllib.request.urlopen(request, timeout=30) as r:
        if not r.url.startswith('https://'):
            raise ValueError('HTTPS required')
        value = r.headers.get('Docker-Content-Digest', '')
    return value if DIGEST.fullmatch(value) else None


def resolve(image, ref, platform='linux/amd64'):
    token = auth(image)
    doc, digest = manifest(image, ref, token)
    if 'manifests' in doc:
        os_name, arch = platform.split('/')
        matches = [x for x in doc['manifests'] if x.get('platform',{}).get('os') == os_name and x.get('platform',{}).get('architecture') == arch and x.get('platform',{}).get('variant') in (None,'','v8')]
        if len(matches) != 1 or not DIGEST.fullmatch(matches[0]['digest']):
            raise ValueError('platform unavailable or ambiguous')
        doc, digest = manifest(image, matches[0]['digest'], token)
    return digest, doc

def labels(image, manifest_doc):
    return config_document(image, manifest_doc).get('config',{}).get('Labels',{}) or {}

def config_document(image, manifest_doc):
    digest = manifest_doc['config']['digest']
    if not DIGEST.fullmatch(digest):
        raise ValueError('bad config digest')
    host, name = locate(image)
    raw, _ = request(f'https://{host}/v2/{name}/blobs/{digest}', {'Authorization':'Bearer '+auth(image)})
    if 'sha256:'+hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('config digest mismatch')
    return json.loads(raw)


def repository(ref):
    """Canonical repository of an image reference, without tag or digest."""
    name = ref.split('@', 1)[0]
    head, _, tail = name.rpartition('/')
    name = (head + '/' if head else '') + tail.split(':', 1)[0]
    first = name.split('/', 1)[0]
    if '/' not in name or ('.' not in first and ':' not in first and first != 'localhost'):
        name = 'docker.io/' + (name if '/' in name else 'library/' + name)
    return name


def tag(ref):
    """Tag of an image reference ('latest' when omitted), or None when it is pinned by digest."""
    if '@' in ref:
        return None
    last = ref.rsplit('/', 1)[-1]
    return last.split(':', 1)[1] if ':' in last else 'latest'


def size(manifest_doc):
    """Compressed bytes a pull of this platform manifest downloads at most."""
    parts = list(manifest_doc.get('layers') or []) + [manifest_doc.get('config') or {}]
    return sum(int(p.get('size') or 0) for p in parts if isinstance(p, dict))
