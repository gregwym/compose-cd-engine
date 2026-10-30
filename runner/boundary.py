"""What a managed project may reach beyond itself, derived from its rendered configuration.

Every rendered setting falls into exactly one class:
- forbidden: host takeover and deployer self-protection (policy.violations, the deployer's own
  resources, Compose providers). Never approvable, whatever the grant.
- boundary: host paths outside the project directory, resources owned by others, and host-level
  features (host network, capabilities, devices, custom drivers, security profiles). Listed in the
  manage grant once, then reused for every later change, lifecycle action and exec.
- the project's own business: everything else (its services, own volumes/networks, tmpfs,
  in-project namespace sharing, hardening options, ports, environment...). Never checked.

A boundary is {"mounts": [{path, mode}], "networks": [name], "volumes": [name], "host": [feature]}.
Grants written before volumes/host existed remain valid with those lists empty.

Host paths. The runner sees only PROJECTS_ROOT; the Docker daemon mounts everything else. Paths
inside PROJECTS_ROOT are verified: symlinks are followed with realpath. Paths outside are
unverified: checked lexically (system paths, volume roots, the deployer), never read, and listed
as such for the owner. Docker follows symlinks in them when it mounts, which the runner cannot
see, so an unverified path must not lie inside a host directory this project can write (see
exposed()): the project cannot plant the symlink that would redirect its own mount.
"""
import json
import os
import posixpath
import re
from dataclasses import dataclass, field
from runner import policy, compose
from shared.wire import Denied

KEYS = ('mounts', 'networks', 'volumes', 'host')
FEATURE = re.compile(r'[a-z_]+(:[!-~]{1,200})?')
SAFE_SECURITY = re.compile(r'no-new-privileges([:=](true|false))?')
MEMORY_FS = ('tmpfs', 'ramfs')


@dataclass
class Scope:
    project: str
    working_dir: str
    deploy_root: str = ''
    views: tuple = ()  # host directories the runner sees at their own paths (PROJECTS_ROOT)
    deployer: set = field(default_factory=set)  # Compose projects that make up the deployer


def scope(identity, deploy_root, views):
    deployer = set()
    if deploy_root:
        deployer = {c['project'] for c in compose.containers()
                    if c['working_dir'] and policy.under(os.path.realpath(c['working_dir']), deploy_root)}
    return Scope(identity['project'], identity['working_dir'], deploy_root, tuple(views), deployer)


# Host paths -----------------------------------------------------------------
def visible(path, ctx):
    return any(policy.under(path, view) for view in ctx.views)


def resolve(path, ctx):
    """The host path Docker will use. Inside the runner's view, symlinks in the existing prefix are
    followed and the rest is created; outside it (or where a symlink leads out) the path is lexical."""
    path = policy.normal(path)
    if not path.startswith('/'):
        raise Denied('policy', 'relative host path')
    reason = policy.forbidden_path(path, ctx.deploy_root)
    if reason:
        raise Denied('policy', reason)
    if not visible(path, ctx):
        return path
    head, rest = path, []
    while not os.path.lexists(head):
        head, tail = posixpath.split(head)
        rest.insert(0, tail)
    real = posixpath.join(os.path.realpath(head), *rest)
    reason = policy.forbidden_path(real, ctx.deploy_root)
    if reason:
        raise Denied('policy', reason)
    return real


def unverified(boundary, ctx):
    """Mount roots the runner cannot see, so symlinks in them were not checked."""
    return [m['path'] for m in boundary.get('mounts', []) if not visible(m['path'], ctx)]


def exposed(need, ctx, *granted):
    """Unverified paths inside a host directory this project mounts, or may mount, read-write.

    The project's containers (and exec) can create symlinks there, and Docker would follow them
    on the next mount without the runner seeing it. Mount that directory itself instead."""
    writable = [m['path'] for b in (need, *granted) for m in b.get('mounts', []) if m['mode'] == 'rw']
    return sorted(f'{p} is inside writable {w}; symlinks there cannot be checked, mount {w} itself'
                  for p in unverified(need, ctx) for w in set(writable) if p != w and policy.under(p, w))


def covered(path, write, mounts):
    return any(policy.under(path, m['path']) and (not write or m['mode'] == 'rw') for m in mounts)


# Boundary documents -----------------------------------------------------------
def canonical(boundary, deploy_root, views=None):
    """Validate a requested or stored boundary; views=None skips host visibility (legacy callers)."""
    if not isinstance(boundary, dict) or set(boundary) - set(KEYS):
        raise Denied('invalid_boundary')
    mounts = boundary.get('mounts', [])
    names = {k: boundary.get(k, []) for k in ('networks', 'volumes', 'host')}
    if not isinstance(mounts, list) or len(mounts) > 64 or any(not isinstance(v, list) or len(v) > 64 for v in names.values()):
        raise Denied('invalid_boundary')
    result = {}
    for item in mounts:
        if not isinstance(item, dict) or set(item) != {'path', 'mode'} or item['mode'] not in ('ro', 'rw'):
            raise Denied('invalid_boundary')
        path = item['path']
        if not isinstance(path, str) or not path.startswith('/') or policy.normal(path) != path:
            raise Denied('unsafe_boundary', 'mount roots must be absolute normalized paths')
        if views is not None:  # verified where the runner sees the path, lexical elsewhere
            if resolve(path, Scope('', '', deploy_root, tuple(views))) != path:
                raise Denied('unsafe_boundary', f'{path} is not canonical (symlink)')
        elif policy.forbidden_source(path, deploy_root):
            raise Denied('unsafe_boundary', policy.forbidden_source(path, deploy_root))
        if result.get(path) != 'rw':
            result[path] = item['mode']
    for kind in ('networks', 'volumes'):
        if any(not isinstance(n, str) or not compose.SERVICE.fullmatch(n) or n in ('host', 'none') for n in names[kind]):
            raise Denied('invalid_boundary', kind)
    if any(not isinstance(f, str) or not FEATURE.fullmatch(f) for f in names['host']):
        raise Denied('invalid_boundary', 'host')
    return {'mounts': [{'path': p, 'mode': m} for p, m in sorted(result.items())],
            **{k: sorted(set(v)) for k, v in names.items()}}


def merge(*boundaries):
    mounts = [m for b in boundaries for m in b.get('mounts', [])]
    # Drop roots already covered by another approved root with at least the same access.
    kept = [m for m in mounts if not any(o is not m and o != m and policy.under(m['path'], o['path'])
                                         and (m['mode'] == 'ro' or o['mode'] == 'rw') for o in mounts)]
    return canonical({'mounts': kept, **{k: [x for b in boundaries for x in b.get(k, [])]
                                         for k in ('networks', 'volumes', 'host')}}, '')


def missing(need, boundary):
    out = [f"mount {m['path']} ({m['mode']})" for m in need['mounts']
           if not covered(m['path'], m['mode'] == 'rw', boundary['mounts'])]
    for kind in ('networks', 'volumes', 'host'):
        out += [f'{kind[:-1] if kind != "host" else "host"} {x}' for x in need[kind] if x not in boundary.get(kind, [])]
    return out


# Docker resources -------------------------------------------------------------
def inspect(kind, name):
    out = compose.run([compose.DOCKER, kind, 'inspect', name], check=False)
    try:
        items = json.loads(out or b'[]')
    except ValueError:
        return None
    return items[0] if items else None


def owner(resource):
    return ((resource or {}).get('Labels') or {}).get(compose.LABEL + 'project')


class Needs:
    def __init__(self, ctx):
        self.ctx = ctx
        self.mounts, self.networks, self.volumes, self.host = {}, set(), set(), set()

    def path(self, path, write):
        real = resolve(path, self.ctx)
        if policy.under(real, os.path.realpath(self.ctx.working_dir)):
            return
        if write or real not in self.mounts:
            self.mounts[real] = 'rw' if write else self.mounts.get(real, 'ro')

    def container(self, ref, what):
        """container:<name|id> must be one of this project's own containers."""
        found = inspect('container', ref)
        project = (((found or {}).get('Config') or {}).get('Labels') or {}).get(compose.LABEL + 'project')
        if project in self.ctx.deployer:
            raise Denied('policy', f'{what} joins the deployer')
        if project != self.ctx.project:
            raise Denied('boundary_exceeded', f'{what} joins a container of another project; use service:<name>')

    def resource(self, kind, key, spec):
        """A top-level volume or network: own, foreign (boundary) or the deployer's (forbidden)."""
        spec = spec or {}
        name = spec.get('name') or f'{self.ctx.project}_{key}'
        if kind == 'network' and name == 'host':
            self.host.add('network_mode:host')
            return
        if kind == 'network' and name in ('none', 'bridge'):
            return
        existing = inspect(kind, name)
        if existing is not None:
            project = owner(existing)
            if project in self.ctx.deployer:
                raise Denied('policy', f'{kind} {name} belongs to the deployer')
            if project != self.ctx.project:
                (self.networks if kind == 'network' else self.volumes).add(name)
            self.driver(kind, name, existing.get('Driver'), existing.get('Options'))
        elif spec.get('external'):
            raise Denied('docker_failed', f'external {kind} {name} does not exist')
        if not spec.get('external'):
            self.driver(kind, name, spec.get('driver'), spec.get('driver_opts'))

    def driver(self, kind, name, driver, options):
        options = options or {}
        if kind == 'volume':
            if driver not in (None, '', 'local'):
                self.host.add('volume_driver:' + driver)
                return
            fstype = str(options.get('type', '')).lower()
            device = options.get('device')
            if not options or fstype in MEMORY_FS:
                return
            if fstype in ('none', 'bind', '') and 'bind' in str(options.get('o', '')) and isinstance(device, str):
                self.path(device, True)
                return
            self.host.add('volume_mount:' + (fstype or 'custom'))
        else:
            if driver not in (None, '', 'bridge'):
                self.host.add('network_driver:' + driver)
            elif options:
                self.host.add('network_options')

    def boundary(self):
        return {'mounts': [{'path': p, 'mode': m} for p, m in sorted(self.mounts.items())],
                'networks': sorted(self.networks), 'volumes': sorted(self.volumes), 'host': sorted(self.host)}


def namespace(needs, service, key, value):
    value = str(value)
    if value.startswith('container:'):
        needs.container(value.split(':', 1)[1], f'{service}: {key}')
    elif key == 'network_mode' and value == 'host':
        needs.host.add('network_mode:host')
    # service:<name> stays inside the project; host pid/ipc/uts/userns/cgroup are policy violations.


def derive(config, ctx):
    """The boundary a fully rendered (env_file-preserving) configuration needs; raises on forbidden."""
    errors = policy.violations(config, ctx.deploy_root)
    if errors:
        raise Denied('policy', errors)
    needs = Needs(ctx)
    for kind in ('volumes', 'networks'):
        for key, spec in sorted((config.get(kind) or {}).items()):
            needs.resource(kind[:-1], key, spec)
    for kind in ('secrets', 'configs'):
        for item in (config.get(kind) or {}).values():
            if isinstance((item or {}).get('file'), str):
                needs.path(item['file'], False)
    for name, service in sorted((config.get('services') or {}).items()):
        if service.get('provider'):
            raise Denied('policy', f'{name}: provider runs a host program')
        for hook in (service.get('post_start') or []) + (service.get('pre_stop') or []):
            if isinstance(hook, dict) and hook.get('privileged'):
                raise Denied('policy', f'{name}: privileged lifecycle hook')
        for item in service.get('env_file') or []:
            path = item.get('path') if isinstance(item, dict) else item
            if isinstance(path, str) and (os.path.lexists(path) or not (isinstance(item, dict) and item.get('required') is False)):
                if not visible(policy.normal(path), ctx):  # Compose reads it inside the runner
                    raise Denied('not_visible', f'{name}: env_file must be inside PROJECTS_ROOT')
                needs.path(path, False)
        for mount in service.get('volumes') or []:
            kind = mount.get('type') if isinstance(mount, dict) else None
            if kind == 'bind':
                needs.path(mount.get('source', ''), not mount.get('read_only'))
                propagation = (mount.get('bind') or {}).get('propagation')
                if propagation not in (None, '', 'rprivate', 'private'):
                    needs.host.add('mount_propagation:' + propagation)
            elif kind not in ('volume', 'tmpfs', 'image'):
                needs.host.add('mount:' + str(kind))
        for key in ('network_mode', 'pid', 'ipc'):
            if service.get(key):
                namespace(needs, name, key, service[key])
        for item in service.get('volumes_from') or []:
            if str(item).startswith('container:'):
                needs.container(str(item).split(':')[1], f'{name}: volumes_from')
        for cap in service.get('cap_add') or []:
            needs.host.add('cap:' + str(cap).upper().removeprefix('CAP_'))
        for device in service.get('devices') or []:
            source = device.get('source') if isinstance(device, dict) else str(device).split(':')[0]
            needs.host.add('device:' + str(source))
        for rule in service.get('device_cgroup_rules') or []:
            needs.host.add('device_cgroup_rule:' + str(rule).replace(' ', '_'))
        if service.get('gpus') or ((((service.get('deploy') or {}).get('resources') or {})
                                    .get('reservations') or {}).get('devices')):
            needs.host.add('gpu')
        for option in service.get('security_opt') or []:
            if not SAFE_SECURITY.fullmatch(str(option)):
                needs.host.add('security_opt:' + str(option).replace(' ', '_'))
        for key in ('cgroup_parent', 'runtime'):
            if service.get(key) and not (key == 'runtime' and service[key] == 'runc'):
                needs.host.add(f'{key}:{service[key]}')
    return needs.boundary()


def preflight(data):
    """Reject Compose features that load other files BEFORE Compose reads them.

    Rendered output cannot show what include, extends.file or label_file loaded, so a project
    could pull another project's files into its own. env_file stays visible in a render with
    --no-env-resolution and is checked like any host path. A conservative lexical gate without
    a YAML dependency: escapes and tags (which could hide a key) are not supported.
    """
    text = data.decode() if isinstance(data, bytes) else data
    if chr(92) in text or re.search(r'(?m)^\s*%|!!|!<', text) or re.search(r'(?m)(^|[\s\[{,:-])![A-Za-z]', text):
        raise Denied('unsupported_compose', 'escapes and YAML tags are not supported')
    for key in ('include', 'extends', 'label_file'):
        if re.search(r'(?<![A-Za-z0-9_])' + re.escape(key) + r'''['"]?\s*:''', text):
            raise Denied('unsupported_compose', key + ' loads other files and is not supported in managed projects')


def check(config, identity, boundary, ctx):
    """Fail closed unless everything the configuration needs is inside the approved boundary."""
    boundary = canonical(boundary, ctx.deploy_root)
    need = derive(config, ctx)
    gaps = missing(need, boundary)
    if gaps:
        raise Denied('boundary_exceeded', gaps)
    problems = exposed(need, ctx, boundary)
    if problems:
        raise Denied('unverifiable_path', problems)
    return boundary
