"""Hard limits and review highlights for a fully rendered Compose configuration."""
import os
import posixpath
import re

SYSTEM = ('/etc', '/proc', '/sys', '/dev', '/boot', '/root', '/usr', '/bin', '/sbin', '/lib', '/lib64',
          '/run', '/var/run', '/var/lib/docker', '/var/packages')
# Capabilities that amount to the host itself: mounts, kernel modules, raw I/O, reading any host file
# by handle, LSM policy. Other capabilities are host-level but approvable per project.
FORBIDDEN_CAPS = {'ALL', 'SYS_ADMIN', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_BOOT', 'DAC_READ_SEARCH', 'MAC_ADMIN',
                  'MAC_OVERRIDE', 'BPF'}


def under(path, root):
    return path == root or path.startswith(root.rstrip('/') + '/')


def normal(path):
    return posixpath.normpath(path) if path.startswith('/') else path


def forbidden_source(source, deploy_root):
    """Check the lexical path and, where the runner can see it, the symlink-resolved target."""
    path = normal(source)
    if not path.startswith('/'):
        return None
    reason = forbidden_path(path, deploy_root)
    if reason:
        return reason
    real = os.path.realpath(path)
    reason = forbidden_path(real, deploy_root) if real != path else None
    return 'symlink ' + reason if reason else None


def forbidden_path(path, deploy_root):
    # Paths can come from interpolated .env values, so they stay out of the message.
    if path == '/' or path.endswith('docker.sock'):
        return 'mounts the host root or a Docker socket'
    if any(under(path, item) for item in SYSTEM):
        return 'mounts a system path'
    parts = path.split('/')
    if re.fullmatch(r'volume[0-9]+(USB[0-9]+)?', parts[1]) and (len(parts) == 2 or any(p.startswith('@') for p in parts[2:])):
        return 'mounts a volume root or system directory'
    if deploy_root and (under(path, deploy_root) or under(deploy_root, path)):
        return 'mounts the deployer directory'  # or a directory that contains it
    return None


def binds(service):
    for item in service.get('volumes') or []:
        if isinstance(item, dict) and item.get('type') == 'bind' and item.get('source'):
            yield item


def volume_devices(config):
    """Top-level named volumes backed by a host path through the local driver's options."""
    for name, volume in sorted((config.get('volumes') or {}).items()):
        device = ((volume or {}).get('driver_opts') or {}).get('device')
        if isinstance(device, str) and device.startswith('/'):
            yield name, device


def host_files(config):
    """Host files mounted through top-level secrets and configs.

    env_file is not here: a normal render merges and drops it; violations() checks it in renders
    made with --no-env-resolution, which keep it."""
    for kind in ('secrets', 'configs'):
        for name, item in sorted((config.get(kind) or {}).items()):
            path = (item or {}).get('file')
            if isinstance(path, str) and path.startswith('/'):
                yield f'{kind[:-1]} {name}', path


def violations(config, deploy_root):
    found = []
    for name, device in volume_devices(config):
        reason = forbidden_source(device, deploy_root)
        if reason:
            found.append(f'volume {name}: {reason}')
    for label, path in host_files(config):
        reason = forbidden_source(path, deploy_root)
        if reason:
            found.append(f'{label}: {reason}')
    for name, service in sorted((config.get('services') or {}).items()):
        if service.get('privileged'):
            found.append(f'{name}: privileged')
        if {str(c).upper().removeprefix('CAP_') for c in service.get('cap_add') or []} & FORBIDDEN_CAPS:
            found.append(f'{name}: forbidden capability')
        for key in ('pid', 'userns_mode', 'cgroup', 'ipc', 'uts'):
            if service.get(key) == 'host':
                found.append(f'{name}: {key}: host')
        if any('unconfined' in str(opt) for opt in service.get('security_opt') or []):
            found.append(f'{name}: unconfined security profile')
        if service.get('use_api_socket'):
            found.append(f'{name}: use_api_socket')  # Compose injects the Docker socket at create time
        if service.get('build'):
            found.append(f'{name}: build is not supported')
        for item in binds(service):
            reason = forbidden_source(item['source'], deploy_root)
            if reason:
                found.append(f'{name}: {reason}')
        for item in service.get('env_file') or []:  # present only in --no-env-resolution renders
            path = item.get('path') if isinstance(item, dict) else item
            reason = forbidden_source(path, deploy_root) if isinstance(path, str) else None
            if reason:
                found.append(f'{name}: env_file {reason}')
        for item in service.get('volumes') or []:
            if isinstance(item, dict) and item.get('type') == 'npipe':
                found.append(f'{name}: npipe mount')
    return found


def unchecked(path):
    # The runner sees only PROJECTS_ROOT; elsewhere a symlink to a forbidden path cannot be detected.
    return '' if os.path.lexists(path) else ', symlinks not checked'


def highlights(config, working_dir):
    """Every reviewable risk of a configuration, as stable strings."""
    out = set()
    for name, device in volume_devices(config):
        if not under(normal(device), working_dir):
            out.add(f'volume {name}: host path {normal(device)}{unchecked(device)}')
    for label, path in host_files(config):
        if not under(normal(path), working_dir):
            out.add(f'{label}: host file {normal(path)}{unchecked(path)}')
    for name, service in (config.get('services') or {}).items():
        if service.get('network_mode') == 'host':
            out.add(f'{name}: host network')
        for cap in service.get('cap_add') or []:
            out.add(f'{name}: capability {cap}')
        for device in service.get('devices') or []:
            label = (f"{device.get('source')}:{device.get('target')}" if isinstance(device, dict) else str(device))
            out.add(f'{name}: device {label}')
        for item in binds(service):
            source = normal(item['source'])
            if not under(source, working_dir):
                mode = 'read-only' if item.get('read_only') else 'READ-WRITE'
                out.add(f"{name}: host path {source} -> {item.get('target')} ({mode}{unchecked(source)})")
        for port in service.get('ports') or []:
            if isinstance(port, dict) and port.get('published'):
                host = port.get('host_ip') or '0.0.0.0'
                out.add(f"{name}: port {host}:{port['published']} -> {port.get('target')}/{port.get('protocol', 'tcp')}")
    return out


def new_highlights(before, after, working_dir):
    old = highlights(before, working_dir) if before else set()
    return sorted(highlights(after, working_dir) - old)

