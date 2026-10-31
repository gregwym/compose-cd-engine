"""The only component with the Docker socket: fixed operations, no database.

Every call re-validates project identity, file hashes and the hard policy, so
the gateway decides *who* may act but never *what* is possible."""
import copy
import difflib
import json
import os
import re
import socket
import secrets
import shutil
import tempfile
import threading
import time
from pathlib import Path
from runner import compose, files, policy, boundary as bounds, diagnostics, execution
from shared.registry import DIGEST, repository, tag as image_tag
from shared import preview
from shared.wire import Denied, canonical, digest, read_line

SOCKET = os.environ.get('CD_RUNNER_SOCKET', '/run/compose-cd/runner.sock')
ACTIONS = ('start', 'stop', 'restart', 'up', 'update')
PINNED = re.compile(r'[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}')
IMAGE = re.compile(r'[a-z0-9][a-z0-9._/:-]*')
TAG = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}')


def sha(data):
    return None if data is None else digest(data)


class Runner:
    def __init__(self, projects_root, deploy_root='', health_timeout=120, min_free_mb=1024):
        self.root = Path(projects_root).resolve(strict=True)
        self.deploy_root = str(Path(deploy_root).resolve()) if deploy_root else ''
        self.health_timeout = health_timeout
        self.min_free = min_free_mb * 1024 * 1024
        # The only host directory the runner sees; data directories are mounted by the Docker
        # daemon and authorized as written (runner/boundary.py).
        self.views = (str(self.root),)
        self.lock = threading.Lock()

    # Identity -------------------------------------------------------------
    def why_unmanageable(self, identity):
        wd = identity['working_dir']
        if not wd.startswith('/'):
            return 'working directory unknown'
        real = os.path.realpath(wd)
        if self.deploy_root and policy.under(real, self.deploy_root):
            return 'the deployer itself'
        if real == str(self.root) or not policy.under(real, str(self.root)):
            return 'outside PROJECTS_ROOT'
        if not identity['config_files'] or any(
                not policy.under(os.path.realpath(f), real) for f in identity['config_files']):
            return 'Compose files outside the project directory'
        return None

    def identity(self, identity, change=False, new=False):
        if not isinstance(identity, dict) or set(identity) != {'project', 'working_dir', 'config_files'}:
            raise Denied('invalid_identity')
        name, wd, config = identity['project'], identity['working_dir'], identity['config_files']
        if (not isinstance(name, str) or not compose.NAME.fullmatch(name) or not isinstance(wd, str)
                or not wd.startswith('/') or not isinstance(config, list) or not 1 <= len(config) <= 8
                or any(not isinstance(f, str) or not f.startswith('/') for f in config)):
            raise Denied('invalid_identity')
        reason = self.why_unmanageable(identity)
        if reason:
            raise Denied('not_manageable', reason)
        if change and len(config) != 1:
            raise Denied('not_manageable', 'changes need a single Compose file')
        observed = compose.observed_identity(name)
        if new:
            if os.path.realpath(wd) != wd:
                raise Denied('invalid_identity', 'canonical project paths required')
            if os.path.lexists(wd) or observed:
                raise Denied('project_exists')
            if config != [wd.rstrip('/') + '/compose.yaml'] or Path(wd).parent.resolve() != self.root:
                raise Denied('invalid_identity')
            return identity
        if os.path.realpath(wd) != wd or any(os.path.realpath(f) != f for f in config):
            raise Denied('invalid_identity', 'canonical project paths required')
        if not Path(wd).is_dir() or Path(wd).is_symlink():
            raise Denied('project_missing')
        for item in config:
            if Path(item).is_symlink() or not Path(item).is_file():
                raise Denied('project_missing', Path(item).name)
        if observed and observed != identity:
            raise Denied('identity_changed', 'Container Manager project identity differs from the approved one')
        return identity

    def scope(self, identity):
        return bounds.scope(identity, self.deploy_root, self.views)

    def authorize_boundary(self, identity, boundary, new=False, compose_text=None, derive=True):
        """The boundary a manage grant records: what was asked for, plus what the project's current
        files and an optional proposed compose.yaml need, so approved projects stay manageable."""
        identity = self.identity(identity, new=new)
        ctx = self.scope(identity)
        result = bounds.canonical(boundary, self.deploy_root)
        derived = []
        if derive and not new:
            derived.append(bounds.derive(self.structure(identity), ctx))
        if derive and compose_text is not None:
            if not isinstance(compose_text, str) or len(compose_text.encode()) > files.MAX_FILE:
                raise Denied('invalid_argument', 'compose')
            env = None if new else files.read(Path(identity['working_dir']) / '.env')
            bounds.preflight(compose_text)
            derived.append(bounds.derive(self.render(identity, compose_text.encode(), env, env_resolution=False), ctx))
        return bounds.merge(result, *derived) if derived else result

    def structure(self, identity):
        """The rendered configuration as policy sees it: env_file paths kept, not read."""
        for path in identity['config_files']:
            bounds.preflight(files.read(path))
        return compose.render(identity, env_resolution=False)

    def check_boundary(self, identity, boundary):
        return bounds.check(self.structure(identity), identity, boundary, self.scope(identity))

    # Reads ----------------------------------------------------------------
    def projects(self):
        grouped = {}
        for c in compose.containers():
            grouped.setdefault(c['project'], []).append(c)
        out = []
        for name, items in sorted(grouped.items()):
            try:
                identity = compose.observed_identity(name, items)
                reason = self.why_unmanageable(identity)
            except Denied as exc:
                identity, reason = None, exc.detail
            out.append({'project': name, 'identity': identity, 'manageable': reason is None, 'reason': reason,
                        'services': [{k: c[k] for k in ('service', 'name', 'image', 'state', 'health', 'ports')}
                                     for c in sorted(items, key=lambda c: (c['service'], c['name']))]})
        return {'root': str(self.root), 'projects': out}

    def logs(self, project, service=None, tail=100):
        if type(tail) is not int or not 1 <= tail <= 500:
            raise Denied('invalid_argument', 'tail')
        items = [c for c in compose.project_containers(project) if service in (None, c['service'])]
        if not items:
            raise Denied('not_found')
        raw = diagnostics.inspect_project(project)
        values = [v.split('=', 1)[1] for c in raw for v in (c.get('Config') or {}).get('Env') or [] if '=' in v]
        return {'logs': {c['name']: diagnostics.clean_text(compose.logs(c['id'], tail), values) for c in items[:8]}}

    def diagnose(self, project):
        return diagnostics.diagnose(project)

    def exec(self, identity, boundary, container, argv, expires, timeout=30, authorize=None):
        execution.validate(argv, timeout)
        if not isinstance(container, str) or not re.fullmatch(r'[a-f0-9]{64}', container):
            raise Denied('invalid_argument', 'full container id required')
        with self.lock:
            # The grant covers the project as it runs; only host takeover stays out of reach.
            identity = self.identity(identity)
            raw = diagnostics.inspect_project(identity['project'])
            target = next((c for c in raw if c['Id'] == container), None)
            if not target:
                raise Denied('target_mismatch')
            labels = (target.get('Config') or {}).get('Labels') or {}
            if (labels.get(compose.LABEL + 'project') != identity['project'] or
                    labels.get(compose.LABEL + 'project.working_dir') != identity['working_dir'] or
                    labels.get(compose.LABEL + 'project.config_files', '').split(',') != identity['config_files']):
                raise Denied('identity_changed')
            host = target.get('HostConfig') or {}
            caps = {str(c).upper().removeprefix('CAP_') for c in host.get('CapAdd') or []}
            if (host.get('Privileged') or caps & policy.FORBIDDEN_CAPS or
                    # Not CgroupnsMode: 'host' is Docker's default on cgroup v1 hosts such as DSM 7.
                    any(host.get(k) == 'host' for k in ('PidMode', 'IpcMode', 'UTSMode', 'UsernsMode')) or
                    any(policy.forbidden_source(m.get('Source') or '', self.deploy_root)
                        for m in target.get('Mounts') or [] if m.get('Type') == 'bind')):
                raise Denied('policy', 'the running container has host-level access no grant can give')
            # The private socket adapter supplies the callback, never a JSON argument.
            if authorize is None:
                raise Denied('not_authorized', 'execution authorization handshake required')
            authorize()
            if type(expires) is not int or expires <= time.time():
                raise Denied('not_authorized', 'elevation expired')
            timeout = min(timeout, max(1, int(expires - time.time())))
            result = execution.run(container, argv, timeout)
            values = [v.split('=', 1)[1] for v in (target.get('Config') or {}).get('Env') or [] if '=' in v]
            result['output'] = diagnostics.clean_text(result['output'], values)
            return result

    def read(self, identity):
        identity = self.identity(identity)
        data = files.read(identity['config_files'][0])
        env = files.read(Path(identity['working_dir']) / '.env')
        return {'compose': data.decode('utf-8', 'replace'), 'compose_sha': sha(data),
                'env_keys': files.env_keys(env), 'env_sha': sha(env), 'config_files': identity['config_files']}

    # Lifecycle ------------------------------------------------------------
    def services(self, services):
        services = services or []
        if not isinstance(services, list) or any(not isinstance(s, str) or not compose.SERVICE.fullmatch(s)
                                                 for s in services):
            raise Denied('invalid_argument', 'services')
        return services

    def lifecycle(self, identity, action, services=None, boundary=None):
        if action not in ACTIONS:
            raise Denied('invalid_argument', 'action')
        services = self.services(services)
        with self.lock:
            identity = self.identity(identity)
            # start/stop/restart reuse the containers that exist; only (re)creation reads the files.
            if action in ('start', 'stop', 'restart'):
                compose.compose(identity, action, *services, timeout=600)
                if action != 'stop':
                    compose.wait_healthy(identity, self.health_timeout, services)
                return {'status': 'success'}
            # Files may have changed since the grant; anything that (re)creates containers re-checks them.
            self.check_files(identity, boundary)
            if action == 'up':
                compose.compose(identity, 'up', '-d', '--no-build', *services)
                compose.wait_healthy(identity, self.health_timeout, services)
                return {'status': 'success'}
            self.space()
            previous = compose.image_ids(identity)
            compose.compose(identity, 'pull', '--ignore-buildable', *services)
            try:
                compose.compose(identity, 'up', '-d', '--no-build', *services)
                compose.wait_healthy(identity, self.health_timeout, services)
            except Denied as exc:
                return self.recover(exc, lambda: [compose.retag(ref, image_id) for ref, image_id in previous.values()],
                                    identity, services)
            now = compose.image_ids(identity)
            return {'status': 'success',
                    'updated': sorted(s for s, (_, old) in previous.items() if now.get(s, (None, old))[1] != old)}

    def check_files(self, identity, boundary=None):
        """What the files would (re)create: inside the manage boundary, or within the hard policy."""
        if boundary is not None:
            self.check_boundary(identity, boundary)
            return
        found = policy.violations(compose.render(identity), self.deploy_root)
        if found:
            raise Denied('policy', found)

    def space(self, size=0):
        """Refuse a pull that could fill the disk: keep CD_MIN_FREE_MB plus twice the download free.

        Measured on PROJECTS_ROOT, the only host file system the runner sees; Docker's data root
        is usually on the same one (a VPS root disk, a Synology volume)."""
        if not self.min_free:
            return
        free = shutil.disk_usage(self.root).free
        needed = self.min_free + 2 * max(0, size)
        if free < needed:
            raise Denied('insufficient_space', f'{free >> 20} MiB free, {needed >> 20} MiB required')

    def recover(self, exc, restore, identity, services=()):
        try:
            restore()
            # --pull never: the restored image id must decide what starts, even with pull_policy: always.
            compose.compose(identity, 'up', '-d', '--no-build', '--pull', 'never', '--remove-orphans', *services)
            compose.wait_healthy(identity, self.health_timeout, services)
        except (Denied, OSError) as again:
            code, detail = (again.code, again.detail) if isinstance(again, Denied) else ('write_failed', type(again).__name__)
            return {'status': 'failed', 'error': exc.code, 'detail': exc.detail,
                    'rollback_error': code, 'rollback_detail': detail}
        return {'status': 'rolled_back', 'error': exc.code, 'detail': exc.detail}

    def down(self, identity, boundary=None):
        with self.lock:
            identity = self.identity(identity)
            # Removes only this project's containers and networks (never volumes); nothing to check.
            compose.compose(identity, 'down', '--remove-orphans', timeout=600)
            return {'status': 'success'}

    # Changes --------------------------------------------------------------
    def render(self, identity, data, env, env_resolution=True):
        with tempfile.TemporaryDirectory(prefix='cd-plan-') as tmp:
            path, env_path = Path(tmp) / 'compose.yaml', Path(tmp) / 'env'
            path.write_bytes(data)
            env_path.write_bytes(env or b'')
            return compose.render(identity, [path], env_path, env_resolution=env_resolution)

    def plan(self, identity, compose_text=None, env_set=None, env_unset=None, new=False, expect=None, boundary=None):
        identity = self.identity(identity, change=True, new=new)
        path = Path(identity['config_files'][0])
        current = None if new else files.read(path)
        env = None if new else files.read(Path(identity['working_dir']) / '.env')
        if compose_text is None and current is None:
            raise Denied('invalid_argument', 'compose')
        if compose_text is not None and (not isinstance(compose_text, str) or len(compose_text.encode()) > files.MAX_FILE):
            raise Denied('invalid_argument', 'compose')
        data = compose_text.encode() if compose_text is not None else current
        new_env = files.edit_env(env, env_set, env_unset) if (env_set or env_unset) else env
        if data == current and new_env == env:
            raise Denied('no_change')
        if boundary is not None:
            # Before any full render: env_file paths must be inside the boundary before Compose reads them.
            bounds.preflight(data)
            try:
                structure = self.render(identity, data, new_env, env_resolution=False)
            except Denied as exc:
                if exc.code != 'docker_failed':
                    raise
                raise Denied('invalid_compose', 'docker compose config rejected the file') from None
            boundary = bounds.check(structure, identity, boundary, self.scope(identity))
        before = None
        if current is not None:
            try:
                before = compose.render(identity)
            except Denied:
                before = None
        try:
            after = self.render(identity, data, new_env)
        except Denied as exc:
            if exc.code != 'docker_failed':
                raise
            # Compose quotes interpolated .env values in its errors, and agents can put any of them
            # into an invalid field before approval; scrubbing cannot follow every dotenv rule.
            raise Denied('invalid_compose', 'docker compose config rejected the file') from None
        found = policy.violations(after, self.deploy_root)
        if found:
            raise Denied('policy', found)
        if expect:
            self.expect_image(before, after, expect)
        diff = ''.join(difflib.unified_diff((current or b'').decode('utf-8', 'replace').splitlines(True),
                                            data.decode('utf-8', 'replace').splitlines(True),
                                            path.name + ' (current)', path.name + ' (new)'))
        return {'identity': identity, 'boundary': boundary, 'new': new, 'base': {'compose': sha(current), 'env': sha(env)},
                'compose': data.decode('utf-8'), 'env_set': dict(env_set or {}), 'env_unset': list(env_unset or []),
                'diff': diff, 'safe_diff': preview.diff(before, after), 'env': files.env_summary(env, new_env), 'expect': expect,
                'highlights': policy.new_highlights(before, after, identity['working_dir']),
                'services': sorted((after.get('services') or {}))}

    @staticmethod
    def expect_image(before, after, expect):
        service, image = expect['service'], expect['image']
        wanted = copy.deepcopy(before)
        if not wanted or service not in wanted.get('services', {}):
            raise Denied('unknown_service')
        wanted['services'][service]['image'] = image
        if canonical(wanted) != canonical(after):
            raise Denied('unexpected_change', 'the edit changed more than one image')

    def apply(self, plan, boundary=None):
        if not isinstance(plan, dict) or not isinstance(plan.get('compose'), str):
            raise Denied('invalid_plan')
        with self.lock:
            fresh = self.plan(plan['identity'], plan['compose'], plan.get('env_set'), plan.get('env_unset'),
                              bool(plan.get('new')), plan.get('expect'), boundary=boundary)
            if fresh['base'] != plan['base']:
                raise Denied('stale', 'project files changed since approval')
            return self.write_and_up(fresh)

    def write_and_up(self, plan):
        identity = plan['identity']
        wd = Path(identity['working_dir'])
        path, env_path = Path(identity['config_files'][0]), wd / '.env'
        if plan['new']:
            wd.mkdir()
            os.chmod(wd, 0o755)
            info = self.root.stat()
            os.chown(wd, info.st_uid, info.st_gid)
        old, old_env = files.read(path), files.read(env_path)
        if not plan['new'] and (sha(old), sha(old_env)) != (plan['base']['compose'], plan['base']['env']):
            raise Denied('stale', 'project files changed since approval')
        data = plan['compose'].encode()
        env = files.edit_env(old_env, plan['env_set'], plan['env_unset']) if (plan['env_set'] or plan['env_unset']) else old_env
        backups = []

        def restore():
            files.write_in_place(path, old)
            if old_env is None:
                files.remove(env_path)
            else:
                files.write_in_place(env_path, old_env)

        try:
            backups = [b for b in (files.backup(path, old) if data != old else None,
                                   files.backup(env_path, old_env) if env != old_env else None) if b]
            if data != old:
                files.write_in_place(path, data, like=wd, mode=0o644)
            if env != old_env:
                files.write_in_place(env_path, env, like=wd, mode=0o600)
            compose.compose(identity, 'up', '-d', '--no-build', '--remove-orphans')
            compose.wait_healthy(identity, self.health_timeout)
        except (Denied, OSError) as caught:
            exc = caught if isinstance(caught, Denied) else Denied('write_failed', type(caught).__name__)
            if not plan['new']:
                return self.recover(exc, restore, identity)
            # A new project has nothing to return to: stop it, keep its files for inspection.
            try:
                compose.run(compose.base(identity) + ['down', '--remove-orphans'], timeout=600, check=False)
            except Denied:
                pass
            return {'status': 'failed', 'error': exc.code, 'detail': exc.detail}
        return {'status': 'success', 'backups': backups}

    def update_image(self, identity, service, image, boundary=None):
        if not isinstance(image, str) or not PINNED.fullmatch(image) or not isinstance(service, str):
            raise Denied('invalid_argument', 'image')
        with self.lock:
            identity = self.identity(identity, change=True)
            raw = compose.render(identity, interpolate=False).get('services', {}).get(service, {}).get('image')
            current = compose.render(identity).get('services', {}).get(service, {}).get('image')
            if not raw or not current:
                raise Denied('unknown_service')
            if current == image:
                return {'status': 'no_change'}
            if repository(current) != repository(image):
                raise Denied('repository_mismatch', repository(current))
            self.space()
            data, env_set = files.image_edit(files.read(identity['config_files'][0]), raw, image)
            plan = self.plan(identity, data.decode(), env_set, None, expect={'service': service, 'image': image}, boundary=boundary)
            return self.write_and_up(plan)


    # Pull triggers ---------------------------------------------------------
    def fingerprint(self, identity):
        """The Compose files and .env as approved with a trigger."""
        return digest({'files': [sha(files.read(f)) for f in identity['config_files']],
                       'env': sha(files.read(Path(identity['working_dir']) / '.env'))})

    @staticmethod
    def follows(image, tag):
        if (not isinstance(image, str) or not IMAGE.fullmatch(image) or '@' in image
                or not isinstance(tag, str) or not TAG.fullmatch(tag)):
            raise Denied('invalid_argument', 'image')
        return repository(image), tag

    def tagged_services(self, identity, image, tag):
        """{service: image as written} for every service that runs image:tag."""
        wanted = self.follows(image, tag)
        services = compose.render(identity, env_resolution=False).get('services') or {}
        found = {name: s['image'] for name, s in sorted(services.items())
                 if isinstance(s.get('image'), str) and (repository(s['image']), image_tag(s['image'])) == wanted}
        if not found:
            raise Denied('unknown_service', f'no service runs {image}:{tag}')
        return found

    def trigger_scope(self, identity, image, tag):
        """What a pull trigger would update, for the approval page."""
        identity = self.identity(identity)
        return {'services': sorted(self.tagged_services(identity, image, tag)), 'files': self.fingerprint(identity),
                'violations': policy.violations(compose.render(identity), self.deploy_root)}

    def pull_image(self, identity, image, tag, digests, size=0, files=None, boundary=None):
        """Pull image:tag and recreate the services that run it, like Container Manager's update.

        The files are not edited. While they are byte-identical to the ones approved with the
        trigger, they are not re-checked (the owner saw the project when approving); once they
        change, they are checked like any other (re)creation. The pulled image must carry one of
        the digests the gateway verified, or the old image is restored and nothing is recreated."""
        self.follows(image, tag)
        if (not isinstance(digests, list) or not 1 <= len(digests) <= 2
                or any(not isinstance(d, str) or not DIGEST.fullmatch(d) for d in digests)
                or type(size) is not int or size < 0 or (files is not None and not isinstance(files, str))):
            raise Denied('invalid_argument', 'digests/size/files')
        with self.lock:
            identity = self.identity(identity)
            if files is None or files != self.fingerprint(identity):
                self.check_files(identity, boundary)
            services = self.tagged_services(identity, image, tag)
            previous = compose.image_ids(identity)
            if all(s in previous and compose.has_digest(previous[s][1], digests) for s in services):
                return {'status': 'no_change', 'services': sorted(services)}
            self.space(size)
            names = sorted(services)
            compose.compose(identity, 'pull', *names)

            def restore():
                for ref, image_id in previous.values():
                    compose.retag(ref, image_id)
            if not all(compose.has_digest(ref, digests) for ref in services.values()):
                restore()
                return {'status': 'failed', 'error': 'digest_mismatch',
                        'detail': 'the registry served an image other than the verified one'}
            try:
                # --pull never: what starts is the image just checked, even with pull_policy: always.
                compose.compose(identity, 'up', '-d', '--no-build', '--pull', 'never', *names)
                compose.wait_healthy(identity, self.health_timeout, names)
            except Denied as exc:
                return self.recover(exc, restore, identity, names)
            return {'status': 'success', 'services': names}


def handle(runner, request):
    op, args = request.get('op'), request.get('args') or {}
    table = {'projects': runner.projects, 'logs': runner.logs, 'read': runner.read,
             'lifecycle': runner.lifecycle, 'plan': runner.plan, 'apply': runner.apply,
             'down': runner.down, 'update_image': runner.update_image,
             'trigger_scope': runner.trigger_scope, 'pull_image': runner.pull_image,
             'authorize_boundary': runner.authorize_boundary, 'diagnose': runner.diagnose, 'exec': runner.exec}
    if op not in table or not isinstance(args, dict):
        raise Denied('unknown_operation')
    try:
        return table[op](**args)
    except TypeError:
        raise Denied('invalid_argument') from None


def serve(runner, path=SOCKET):
    if os.path.lexists(path):
        os.unlink(path)
    os.umask(0o077)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path)
        os.chmod(path, 0o600)
        server.listen(16)
        print('runner ready: ' + str(runner.root), flush=True)
        while True:
            connection, _ = server.accept()
            threading.Thread(target=session, args=(runner, connection), daemon=True).start()


def session(runner, connection):
    with connection:
        try:
            connection.settimeout(30)
            request = json.loads(read_line(connection))
            connection.settimeout(None)
            if request.get('op') == 'exec':
                args = request.get('args')
                if not isinstance(args, dict) or 'authorize' in args:
                    raise Denied('invalid_argument')
                binding = digest(request)
                def authorize():
                    challenge = secrets.token_urlsafe(24)
                    connection.settimeout(5)
                    connection.sendall(canonical({'phase': 'authorize_exec', 'challenge': challenge,
                                                   'binding': binding}).encode() + b'\n')
                    try:
                        decision = json.loads(read_line(connection, limit=4096))
                    except (OSError, ValueError):
                        raise Denied('not_authorized', 'authorization unavailable') from None
                    finally:
                        connection.settimeout(None)
                    if decision != {'phase': 'authorize_exec', 'challenge': challenge,
                                    'binding': binding, 'allow': True}:
                        raise Denied('not_authorized', 'invalid execution authorization')
                result = runner.exec(**args, authorize=authorize)
            else:
                result = handle(runner, request)
            reply = {'ok': True, 'result': result}
        except Denied as exc:
            reply = {'ok': False, 'error': exc.code, 'detail': exc.detail}
        except Exception as exc:  # Never crash the runner on one request.
            reply = {'ok': False, 'error': 'internal', 'detail': type(exc).__name__}
        try:
            connection.sendall(canonical(reply).encode() + b'\n')
        except OSError:
            pass


def main():
    root = os.environ.get('PROJECTS_ROOT')
    if not root:
        raise SystemExit('PROJECTS_ROOT is required')
    runner = Runner(root, os.environ.get('DEPLOY_ROOT', ''), int(os.environ.get('CD_HEALTH_TIMEOUT', '120')),
                    int(os.environ.get('CD_MIN_FREE_MB', '1024')))
    serve(runner)


if __name__ == '__main__':
    main()
