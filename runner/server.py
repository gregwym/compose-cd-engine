"""The only component with the Docker socket: fixed operations, no database.

Every call re-validates project identity, file hashes and the hard policy, so
the gateway decides *who* may act but never *what* is possible."""
import copy
import difflib
import json
import os
import re
import socket
import tempfile
import threading
from pathlib import Path
from runner import compose, files, policy
from shared.registry import repository
from shared.wire import Denied, canonical, digest, read_line

SOCKET = os.environ.get('CD_RUNNER_SOCKET', '/run/compose-cd/runner.sock')
ACTIONS = ('start', 'stop', 'restart', 'up', 'update')
PINNED = re.compile(r'[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}')


def sha(data):
    return None if data is None else digest(data)


class Runner:
    def __init__(self, projects_root, deploy_root='', health_timeout=120):
        self.root = Path(projects_root).resolve(strict=True)
        self.deploy_root = str(Path(deploy_root).resolve()) if deploy_root else ''
        self.health_timeout = health_timeout
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
            if os.path.lexists(wd) or observed:
                raise Denied('project_exists')
            if config != [wd.rstrip('/') + '/compose.yaml'] or Path(wd).parent.resolve() != self.root:
                raise Denied('invalid_identity')
            return identity
        if not Path(wd).is_dir() or Path(wd).is_symlink():
            raise Denied('project_missing')
        for item in config:
            if Path(item).is_symlink() or not Path(item).is_file():
                raise Denied('project_missing', Path(item).name)
        if observed and observed != identity:
            raise Denied('identity_changed', 'Container Manager project identity differs from the approved one')
        return identity

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
        return {'logs': {c['name']: compose.logs(c['id'], tail) for c in items[:8]}}

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

    def lifecycle(self, identity, action, services=None):
        if action not in ACTIONS:
            raise Denied('invalid_argument', 'action')
        services = self.services(services)
        with self.lock:
            identity = self.identity(identity)
            if action in ('start', 'stop', 'restart'):
                compose.compose(identity, action, *services, timeout=600)
                if action != 'stop':
                    compose.wait_healthy(identity, self.health_timeout, services)
                return {'status': 'success'}
            if action in ('up', 'update'):
                # Files may have changed since the grant; anything that (re)creates containers re-checks the policy.
                found = policy.violations(compose.render(identity), self.deploy_root)
                if found:
                    raise Denied('policy', found)
            if action == 'up':
                compose.compose(identity, 'up', '-d', '--no-build', *services)
                compose.wait_healthy(identity, self.health_timeout, services)
                return {'status': 'success'}
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

    def down(self, identity):
        with self.lock:
            identity = self.identity(identity)
            compose.compose(identity, 'down', '--remove-orphans', timeout=600)
            return {'status': 'success'}

    # Changes --------------------------------------------------------------
    def render(self, identity, data, env):
        with tempfile.TemporaryDirectory(prefix='cd-plan-') as tmp:
            path, env_path = Path(tmp) / 'compose.yaml', Path(tmp) / 'env'
            path.write_bytes(data)
            env_path.write_bytes(env or b'')
            return compose.render(identity, [path], env_path)

    def plan(self, identity, compose_text=None, env_set=None, env_unset=None, new=False, expect=None):
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
        before = None
        if current is not None:
            try:
                before = compose.render(identity)
            except Denied:
                before = None
        after = self.render(identity, data, new_env)
        found = policy.violations(after, self.deploy_root)
        if found:
            raise Denied('policy', found)
        if expect:
            self.expect_image(before, after, expect)
        diff = ''.join(difflib.unified_diff((current or b'').decode('utf-8', 'replace').splitlines(True),
                                            data.decode('utf-8', 'replace').splitlines(True),
                                            path.name + ' (current)', path.name + ' (new)'))
        return {'identity': identity, 'new': new, 'base': {'compose': sha(current), 'env': sha(env)},
                'compose': data.decode('utf-8'), 'env_set': dict(env_set or {}), 'env_unset': list(env_unset or []),
                'diff': diff, 'env': files.env_summary(env, new_env), 'expect': expect,
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

    def apply(self, plan):
        if not isinstance(plan, dict) or not isinstance(plan.get('compose'), str):
            raise Denied('invalid_plan')
        with self.lock:
            fresh = self.plan(plan['identity'], plan['compose'], plan.get('env_set'), plan.get('env_unset'),
                              bool(plan.get('new')), plan.get('expect'))
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

    def update_image(self, identity, service, image):
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
            data, env_set = files.image_edit(files.read(identity['config_files'][0]), raw, image)
            plan = self.plan(identity, data.decode(), env_set, None, expect={'service': service, 'image': image})
            return self.write_and_up(plan)


def handle(runner, request):
    op, args = request.get('op'), request.get('args') or {}
    table = {'projects': runner.projects, 'logs': runner.logs, 'read': runner.read,
             'lifecycle': runner.lifecycle, 'plan': runner.plan, 'apply': runner.apply,
             'down': runner.down, 'update_image': runner.update_image}
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
            reply = {'ok': True, 'result': handle(runner, request)}
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
    runner = Runner(root, os.environ.get('DEPLOY_ROOT', ''), int(os.environ.get('CD_HEALTH_TIMEOUT', '120')))
    serve(runner)


if __name__ == '__main__':
    main()
