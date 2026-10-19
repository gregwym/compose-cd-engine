"""Privileged local broker. Durable tasks; private state; no shell or YAML input."""
import fcntl
import json
import os
import socket
import sqlite3
import stat
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from deployer import schema
from management.protocol import read_frame, reserve_nonce, trusted_json

SOCKET = '/run/compose-cd-management/projects.sock'
ACTIVE = ('queued', 'running')


def protected_directory(path):
    path = Path(path)
    for item in [path, *path.parents]:
        st = item.lstat()
        schema.check(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022)
    return path


class Service:
    def __init__(self, policy_path, runner):
        self.policy_path = policy_path
        self.runner = runner
        self.cfg = schema.policy(trusted_json(policy_path))
        self.root = protected_directory(self.cfg['workspace'])
        schema.check(self.root.stat().st_mode & 0o077 == 0)
        for item in self.cfg['storage'].values():
            # Writable leaves are permitted, but only below protected parents.
            root = Path(item['path'])
            protected_directory(root.parent)
            st = root.lstat()
            schema.check(stat.S_ISDIR(st.st_mode) and not root.is_symlink())
            if not item['shared']:
                protected_directory(root)
        self.db_path = self.root / 'projects.sqlite'
        try:
            fd = os.open(str(self.db_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
        if self.db_path.exists():
            schema.check(not self.db_path.is_symlink() and self.db_path.stat().st_uid == self.root.stat().st_uid
                         and not self.db_path.stat().st_mode & 0o077)
        self.event = threading.Event()
        self.stopped = threading.Event()
        with self.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS plans (
                  id TEXT PRIMARY KEY, project TEXT, created INTEGER, policy TEXT,
                  base INTEGER, spec TEXT, task TEXT);
                CREATE TABLE IF NOT EXISTS projects (
                  id TEXT PRIMARY KEY, revision INTEGER, spec TEXT, recovery INTEGER);
                CREATE TABLE IF NOT EXISTS tasks (
                  id TEXT PRIMARY KEY, project TEXT, operation TEXT, state TEXT,
                  created INTEGER, updated INTEGER, spec TEXT, policy TEXT, base INTEGER);
            ''')
            # Crash reconciliation: never blindly replay an in-flight mutation.
            rows = db.execute("SELECT project FROM tasks WHERE state='running'").fetchall()
            for row in rows:
                db.execute('UPDATE projects SET recovery=1 WHERE id=?', row)
            db.execute("UPDATE tasks SET state='outcome_unknown', updated=? WHERE state='running'", (int(time.time()),))

    @contextmanager
    def db(self):
        db = sqlite3.connect(str(self.db_path), timeout=5)
        try:
            db.execute('PRAGMA busy_timeout=5000')
            with db:
                yield db
        finally:
            db.close()

    @contextmanager
    def lock(self, blocking=False):
        self.runner.STATE_DIR.mkdir(parents=True, exist_ok=True)
        with (self.runner.STATE_DIR / 'global.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            yield

    def policy(self, require_enabled=True):
        cfg = schema.policy(trusted_json(self.policy_path))
        # Workspace/storage changes need administrator restart and mount review.
        schema.check(cfg['workspace'] == self.cfg['workspace'] and cfg['storage'] == self.cfg['storage'])
        schema.check(not require_enabled or cfg['enabled'])
        return cfg

    def dispatch(self, value):
        value = schema.request(schema.canonical(value).encode())
        schema.check(abs(int(time.time()) - value['timestamp']) <= 60)
        reserve_nonce(value, str(self.root / 'nonces.sqlite'))
        project, op, payload = value['project'], value['operation'], value['payload']
        cfg = self.policy(require_enabled=op not in ('status', 'task', 'stop'))
        schema.check(op in cfg['operations'])
        # Reads need no global lock and remain available during long deployments.
        if op == 'task':
            with self.db() as db:
                row = db.execute('SELECT id, operation, state, created, updated FROM tasks WHERE id=? AND project=?',
                                 (payload['task_id'], project)).fetchone()
            schema.check(row is not None)
            return dict(zip(('task_id', 'operation', 'status', 'created', 'updated'), row))
        if op == 'status':
            return self.status(project)
        with self.lock():
            cfg = self.policy(require_enabled=op != 'stop')
            with self.db() as db:
                db.execute('BEGIN IMMEDIATE')
                current = db.execute('SELECT revision, spec, recovery FROM projects WHERE id=?', (project,)).fetchone()
                base = current[0] if current else 0
                busy = db.execute("SELECT id FROM tasks WHERE project=? AND state IN ('queued','running')", (project,)).fetchone()
                if op == 'plan':
                    schema.check(not busy)
                    compose, budget = schema.compile_project(project, payload, cfg)
                    self.capacity(db, project, payload, cfg)
                    if current:
                        # No implicit removal of services or their storage.
                        schema.check(set(payload['services']) == set(json.loads(current[1])['services']))
                    schema.check(db.execute('SELECT count(*) FROM plans').fetchone()[0] < 10000)
                    plan_id = uuid.uuid4().hex
                    db.execute('INSERT INTO plans VALUES (?,?,?,?,?,?,NULL)',
                               (plan_id, project, int(time.time()), schema.fingerprint(cfg), base, schema.canonical(payload)))
                    return {'status': 'planned', 'plan_id': plan_id, 'base_revision': base,
                            'expires_in': 3600, 'services': schema.preview(payload), 'budget': budget}
                if op == 'apply':
                    row = db.execute('SELECT created, policy, base, spec, task FROM plans WHERE id=? AND project=?',
                                     (payload['plan_id'], project)).fetchone()
                    schema.check(row is not None)
                    # A fresh authenticated request for the same plan returns its
                    # existing task, not another execution (including after failure).
                    if row[4]:
                        return {'status': 'accepted', 'task_id': row[4]}
                    schema.check(row[0] + 3600 >= time.time() and row[1] == schema.fingerprint(cfg)
                                 and row[2] == base and not busy and (not current or not current[2]))
                    spec = json.loads(row[3])
                    schema.compile_project(project, spec, cfg)
                    self.capacity(db, project, spec, cfg)
                    task = self.enqueue(db, project, 'apply', spec, cfg, base)
                    db.execute('UPDATE plans SET task=? WHERE id=?', (task, payload['plan_id']))
                    if not current:
                        # Reserve project/ports/resources before worker starts.
                        db.execute('INSERT INTO projects VALUES (?,0,?,0)', (project, row[3]))
                else:
                    schema.check(current is not None and not busy)
                    schema.check(op == 'stop' or not current[2])
                    spec = json.loads(current[1])
                    if op != 'stop':
                        schema.compile_project(project, spec, cfg)
                    task = self.enqueue(db, project, op, spec, cfg, base)
            self.event.set()
            return {'status': 'accepted', 'task_id': task}

    def capacity(self, db, project, spec, cfg):
        specs = {row[0]: json.loads(row[1]) for row in db.execute('SELECT id,spec FROM projects')}
        # A queued update reserves its new resources/ports as well.
        for row in db.execute("SELECT project,spec FROM tasks WHERE state IN ('queued','running')"):
            specs[row[0]] = json.loads(row[1])
        specs[project] = spec
        schema.check(len(specs) <= cfg['max_projects'])
        memory = cpus = 0
        ports = set()
        for key, item in specs.items():
            _, budget = schema.compile_project(key, item, cfg)
            memory += budget['memory_mb']
            cpus += budget['cpus']
            for port in budget['ports']:
                schema.check(tuple(port) not in ports)
                ports.add(tuple(port))
        schema.check(memory <= cfg['max_memory_mb'] and cpus <= cfg['max_cpus'])

    def enqueue(self, db, project, op, spec, cfg, base):
        schema.check(db.execute('SELECT count(*) FROM tasks').fetchone()[0] < 10000)
        task = uuid.uuid4().hex
        now = int(time.time())
        db.execute('INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?)',
                   (task, project, op, 'queued', now, now, schema.canonical(spec), schema.fingerprint(cfg), base))
        return task

    def compose(self, directory, project, *args, timeout=300, capture=False):
        # No inherited DOCKER_HOST/CONTEXT, COMPOSE_FILE, .env or plugin paths.
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/nonexistent',
               'DOCKER_HOST': 'unix:///var/run/docker.sock', 'COMPOSE_DISABLE_ENV_FILE': '1'}
        return subprocess.run([self.runner.DOCKER, 'compose', '--project-directory', str(directory),
                               '--env-file', '/dev/null', '-p', 'cdp-' + project,
                               '-f', str(directory / 'compose.json'), *args],
                              env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=timeout, check=True)

    def docker(self, *args):
        return subprocess.run([self.runner.DOCKER, '--host', 'unix:///var/run/docker.sock', *args],
                              env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/nonexistent'},
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=30, check=True).stdout

    def ready(self, project, services, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            healthy = True
            for service in services:
                ids = self.docker('ps', '--quiet', '--filter', 'label=com.docker.compose.project=cdp-' + project,
                                  '--filter', 'label=com.docker.compose.service=' + service).decode().split()
                if len(ids) != 1:
                    healthy = False
                    continue
                state = self.docker('inspect', '--format',
                    '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}', ids[0])
                healthy = healthy and state.strip() == b'running healthy'
            if healthy:
                return
            time.sleep(2)
        raise RuntimeError('readiness failed')

    def provision_storage(self, project, spec, cfg):
        # Open every parent without following symlinks. Only project/slot names
        # are caller-selected; an app-writable leaf is never traversed.
        for service in spec['services'].values():
            for mount in service.get('mounts', []):
                store = cfg['storage'][mount['storage']]
                root = Path(store['path'])
                protected_directory(root.parent)
                rootfd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    if store['shared']:
                        continue
                    st = os.fstat(rootfd)
                    schema.check(st.st_uid == 0 and not st.st_mode & 0o022)
                    try:
                        os.mkdir(project, mode=0o755, dir_fd=rootfd)
                    except FileExistsError:
                        pass
                    projectfd = os.open(project, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
                    try:
                        st = os.fstat(projectfd)
                        schema.check(st.st_uid == 0 and not st.st_mode & 0o022)
                        try:
                            os.mkdir(mount['slot'], mode=0o750, dir_fd=projectfd)
                            created = True
                        except FileExistsError:
                            created = False
                        if not created:
                            # Runner drops DAC_OVERRIDE: an app-owned 0750 leaf
                            # need not be readable by UID 0. Inspect only the
                            # entry below the protected parent, never its data.
                            st = os.stat(mount['slot'], dir_fd=projectfd, follow_symlinks=False)
                            schema.check(stat.S_ISDIR(st.st_mode) and st.st_uid == store['uid'])
                            continue
                        leaf = os.open(mount['slot'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=projectfd)
                        try:
                            os.fchown(leaf, store['uid'], store['gid'])
                        finally:
                            os.close(leaf)
                    finally:
                        os.close(projectfd)
                finally:
                    os.close(rootfd)

    def working_directory(self, task, compose):
        directory = self.root / task
        directory.mkdir(mode=0o700)
        # Private atomic replacement supplied by the existing runner helper.
        self.runner.write_json(directory / 'compose.json', compose)
        return directory

    def status(self, project):
        with self.db() as db:
            row = db.execute('SELECT revision,spec,recovery FROM projects WHERE id=?', (project,)).fetchone()
            last = db.execute('SELECT id,state,operation FROM tasks WHERE project=? ORDER BY rowid DESC LIMIT 1', (project,)).fetchone()
        schema.check(row is not None)
        # Only known service names and enumerated states cross the API.
        names = set(json.loads(row[1])['services'])
        data = self.docker('ps', '--all', '--filter', 'label=com.docker.compose.project=cdp-' + project,
                           '--format', '{{.Label "com.docker.compose.service"}} {{.State}}')
        states = {name: 'absent' for name in names}
        for line in data.decode().splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in names and parts[1] in ('created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead'):
                states[parts[0]] = parts[1]
        return {'status': 'success', 'revision': row[0], 'recovery_required': bool(row[2]),
                'services': states, 'last_task': dict(zip(('task_id', 'status', 'operation'), last)) if last else None}

    def run_one(self):
        with self.lock(blocking=True):
            with self.db() as db:
                row = db.execute("SELECT id,project,operation,spec,policy,base FROM tasks WHERE state='queued' ORDER BY rowid LIMIT 1").fetchone()
                if not row:
                    return False
                task, project, op, spec_json, policy_hash, base = row
                db.execute("UPDATE tasks SET state='running',updated=? WHERE id=?", (int(time.time()), task))
            mutated = False
            try:
                cfg = self.policy(require_enabled=op != 'stop')
                schema.check(schema.fingerprint(cfg) == policy_hash and op in cfg['operations'])
                spec = json.loads(spec_json)
                with self.db() as db:
                    current = db.execute('SELECT revision,recovery FROM projects WHERE id=?', (project,)).fetchone()
                    schema.check(current is not None and current[0] == base and (op == 'stop' or not current[1]))
                    if op != 'stop':
                        # Earlier queued updates can fail, leaving larger old
                        # resource/port reservations than assumed at enqueue.
                        self.capacity(db, project, spec, cfg)
                if op == 'stop':
                    ids = self.docker('ps', '--all', '--quiet', '--no-trunc', '--filter',
                                      'label=com.docker.compose.project=cdp-' + project).decode().split()
                    import re
                    schema.check(all(re.fullmatch('[a-f0-9]{64}', x) for x in ids))
                    if ids:
                        self.docker('stop', '--time', '10', *ids)
                    with self.db() as db:
                        db.execute("UPDATE tasks SET state='success',updated=? WHERE id=?", (int(time.time()), task))
                    return True
                compose, _ = schema.compile_project(project, spec, cfg)
                if base == 0 and op == 'apply':
                    for args in [('ps', '--all', '--quiet'), ('network', 'ls', '--quiet')]:
                        schema.check(not self.docker(*args, '--filter', 'label=com.docker.compose.project=cdp-' + project).strip())
                self.provision_storage(project, spec, cfg)
                directory = self.working_directory(task, compose)
                # Only generated JSON is ever parsed by Compose. No caller file
                # references, extensions, interpolation, hooks or provider plugin.
                self.compose(directory, project, 'config', '--quiet', timeout=30)
                if op == 'apply':
                    self.compose(directory, project, 'pull', timeout=600)
                if op != 'stop':
                    # A crash after recreation might leave migrated data. Latch
                    # BEFORE invoking Docker, never automatically restore data.
                    with self.db() as db:
                        db.execute('UPDATE projects SET recovery=1 WHERE id=?', (project,))
                mutated = True
                if op == 'apply':
                    self.compose(directory, project, 'up', '-d', '--no-build', '--pull', 'never',
                                 '--wait', '--wait-timeout', str(cfg['health_timeout']),
                                 timeout=cfg['health_timeout'] + 120)
                else:
                    args = [op] + (['--no-deps'] if op == 'restart' else []) + sorted(spec['services'])
                    self.compose(directory, project, *args, timeout=120)
                    if op != 'stop':
                        # Compose wait is exit-oriented, so use the same proven
                        # fixed readiness checker as deployment for lifecycle.
                        self.ready(project, sorted(spec['services']), cfg['health_timeout'])
                with self.db() as db:
                    if op == 'apply':
                        db.execute('UPDATE projects SET revision=revision+1,spec=?,recovery=0 WHERE id=?', (spec_json, project))
                    elif op != 'stop':
                        db.execute('UPDATE projects SET recovery=0 WHERE id=?', (project,))
                    db.execute("UPDATE tasks SET state='success',updated=? WHERE id=?", (int(time.time()), task))
            except Exception:
                with self.db() as db:
                    db.execute('UPDATE tasks SET state=?,updated=? WHERE id=?',
                               ('recovery_required' if mutated and op != 'stop' else 'failed', int(time.time()), task))
                # Deliberately no traceback, host paths, environment or Docker output.
            return True

    def worker(self):
        while not self.stopped.is_set():
            self.event.clear()
            try:
                while self.run_one():
                    if self.stopped.is_set():
                        return
            except Exception:
                pass
            self.event.wait(2)

    def serve(self):
        path = Path(SOCKET)
        if path.exists():
            schema.check(path.is_socket())
            path.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            os.chown(path, 0, int(os.environ.get('CD_MANAGEMENT_GID', '30003')))
            os.chmod(path, 0o660)
            server.listen(4)
            threading.Thread(target=self.worker, daemon=True).start()
            while True:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(5)
                    try:
                        value = schema.request(read_frame(connection, schema.MAX_REQUEST))
                        result = self.dispatch(value)
                    except BlockingIOError:
                        result = {'status': 'busy'}
                    except Exception:
                        result = {'status': 'denied_or_failed'}
                    try:
                        data = schema.canonical(result).encode()
                        if len(data) > 65536:
                            data = b'{"status":"response_too_large"}'
                        connection.sendall(data + b'\n')
                    except OSError:
                        pass
