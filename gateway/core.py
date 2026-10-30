"""Who may do what: agent operations, owner approvals, jobs and triggers."""
import re
import json
import socket
import secrets
import threading
import time
from gateway import tailscale, triggers
from gateway.agents import fingerprint
from gateway.store import now
from shared import wire
from shared.registry import repository
from shared.wire import Denied

READ = ('projects', 'logs')
OPERATE = ('start', 'stop', 'restart', 'up', 'update')
KINDS = ('read', 'manage', 'elevated', 'operate', 'change', 'create', 'down', 'serve', 'unserve', 'trigger')
NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,62}')
TRIGGER_INTERVAL = 1800


def arg(args, key, kind, default=None, required=True):
    value = args.get(key, default)
    if value is None and not required:
        return None
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise Denied('invalid_argument', key)
    return value


class Gateway:
    def __init__(self, store, runner_socket, origin, host, funnel=False, apply_serve=tailscale.apply_serve):
        self.store, self.runner_socket = store, runner_socket
        self.origin, self.host, self.funnel = origin, host, funnel
        self.apply_serve = apply_serve
        self.wake = threading.Event()
        self.serve_lock = threading.Lock()
        self.threads = []

    def runner(self, op, **args):
        return wire.call(self.runner_socket, op, args)

    # Agent API ------------------------------------------------------------
    def agent(self, value):
        op, args, agent = value['op'], value['args'], value['agent']
        if op == 'pair':
            return self.pair(agent, value['public_key'], args)
        self.store.active_agent(agent, value['public_key'])
        if op == 'whoami':
            return {'agent': agent, 'grants': [{k: g[k] for k in ('id', 'project', 'scope', 'boundary', 'expires')}
                                               for g in self.store.grants(agent)]}
        if op == 'projects':
            self.require_read(agent)
            return self.projects(agent)
        if op == 'diagnose':
            self.require_read(agent)
            return self.runner('diagnose', project=arg(args, 'project', str))
        if op == 'exec':
            return self.execute_argv(agent, args)
        if op == 'logs':
            self.require_read(agent)
            return self.runner('logs', project=arg(args, 'project', str), service=arg(args, 'service', str, required=False),
                               tail=arg(args, 'tail', int, 100))
        if op == 'read':
            project = arg(args, 'project', str)
            # A global diagnostic grant must not shadow an existing project read right.
            grant = self.store.grant(agent, project)
            if grant:
                return self.runner('read', identity=grant['identity'])
            self.require_read(agent)
            return self.runner('diagnose', project=project)
        if op in OPERATE:
            grant = self.require_grant(agent, arg(args, 'project', str))
            services = arg(args, 'services', list, [])
            return {'job': self.job(agent, grant['project'], op,
                                    lambda: self.granted_runner(agent, grant, 'lifecycle', action=op, services=services))}
        if op == 'request':
            return self.request(agent, args)
        if op == 'request_status':
            item = self.store.request(arg(args, 'id', str))
            if not item or item['agent'] != agent:
                raise Denied('not_found')
            return self.public(item, owner=False)
        if op == 'job':
            job = self.store.job(arg(args, 'id', str))
            if not job or job['actor'] != agent:
                raise Denied('not_found')
            return {k: job[k] for k in ('id', 'project', 'op', 'status', 'result', 'created', 'updated')}
        raise Denied('unknown_operation')

    def pair(self, agent, public_key, args):
        label = arg(args, 'label', str)
        if not 1 <= len(label) <= 60 or not label.isprintable():
            raise Denied('invalid_argument', 'label')
        row = self.store.pair(agent, public_key, label)
        if row['public_key'] != public_key:
            raise Denied('not_paired')
        if row['status'] == 'active':
            return {'status': 'paired', 'agent': agent}
        return {'status': 'pending', 'agent': agent, 'fingerprint': fingerprint(public_key),
                'approval_url': f"{self.origin}/p/{row['token']}", 'expires': row['expires']}

    def require_read(self, agent):
        grant = self.store.grant(agent, '*', 'read')
        if not grant:
            raise Denied('not_authorized', 'request kind=read first')
        return grant

    def current_grant(self, agent, grant):
        row = self.store.agent(agent)
        current = self.store.grant(agent, grant['project'], grant['scope'])
        if not row or row['status'] != 'active' or not current or current['id'] != grant['id']:
            raise Denied('not_authorized', 'grant expired, replaced or revoked')
        return current

    def granted_runner(self, agent, grant, op, **args):
        current = self.current_grant(agent, grant)
        if current['scope'] == 'manage':
            args['boundary'] = current['boundary']
        if op != 'apply':
            args['identity'] = current['identity']
        return self.runner(op, **args)

    def execute_argv(self, agent, args):
        project = arg(args, 'project', str)
        manage = self.store.grant(agent, project, 'manage')
        elevated = self.store.grant(agent, project, 'elevated')
        if not manage or not elevated or elevated['boundary'].get('manage_grant') != manage['id']:
            raise Denied('not_authorized', 'active manage and finite elevated grants required')
        argv, container = arg(args, 'argv', list), arg(args, 'container', str)
        timeout = arg(args, 'timeout', int, 30)
        if (not 1 <= len(argv) <= 64 or any(not isinstance(a, str) or not a or '\x00' in a or len(a) > 4096 for a in argv)
                or sum(map(len, argv)) > 16384 or argv[0].startswith('-') or not 1 <= timeout <= 120
                or not re.fullmatch(r'[a-f0-9]{64}', container)):
            raise Denied('invalid_argument', 'argv/container/timeout')
        def work():
            self.current_grant(agent, elevated)
            self.current_grant(agent, manage)
            return self.runner_exec(agent, manage, elevated, {
                'identity': manage['identity'], 'boundary': manage['boundary'], 'container': container,
                'argv': argv, 'timeout': timeout, 'expires': elevated['expires']})
        return {'job': self.job(agent, project, 'exec', work)}

    def runner_exec(self, agent, manage, elevated, args):
        """Reauthorize on the original socket after runner obtains its execution lock.

        The challenge binds the entire immutable operation. No additional server,
        network endpoint, runner database access or persistent ticket is needed.
        """
        request = {'op': 'exec', 'args': args}
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(1800)
                sock.connect(self.runner_socket)
                sock.sendall(wire.canonical(request).encode() + b'\n')
                ready = json.loads(wire.read_line(sock))
                if ready.get('phase') != 'authorize_exec':
                    if not ready.get('ok'):
                        raise Denied(ready.get('error', 'failed'), ready.get('detail'))
                    raise Denied('runner_protocol', 'execution authorization handshake required')
                if ready.get('binding') != wire.digest(request) or not isinstance(ready.get('challenge'), str):
                    raise Denied('runner_protocol')
                # This is deliberately AFTER readiness, not merely before dispatch.
                # One transaction gives agent + both grants a single authorization point.
                with self.store.db() as db:
                    active = db.execute("SELECT 1 FROM agents WHERE id=? AND status='active'", (agent,)).fetchone()
                    grants = db.execute("SELECT id FROM grants WHERE id IN (?,?) AND agent=? AND status='active' "
                                        "AND (expires IS NULL OR expires>?)",
                                        (manage['id'], elevated['id'], agent, now())).fetchall()
                    if not active or {g['id'] for g in grants} != {manage['id'], elevated['id']}:
                        raise Denied('not_authorized', 'grant expired, replaced or revoked')
                sock.sendall(wire.canonical({'phase': 'authorize_exec', 'challenge': ready['challenge'],
                                            'binding': ready['binding'], 'allow': True}).encode() + b'\n')
                reply = json.loads(wire.read_line(sock))
        except (OSError, ValueError) as exc:
            raise Denied('runner_unavailable', type(exc).__name__) from None
        if not reply.get('ok'):
            raise Denied(reply.get('error', 'failed'), reply.get('detail'))
        return reply['result']

    def require_grant(self, agent, project):
        grant = self.store.grant(agent, project)
        if not grant:
            raise Denied('not_authorized', 'request kind=operate for this project first')
        return grant

    def projects(self, agent=None):
        listing = self.runner('projects')
        grants = {g['project']: g['expires'] for g in self.store.grants(agent)} if agent else {}
        dash = self.store.dashboard()
        for item in listing['projects']:
            item['operate_until'] = grants.get(item['project'])
            item['routes'] = [r['https_port'] for r in dash['routes'] if r['project'] == item['project']]
            item['triggers'] = [t['service'] for t in dash['triggers']
                                if t['project'] == item['project'] and t['status'] == 'active']
        return listing

    def identity(self, agent, project, manageable=True):
        grant = self.store.grant(agent, project)
        if grant:
            return grant['identity']
        for item in self.runner('projects')['projects']:
            if item['project'] == project:
                if manageable and not item['manageable']:
                    raise Denied('not_manageable', item['reason'])
                return item['identity']
        raise Denied('not_found')

    # Requests -------------------------------------------------------------
    def request(self, agent, args):
        kind = arg(args, 'kind', str)
        if kind not in KINDS:
            raise Denied('invalid_argument', 'kind')
        project = arg(args, 'project', str, '*' if kind == 'read' else ('' if kind == 'unserve' else None))
        manage = self.store.grant(agent, project, 'manage')
        if manage and kind in ('change', 'create', 'down'):
            return self.managed_change(agent, manage, kind, args)
        if kind == 'read':
            if project != '*':
                raise Denied('invalid_argument', 'read scope is environment-wide (*)')
            detail = {'identity': {}, 'lifetime': self.reusable_lifetime(args), 'scope': 'read', 'boundary': {}}
        elif kind == 'manage':
            identity = self.identity(agent, project) if not args.get('new') else self.new_identity(project)
            # The runner adds what the current files (and an optional proposed compose.yaml) need, so the
            # owner approves the project's whole boundary once instead of one feature at a time.
            boundary = self.runner('authorize_boundary', identity=identity, boundary=arg(args, 'boundary', dict, {}),
                                   new=bool(args.get('new')), compose_text=arg(args, 'compose', str, required=False))
            unverified = boundary.pop('unverified', [])  # outside the runner's view: symlinks not checked
            detail = {'identity': identity, 'lifetime': self.reusable_lifetime(args), 'scope': 'manage',
                      'boundary': boundary, 'unverified': unverified, 'new': bool(args.get('new'))}
        elif kind == 'elevated':
            if not manage:
                raise Denied('not_authorized', 'manage grant required first')
            seconds = arg(args, 'seconds', int, 900)
            if not 1 <= seconds <= 3600:
                raise Denied('invalid_argument', 'seconds must be 1..3600')
            detail = {'identity': manage['identity'], 'lifetime': seconds, 'scope': 'elevated',
                      'boundary': {'manage_grant': manage['id']}}
        elif kind == 'operate':
            detail = {'identity': self.identity(agent, project), 'lifetime': self.lifetime(args)}
        elif kind == 'change':
            detail = {'plan': self.runner('plan', identity=self.identity(agent, project),
                                          compose_text=arg(args, 'compose', str, required=False),
                                          env_set=self.env_set(args), env_unset=arg(args, 'env_unset', list, [])),
                      'compose_supplied': args.get('compose') is not None}
        elif kind == 'create':
            if not NAME.fullmatch(project):
                raise Denied('invalid_argument', 'project')
            root = self.runner('projects')['root']
            wd = f'{root}/{project}'
            identity = {'project': project, 'working_dir': wd, 'config_files': [wd + '/compose.yaml']}
            detail = {'plan': self.runner('plan', identity=identity, compose_text=arg(args, 'compose', str),
                                          env_set=self.env_set(args), env_unset=[], new=True),
                      'lifetime': self.lifetime(args)}
        elif kind == 'down':
            detail = {'identity': self.identity(agent, project)}
        elif kind == 'serve':
            detail = self.serve_detail(agent, project, args)
        elif kind == 'unserve':
            port = arg(args, 'https_port', int)
            route = next((r for r in self.store.dashboard()['routes'] if r['https_port'] == port), None)
            if not route:
                raise Denied('not_found')
            project, detail = route['project'], {'https_port': port}
        else:
            detail = self.trigger_detail(agent, project, args)
        rid = self.store.create_request(agent, project, kind, detail)
        return self.public(self.store.request(rid), owner=False)

    def new_identity(self, project):
        if not NAME.fullmatch(project):
            raise Denied('invalid_argument', 'project')
        root = self.runner('projects')['root']
        wd = f'{root}/{project}'
        return {'project': project, 'working_dir': wd, 'config_files': [wd + '/compose.yaml']}

    def managed_change(self, agent, grant, kind, args):
        self.current_grant(agent, grant)
        if kind == 'down':
            return {'job': self.job(agent, grant['project'], kind,
                                    lambda: self.granted_runner(agent, grant, 'down'))}
        plan = self.runner('plan', identity=grant['identity'], boundary=grant['boundary'],
                           compose_text=arg(args, 'compose', str, required=kind == 'create'),
                           env_set=self.env_set(args), env_unset=arg(args, 'env_unset', list, []), new=kind == 'create')
        return {'job': self.job(agent, grant['project'], kind,
                                lambda: self.granted_runner(agent, grant, 'apply', plan=plan))}

    @staticmethod
    def reusable_lifetime(args):
        if args.get('permanent') is True:
            return None
        return Gateway.lifetime(args)

    @staticmethod
    def lifetime(args):
        days = arg(args, 'days', int, 7)
        if not 1 <= days <= 30:
            raise Denied('invalid_argument', 'days')
        return days * 86400

    @staticmethod
    def env_set(args):
        values = arg(args, 'env_set', dict, {})
        if any(not isinstance(v, str) for v in values.values()):
            raise Denied('invalid_argument', 'env_set')
        return values

    def serve_detail(self, agent, project, args):
        target, https = arg(args, 'target_port', int), arg(args, 'https_port', int)
        if not 1 <= https <= 65535 or https in tailscale.RESERVED:
            raise Denied('invalid_argument', 'https_port')
        if any(r['https_port'] == https for r in self.store.dashboard()['routes']):
            raise Denied('port_in_use')
        listed = next((p for p in self.runner('projects')['projects'] if p['project'] == project), None)
        if not listed:
            raise Denied('not_found')
        published = {p['host_port'] for s in listed['services'] for p in s['ports']
                     if p['host_ip'] in ('0.0.0.0', '::', '')}
        if target not in published:
            raise Denied('port_not_published', sorted(published))
        return {'project': project, 'https_port': https, 'target_port': target,
                'url': f'https://{self.host}:{https}/'}

    def trigger_detail(self, agent, project, args):
        identity = self.identity(agent, project)
        manage = self.store.grant(agent, project, 'manage')
        service = arg(args, 'service', str)
        config = triggers.validate({k: args[k] for k in ('repository', 'workflow', 'branch', 'image', 'platform') if k in args})
        listed = next((p for p in self.runner('projects')['projects'] if p['project'] == project), None)
        current = next((s['image'] for s in (listed or {}).get('services', []) if s['service'] == service), None)
        if current is None:
            raise Denied('unknown_service')
        if repository(current) != repository(config['image']):
            raise Denied('repository_mismatch', repository(current))
        return {'identity': identity, 'service': service, 'config': config,
                'signer': triggers.identity(config),
                **({'manage_grant': manage['id'], 'agent': agent} if manage else {})}

    def public_preview(self, item):
        # Capability URL exposes only an allowlisted, value-free review projection.
        detail = item['detail']
        safe = {k: detail[k] for k in ('identity', 'lifetime', 'scope', 'boundary', 'unverified', 'new', 'service', 'signer', 'config', 'url', 'target_port', 'https_port') if k in detail}
        if 'plan' in detail:
            plan = detail['plan']
            safe['plan'] = {'identity': plan['identity'], 'new': plan.get('new', False),
                            'diff': plan.get('safe_diff', 'Legacy preview withheld; submit a new request.'),
                            'highlights': [], 'env': plan.get('env', {}), 'services': plan.get('services', []),
                            'redacted': 'safe_diff' not in plan}
        return {**{k: item[k] for k in ('id', 'kind', 'project', 'agent', 'status', 'created', 'expires')},
                'detail': safe, 'outcome': None, 'approval_url': f"{self.origin}/r/{item['id']}"}

    def public(self, item, owner):
        detail = dict(item['detail'])
        if 'plan' in detail:
            plan = dict(detail['plan'])
            plan['env_set'] = sorted(plan.get('env_set') or {})  # values never leave the gateway
            if not owner:
                # The diff and the rendered risk list embed current file content and interpolated
                # .env values; agents without `read` must not get them before the owner approves.
                for key in ('diff', 'highlights'):
                    plan.pop(key, None)
                if detail.get('compose_supplied') is False:
                    plan.pop('compose', None)  # an .env-only change would echo the current Compose file
                plan['redacted'] = True
            detail['plan'] = plan
        return {'id': item['id'], 'kind': item['kind'], 'project': item['project'], 'agent': item['agent'],
                'status': item['status'], 'created': item['created'], 'expires': item['expires'],
                'detail': detail, 'outcome': item['outcome'], 'approval_url': f"{self.origin}/r/{item['id']}"}

    # Approved decisions ---------------------------------------------------
    def execute(self, rid):
        item = self.store.request(rid)
        if not item or item['status'] != 'approved' or item['outcome']:
            return
        try:
            self.store.finish_request(rid, self.perform(item))
        except Exception as exc:  # the approval stands; record why nothing happened
            self.store.finish_request(rid, {'error': getattr(exc, 'code', type(exc).__name__)})

    def perform(self, item):
        rid, kind, detail = item['id'], item['kind'], item['detail']
        agent, project = item['agent'], item['project']
        outcome = {}
        if kind in ('read', 'manage', 'elevated'):
            if kind == 'elevated':
                current = self.store.grant(agent, project, 'manage')
                if not current or current['id'] != detail['boundary']['manage_grant']:
                    raise Denied('not_authorized', 'manage grant changed')
            if kind == 'manage':
                self.runner('authorize_boundary', identity=detail['identity'], boundary=detail['boundary'],
                            new=detail.get('new', False), derive=False)
            with self.store.db() as db:
                outcome['grant'] = self.store.add_grant(db, agent, project, detail['identity'], detail['lifetime'], rid,
                                                       scope=kind, boundary=detail['boundary'])
        if kind in ('operate', 'create'):
            identity = detail['identity'] if kind == 'operate' else detail['plan']['identity']
            with self.store.db() as db:
                outcome['grant'] = self.store.add_grant(db, agent, project, identity, detail['lifetime'], rid)
        if kind in ('change', 'create'):
            outcome['job'] = self.job(agent, project, kind, lambda: self.runner('apply', plan=detail['plan']))
        elif kind == 'down':
            outcome['job'] = self.job(agent, project, 'down', lambda: self.runner('down', identity=detail['identity']))
        elif kind == 'serve':
            with self.store.db() as db:
                db.execute('INSERT INTO routes VALUES (?,?,?,?,?)',
                           (detail['https_port'], project, detail['target_port'], rid, now()))
            outcome['url'] = detail['url']
        elif kind == 'unserve':
            with self.store.db() as db:
                db.execute('DELETE FROM routes WHERE https_port=?', (detail['https_port'],))
        elif kind == 'trigger':
            tid = secrets.token_hex(8)
            with self.store.db() as db:
                db.execute("UPDATE triggers SET status='replaced' WHERE project=? AND service=? AND status='active'",
                           (project, detail['service']))
                db.execute('INSERT INTO triggers VALUES (?,?,?,?,?,?,?,?,?,?)',
                           (tid, project, detail['service'], wire.canonical({**detail['config'], **({'manage_grant': detail['manage_grant'], 'agent': agent} if detail.get('manage_grant') else {})}),
                            wire.canonical(detail['identity']), secrets.token_urlsafe(32), None, 'active', rid, now()))
            outcome['trigger'] = tid
            self.wake.set()
        if kind in ('serve', 'unserve', 'trigger'):
            outcome['serve'] = self.sync_serve()
        return outcome

    def job(self, actor, project, op, work):
        jid = self.store.create_job(actor, project, op)

        def run():
            self.store.update_job(jid, 'running')
            try:
                result = work()
                status = result.get('status', 'success') if isinstance(result, dict) else 'success'
            except Denied as exc:
                result = {'error': exc.code, 'detail': exc.detail}
                status = 'stale' if exc.code == 'stale' else 'failed'
            except Exception as exc:
                result, status = {'error': 'internal', 'detail': type(exc).__name__}, 'failed'
            self.store.update_job(jid, status, result)
        thread = threading.Thread(target=run, daemon=True)
        self.threads.append(thread)
        thread.start()
        return jid

    # Tailscale Serve ------------------------------------------------------
    def sync_serve(self):
        # One snapshot-to-apply critical section, so a stale snapshot never overwrites a newer one.
        with self.serve_lock:
            dash = self.store.dashboard()
            funnel = self.funnel and any(t['status'] == 'active' for t in dash['triggers'])
            for attempt in ([funnel, False] if funnel else [False]):
                try:
                    self.apply_serve(tailscale.serve_config(self.host, dash['routes'], attempt))
                    return 'applied' if attempt == funnel else 'applied_without_funnel'
                except (OSError, ValueError) as exc:
                    print(f'Tailscale Serve configuration failed (funnel={attempt}): {exc}', flush=True)
            return 'failed'

    # Triggers -------------------------------------------------------------
    def webhook(self, tid, body, signature, event):
        with self.store.db() as db:
            row = db.execute("SELECT * FROM triggers WHERE id=? AND status='active'", (tid,)).fetchone()
        if not row:
            raise Denied('not_found')
        if triggers.webhook(body, signature, event, row['secret'], self.store.decode(row)['config']):
            self.store.nonce('hook:' + tid + ':' + wire.digest(body), ttl=7 * 86400)
            self.wake.set()
            return True
        return False

    def check_triggers(self, force=False):
        with self.store.db() as db:
            rows = [self.store.decode(r) for r in db.execute("SELECT * FROM triggers WHERE status='active'").fetchall()]
        for row in rows:
            last = row['last'] or {}
            if not force and last.get('checked', 0) + TRIGGER_INTERVAL > now():
                continue
            state = {**last, 'checked': now(), 'error': None}
            try:
                manage = None
                if row['config'].get('manage_grant'):
                    manage = self.store.grant(row['config']['agent'], row['project'], 'manage')
                    if not manage or manage['id'] != row['config']['manage_grant']:
                        raise Denied('not_authorized')
                    self.current_grant(row['config']['agent'], manage)
                commit, image = triggers.latest(row['config'])
                state['commit'] = commit
                if image != last.get('image'):
                    jid = self.store.create_job('trigger:' + row['id'], row['project'], 'update_image')
                    self.store.update_job(jid, 'running')
                    try:
                        result = (self.granted_runner(row['config']['agent'], manage, 'update_image', service=row['service'], image=image)
                                  if manage else self.runner('update_image', identity=row['identity'], service=row['service'], image=image))
                        self.store.update_job(jid, result.get('status', 'success'), result)
                        if result.get('status') in ('success', 'no_change'):
                            state['image'] = image
                        else:
                            state['error'] = result.get('error')
                    except Denied as exc:
                        self.store.update_job(jid, 'stale' if exc.code == 'stale' else 'failed',
                                              {'error': exc.code, 'detail': exc.detail})
                        raise
            except Denied as exc:
                state['error'] = exc.code
            except (OSError, ValueError, KeyError) as exc:
                state['error'] = type(exc).__name__
            with self.store.db() as db:
                db.execute('UPDATE triggers SET last=? WHERE id=?', (wire.canonical(state), row['id']))

    def trigger_loop(self):
        while True:
            woke = self.wake.wait(60)
            self.wake.clear()
            try:
                self.check_triggers(force=woke)
            except Exception as exc:  # keep polling after unexpected errors
                print('trigger check failed: ' + type(exc).__name__, flush=True)
            time.sleep(1)
