#!/usr/bin/env python3
"""Resumable v2 agent client; emits bounded JSON events for OpenClaw/Telegram."""
import argparse
import json
import os
import ssl
import sys
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from authorization.protocol import ROUTES, request as validate
from authorization.rpc import signature
from deployer import schema


class Client:
    def __init__(self, endpoint, agent, project, key):
        url = urlsplit(endpoint)
        schema.check(url.scheme == 'https' and url.hostname and url.path in ('', '/')
                     and not url.username and not url.password and not url.query and not url.fragment)
        schema.name(agent); schema.name(project)
        schema.check(len(key) >= 32)
        self.endpoint, self.agent, self.project, self.key = endpoint.rstrip('/'), agent, project, key
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def call(self, operation, payload=None):
        value = {'version': 2, 'agent': self.agent, 'project': self.project, 'operation': operation,
                 'request_id': uuid.uuid4().hex, 'timestamp': int(time.time()), 'payload': payload or {}}
        raw = schema.canonical(value).encode()
        validate(raw)
        route = next(path for path, op in ROUTES.items() if op == operation)
        request = urllib.request.Request(self.endpoint + route, raw,
            {'Content-Type': 'application/json', 'X-Management-Signature': signature(raw, self.key)}, method='POST')
        with self.opener.open(request, timeout=15) as response:
            data = response.read(65537)
            schema.check(len(data) <= 65536)
            result = json.loads(data)
            schema.check(isinstance(result, dict))
            return result


def private(path, limit):
    path = Path(path)
    st = path.lstat()
    schema.check(path.is_file() and not path.is_symlink() and st.st_uid == os.geteuid()
                 and not st.st_mode & 0o077 and st.st_size <= limit)
    return path.read_bytes()


class Workflow:
    """Disk state contains IDs/hashes, never spec values or credentials.

    Network retries are only reads and immutable, idempotent plan→request/apply.
    Unknown lifecycle actions are deliberately not retried.
    """
    def __init__(self, client, state, spec=None, mode='persistent', lifetime=86400, emit=None):
        self.client, self.path, self.spec = client, Path(state), spec
        self.emit = emit or (lambda event: print(schema.canonical(event), flush=True))
        self.identity = {'endpoint': client.endpoint, 'agent': client.agent, 'project': client.project}
        st = self.path.parent.lstat()
        schema.check(self.path.parent.is_dir() and not self.path.parent.is_symlink()
                     and st.st_uid == os.geteuid() and not st.st_mode & 0o077)
        if self.path.exists() or self.path.is_symlink():
            self.state = json.loads(private(self.path, 4096))
            schema.check(self.state['identity'] == self.identity)
            if spec is not None:
                schema.check(self.state['spec_hash'] == schema.fingerprint(spec))
        else:
            schema.check(spec is not None)
            self.state = {'identity': self.identity, 'spec_hash': schema.fingerprint(spec),
                          'mode': mode, 'lifetime': lifetime, 'phase': 'plan'}
            self.save()

    def save(self):
        # Same-directory O_EXCL temporary; no symlink-following or public file.
        tmp = self.path.with_name('.' + uuid.uuid4().hex + '.next')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(schema.canonical(self.state))
                stream.flush(); os.fsync(stream.fileno())
            os.replace(tmp, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if tmp.exists():
                tmp.unlink()

    def step(self):
        phase = self.state['phase']
        if phase == 'done':
            return {'status': self.state['result'], 'task_id': self.state['task_id']}
        if phase == 'plan':
            schema.check(self.spec is not None)
            result = self.client.call('plan', self.spec)
            if result.get('status') not in ('authorized', 'needs_approval'):
                return result
            self.state.update(plan_id=result['plan_id'], phase='request' if result['status'] == 'needs_approval' else 'apply')
            self.save()
            return {'status': 'planned', 'plan_id': result['plan_id'], 'grant_diff': result.get('grant_diff', {})}
        if phase == 'request':
            result = self.client.call('grant_request', {'plan_id': self.state['plan_id'],
                'mode': self.state['mode'], 'lifetime': self.state['lifetime']})
            if 'approval_url' not in result:
                return result
            approval = urlsplit(result['approval_url'])
            schema.check(approval.scheme == 'https' and approval.hostname and not approval.username and not approval.password
                         and not approval.query and not approval.fragment)
            self.state.update(approval_id=result['request_id'], approval_url=result['approval_url'], phase='waiting')
            self.save()
            # Caller routes this event to the existing OpenClaw Telegram session;
            # no bot token or administrator credential is involved.
            return {'status': 'authorization_required', 'approval_url': result['approval_url'],
                    'request_id': result['request_id'], 'scope': result['scope'], 'mode': result['mode']}
        if phase == 'waiting':
            result = self.client.call('grant_status', {'approval_id': self.state['approval_id']})
            if result.get('status') == 'approved':
                self.state['phase'] = 'apply'; self.save()
                return {'status': 'authorized'}
            if result.get('status') == 'pending':
                return {'status': 'waiting_for_authorization', 'approval_url': self.state['approval_url']}
            return result
        if phase == 'apply':
            # Exactly the original immutable plan, including after a lost response.
            result = self.client.call('apply', {'plan_id': self.state['plan_id']})
            if result.get('status') != 'accepted':
                return result
            self.state.update(task_id=result['task_id'], phase='task'); self.save()
            return result
        schema.check(phase == 'task')
        result = self.client.call('task', {'task_id': self.state['task_id']})
        if result.get('status') not in ('queued', 'running'):
            self.state.update(phase='done', result=result.get('status', 'outcome_unknown')); self.save()
        return result

    def run(self, follow=False, timeout=3600, interval=5):
        deadline, failures = time.monotonic() + timeout, 0
        while True:
            try:
                event = self.step()
                failures = 0
            except (OSError, ValueError):
                failures += 1
                event = {'status': 'transport_not_confirmed', 'phase': self.state['phase'], 'resume': str(self.path)}
            self.emit(event)
            status = event.get('status')
            if status in ('success', 'failed', 'recovery_required', 'outcome_unknown'):
                return 0 if status == 'success' else 1
            if status in ('planned', 'authorized', 'accepted'):
                continue
            if not follow or status not in ('authorization_required', 'waiting_for_authorization', 'queued', 'running', 'transport_not_confirmed', 'busy'):
                return 75 if status in ('authorization_required', 'waiting_for_authorization', 'queued', 'running', 'busy') else 1
            if failures >= 3 or time.monotonic() >= deadline:
                return 75
            time.sleep(min(interval, max(0, deadline - time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['deploy', 'plan', 'apply', 'task', 'status', 'projects', 'grants', 'grant_status', 'start', 'stop', 'restart', 'diagnose', 'retire'])
    parser.add_argument('project')
    parser.add_argument('--endpoint', required=True, help='private HTTPS origin; no path')
    parser.add_argument('--agent', default='openclaw')
    parser.add_argument('--secret-file', required=True)
    parser.add_argument('--spec')
    parser.add_argument('--id')
    parser.add_argument('--state', help='private durable workflow state file for deploy')
    parser.add_argument('--mode', choices=['once', 'persistent', 'expiring'], default='persistent')
    parser.add_argument('--lifetime', type=int, default=86400)
    parser.add_argument('--follow', action='store_true', help='keep polling and automatically continue after Passkey approval')
    parser.add_argument('--timeout', type=int, default=3600)
    args = parser.parse_args()
    schema.number(args.timeout, 1, 86400); schema.number(args.lifetime, 60, 31536000)
    client = Client(args.endpoint, args.agent, args.project, private(args.secret_file, 4096).strip())
    spec = json.loads(private(args.spec, 59000)) if args.spec else None
    if args.operation == 'deploy':
        schema.check(args.state is not None and not args.id)
        return Workflow(client, args.state, spec, args.mode, args.lifetime).run(args.follow, args.timeout)
    schema.check(not args.state and not args.follow)
    if args.operation == 'plan':
        schema.check(spec is not None and not args.id)
        payload = spec
    elif args.operation in ('apply', 'task', 'grant_status'):
        schema.check(args.id is not None and spec is None)
        payload = {dict(apply='plan_id', task='task_id', grant_status='approval_id')[args.operation]: args.id}
    else:
        schema.check(spec is None and args.id is None)
        payload = {}
    # Never retry non-idempotent lifecycle mutations automatically.
    result = client.call(args.operation, payload)
    print(schema.canonical(result))
    return 0 if (not result.get('status') or result['status'] in ('success', 'authorized', 'needs_approval', 'accepted', 'queued', 'running', 'pending', 'approved')) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('{"status":"local_or_transport_error","action":"resume using the same state; do not blindly repeat lifecycle operations"}')
        sys.exit(1)
