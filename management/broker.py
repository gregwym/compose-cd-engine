"""Privileged fixed-action adapter. Not a Docker authorization sandbox."""
import fcntl
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from management.protocol import ACTIONS, MAX_REQUEST, MAX_RESPONSE, read_frame, request


STATES = {'created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead'}
HEALTH = {'healthy', 'unhealthy', 'starting', 'none'}


def validate_policy(cfg):
    policy = cfg['management']
    if (not isinstance(policy, dict) or set(policy) != {'socket', 'actions', 'verifier_socket'}
            or not isinstance(policy['socket'], str)
            or not policy['socket'].startswith('/run/compose-cd-management/')
            or '..' in Path(policy['socket']).parts
            or not isinstance(policy['actions'], list) or not policy['actions']
            or any(not isinstance(x, str) or x not in ACTIONS for x in policy['actions'])
            or not isinstance(policy['verifier_socket'], str)
            or not policy['verifier_socket'].startswith('/run/compose-cd/')
            or '..' in Path(policy['verifier_socket']).parts):
        raise ValueError('invalid fixed management policy')
    # NAS-managed targets cannot accidentally archive/restore application data.
    if cfg.get('snapshot_paths'):
        raise ValueError('management targets must use external NAS backups')
    if cfg.get('rollback', True):
        raise ValueError('management pilot requires rollback=false (no implicit DB rollback)')
    if not cfg.get('require_readiness', False):
        raise ValueError('management targets require readiness checks')


def status(cfg, runner):
    services = {}
    for service in cfg['services']:
        ids = runner.command(cfg, 'ps', '-a', '-q', service, timeout=15).stdout.decode().split()
        if not ids:
            services[service] = {'state': 'absent', 'health': 'none'}
            continue
        if len(ids) != 1:
            raise ValueError('ambiguous service')
        # Never inspect env, labels, mounts, argv or health probe output for clients.
        raw = subprocess.run([runner.DOCKER, 'inspect', '--format',
            '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}', ids[0]],
            check=True, timeout=15, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode().strip().split()
        if len(raw) != 2 or raw[0] not in STATES or raw[1] not in HEALTH:
            raise ValueError('invalid container state')
        services[service] = {'state': raw[0], 'health': raw[1]}
    return {'services': services}


def log_summary(cfg, runner):
    # No arbitrary free-form log text crosses the trust boundary. Even regex
    # redaction cannot reliably detect secrets in attacker-controlled messages.
    import selectors
    result = {}
    for service in cfg['services']:
        process = runner.log_process(cfg, service)
        counts = {'error': 0, 'warning': 0, 'info': 0, 'other': 0}
        captured = bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + 3
                while len(captured) < 32768 and time.monotonic() < deadline:
                    if not selector.select(timeout=0.1):
                        if process.poll() is not None:
                            break
                        continue
                    data = os.read(process.stdout.fileno(), min(4096, 32768 - len(captured)))
                    if not data:
                        break
                    captured.extend(data)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
        if process.returncode not in (0, -9):
            raise RuntimeError('logs unavailable')
        for line in captured.decode('utf-8', 'replace').splitlines():
            try:
                doc = json.loads(line)
                level = doc.get('level') if isinstance(doc, dict) else None
            except ValueError:
                level = None
            key = {'ERROR': 'error', 'error': 'error', 'WARN': 'warning',
                   'warning': 'warning', 'INFO': 'info', 'info': 'info'}.get(level, 'other') if isinstance(level, str) else 'other'
            counts[key] += 1
        result[service] = counts
    return {'summary': result, 'content': 'withheld', 'max_bytes_per_service': 32768}


def dispatch(cfg, value, runner):
    # Independent privileged-side validation: HTTP-side allowlists are not enough.
    validate_policy(cfg)
    value = request(json.dumps(value).encode())
    if (value['project'] != cfg['id'] or value['action'] not in cfg['management']['actions']
            or abs(int(time.time()) - value['timestamp']) > 60):
        raise ValueError('not authorized')
    action = value['action']
    runner.STATE_DIR.mkdir(parents=True, exist_ok=True)
    with (runner.STATE_DIR / 'global.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Replay prevention also at privileged boundary. Gateway compromise cannot
        # replay a previously delivered lifecycle action to this broker.
        from management.protocol import reserve_nonce
        reserve_nonce(value, str(runner.STATE_DIR / 'management-nonces.sqlite'))
        audit = {'project': cfg['id'], 'action': action, 'request_id': value['request_id'], 'status': 'running', 'timestamp': int(time.time())}
        audit_path = runner.STATE_DIR / (cfg['id'] + '.management.json')
        runner.write_json(audit_path, audit)
        if action not in ('status', 'logs'):
            # Survive a crash between dispatch and terminal audit. Never infer
            # success or automatically replay an operation left in running state.
            runner.write_json(runner.STATE_DIR / (cfg['id'] + '.last-management-action.json'), audit)
        try:
            if action == 'status':
                result = status(cfg, runner)
                result['recovery_required'] = (runner.STATE_DIR / (cfg['id'] + '.recovery-required.json')).exists()
                last_path = runner.STATE_DIR / (cfg['id'] + '.last-management-action.json')
                if last_path.exists():
                    result['last_action'] = json.loads(last_path.read_text())
                receipt_path = runner.STATE_DIR / (cfg['id'] + '.receipt')
                if receipt_path.exists():
                    receipt = json.loads(receipt_path.read_text())
                    known = {'success', 'no_change', 'failed', 'deploying', 'validated', 'checked', 'observed', 'rolled_back', 'rollback_failed', 'recovery_required'}
                    result['deployment'] = receipt['status'] if receipt.get('status') in known else 'unknown'
            elif action == 'logs':
                result = log_summary(cfg, runner)
            elif action == 'diagnose':
                runner.wait_healthy(cfg)
                result = {'readiness': 'passed'}
            elif action == 'update':
                # Never signal Runner directly, never accept an image or candidate.
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as wake:
                    wake.sendto(b'check', cfg['management']['verifier_socket'])
                result = {'verification': 'requested'}
            else:
                if action != 'stop' and (runner.STATE_DIR / (cfg['id'] + '.recovery-required.json')).exists():
                    raise ValueError('administrator recovery acknowledgement required')
                if cfg.get('observe', True):
                    raise ValueError('target is observe-only')
                if action == 'start':
                    runner.command(cfg, 'start', *cfg['services'], timeout=120)
                elif action == 'restart':
                    runner.command(cfg, 'restart', '--no-deps', *cfg['services'], timeout=120)
                else:
                    runner.command(cfg, 'stop', *cfg['services'], timeout=120)
                if action != 'stop':
                    runner.wait_healthy(cfg)
                result = {'completed': action}
            audit['status'] = 'accepted' if action == 'update' else 'success'
            return {**audit, **result}
        except Exception:
            audit['status'] = 'failed'
            raise
        finally:
            # Append only bounded protocol fields, never exception text or logs.
            runner.write_json(audit_path, audit)
            if action not in ('status', 'logs'):
                runner.write_json(runner.STATE_DIR / (cfg['id'] + '.last-management-action.json'), audit)
            audit_log = runner.STATE_DIR / 'management-audit.jsonl'
            if audit_log.exists() and audit_log.stat().st_size > 2 * 1024 * 1024:
                audit_log.replace(runner.STATE_DIR / 'management-audit.previous.jsonl')
            with audit_log.open('a') as stream:
                stream.write(json.dumps(audit, sort_keys=True) + '\n')


def serve(cfg, runner):
    validate_policy(cfg)
    path = Path(cfg['management']['socket'])
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_socket():
            raise ValueError('unsafe management socket path')
        path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        os.chown(path, 0, int(os.environ.get('CD_MANAGEMENT_GID', '30003')))
        os.chmod(path, 0o660)
        server.listen(4)
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                value = None
                try:
                    value = request(read_frame(connection, MAX_REQUEST))
                    result = dispatch(cfg, value, runner)
                except BlockingIOError:
                    result = {'status': 'busy'}
                except Exception:
                    result = {'status': 'denied_or_failed'}
                if value is not None:
                    result['request_id'] = value['request_id']
                try:
                    data = json.dumps(result).encode()
                    if len(data) > MAX_RESPONSE:
                        data = b'{"status":"response_too_large"}'
                    connection.sendall(data + b'\n')
                except OSError:
                    pass  # Audit remains authoritative after client timeout.
