"""Bounded Docker Engine exec, with process termination inside the container.

A container must supply GNU/BusyBox timeout. Killing only the docker client does
not kill an Engine exec, so the timeout wrapper is mandatory and fail-closed.
"""
import os
import selectors
import subprocess
import time
from runner import compose
from shared.wire import Denied


def validate(argv, timeout):
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 64 or
            any(not isinstance(a, str) or not a or '\x00' in a or len(a) > 4096 for a in argv) or
            sum(map(len, argv)) > 16384 or argv[0].startswith('-') or
            type(timeout) is not int or not 1 <= timeout <= 120):
        raise Denied('invalid_argument', 'argv/timeout')
    return argv


def run(container, argv, timeout):
    validate(argv, timeout)
    command = [compose.DOCKER, 'exec', container, 'timeout', '-s', 'KILL', str(timeout), *argv]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, env=compose.environment())
    data, truncated, timed_out = bytearray(), False, False
    deadline = time.monotonic() + timeout + 5
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() >= deadline:
                process.kill()
                timed_out = True
                break
            for key, _ in selector.select(0.1):
                block = os.read(key.fileobj.fileno(), 8192)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                remaining = 65536 - len(data)
                data.extend(block[:remaining])
                truncated |= len(block) > remaining
    process.wait()
    process.stdout.close()
    timed_out |= process.returncode in (124, 137)
    return {'status': 'failed' if timed_out or process.returncode else 'success',
            'exit_code': process.returncode, 'timed_out': timed_out, 'truncated': truncated,
            'output': data.decode('utf-8', 'replace'), 'container': container,
            'timeout': timeout, 'termination': 'container timeout wrapper; client deadline fallback'}
