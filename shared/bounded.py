"""Bound subprocess stdout before buffering; kill/reap on timeout or overflow."""
import os
import selectors
import subprocess
import time


def run(argv, *, env, limit=524288, timeout=30):
    with subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        try:
            output = bytearray()
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    if not selector.select(remaining):
                        raise subprocess.TimeoutExpired(argv, timeout)
                    chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > limit:
                        raise ValueError('subprocess output limit exceeded')
            process.wait(timeout=max(0.001, deadline-time.monotonic()))
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, argv)
            return bytes(output)
        except BaseException:
            process.kill()
            process.wait()
            raise
