"""Credential-free fixed TCP relays: localhost Serve targets to registered backends.
No HTTP parsing/rewrite, so root paths, WebSockets and streaming survive unchanged.
"""
import selectors
import socket
import socketserver
import threading
from management.protocol import trusted_json
from app_ingress.policy import validate


def relay(client, backend):
    with socket.create_connection(backend, timeout=10) as upstream:
        client.settimeout(60)
        upstream.settimeout(60)
        with selectors.DefaultSelector() as sel:
            sel.register(client, selectors.EVENT_READ, upstream)
            sel.register(upstream, selectors.EVENT_READ, client)
            while True:
                ready = sel.select(60)
                if not ready:
                    return
                for key, _ in ready:
                    data = key.fileobj.recv(65536)
                    if not data:
                        return
                    key.data.sendall(data)


class Relay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, address, backend):
        self.backend = backend
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, *_):
        pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        relay(self.request, self.server.backend)


def main():
    cfg = validate(trusted_json('/etc/app-ingress/policy.json'))
    servers = []
    for value in cfg['backends'].values():
        server = Relay(('127.0.0.1', value['local_port']), (value['dns'], value['port']))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    threading.Event().wait()


if __name__ == '__main__':
    main()
