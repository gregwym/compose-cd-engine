"""Optional credential-free management frontend. Never run in the app namespace."""
import json
import os
import socket
from http.server import BaseHTTPRequestHandler
from management.protocol import read_frame
from receiver.receiver import BoundedHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        try:
            if (self.path != '/v1/ingress' or self.headers.get('Host') != self.server.expected_host
                    or self.headers.get('Transfer-Encoding')):
                raise ValueError('invalid route')
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 8192:
                raise ValueError('invalid length')
            self.connection.settimeout(30)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('truncated body')
            value = json.loads(raw)
            # Canonical single frame prevents injected trailing operations.
            frame = json.dumps(value, separators=(',', ':')).encode()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(30)
                conn.connect('/run/app-ingress/broker.sock')
                conn.sendall(frame + b'\n')
                response = read_frame(conn, 65536)
            status = 200
        except Exception:
            status, response = 400, b'{"error":"request_failed"}'
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(response)


def main():
    server = BoundedHTTPServer(('127.0.0.1', 18794), Handler)
    server.expected_host = os.environ['APP_INGRESS_MANAGEMENT_HOST']
    server.serve_forever()


if __name__ == '__main__':
    main()
