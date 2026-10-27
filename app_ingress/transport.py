"""Isolated, version-gated Tailscale LocalAPI transport. Never a caller RPC.
Only broker-owned documents reach the fixed endpoint; ETag gives atomic CAS.
"""
import http.client
import json
import socket
from authorization.scope import require
from deployer import schema


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('local-tailscaled.sock', timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Serve:
    def __init__(self, path):
        self.path = path

    def request(self, method, endpoint, value=None, headers=None):
        conn = UnixHTTP(self.path)
        try:
            conn.request(method, '/localapi/v0/' + endpoint,
                         None if value is None else schema.canonical(value).encode(), headers or {})
            response = conn.getresponse()
            raw = response.read(262145)
            require(response.status == 200 and len(raw) <= 262144, 'serve_transport_failed')
            return json.loads(raw or b'{}'), response.getheader('ETag')
        finally:
            conn.close()

    def snapshot(self):
        status, _ = self.request('GET', 'status')
        require(str(status.get('Version', '')).split('-')[0] == '1.104.2', 'unsupported_tailscale_version')
        require(status.get('BackendState') == 'Running', 'tailnet_not_ready')
        value, tag = self.request('GET', 'serve-config')
        require(isinstance(tag, str) and tag and '\r' not in tag and '\n' not in tag, 'missing_serve_etag')
        return value or {}, tag

    def replace(self, candidate, tag):
        self.request('POST', 'serve-config', candidate, {'If-Match': tag, 'Content-Type': 'application/json'})
