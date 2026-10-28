"""Tailscale LocalAPI: the device's HTTPS name and its Serve configuration."""
import http.client
import json
import re
import socket

SOCKET = '/var/run/tailscale/tailscaled.sock'
UI_PORT, HOOK_PORT = 18790, 18791
RESERVED = (443, 8443)


class LocalAPI(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('local-tailscaled.sock', timeout=10)
        self.socket_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def call(path, method, url, body=None, headers=None):
    connection = LocalAPI(path)
    try:
        connection.request(method, url, body=body, headers={'Sec-Tailscale': 'localapi', **(headers or {})})
        response = connection.getresponse()
        data = response.read(2 * 1024 * 1024)
        if response.status >= 300:
            raise OSError(f'tailscale {url}: HTTP {response.status}')
        return data, response.getheader('Etag')
    finally:
        connection.close()


def domain(path=SOCKET):
    """The MagicDNS name once logged in with HTTPS enabled, else None."""
    status = json.loads(call(path, 'GET', '/localapi/v0/status')[0])
    if status.get('BackendState') != 'Running':
        return None
    name = (status.get('Self') or {}).get('DNSName', '').rstrip('.')
    if not re.fullmatch(r'[a-z0-9-]+(\.[a-z0-9-]+)+\.ts\.net', name):
        raise ValueError('enable MagicDNS in the Tailscale admin console')
    if name not in [d.rstrip('.') for d in status.get('CertDomains') or []]:
        raise ValueError('enable HTTPS certificates in the Tailscale admin console')
    return name


def serve_config(host, routes, funnel):
    """Owner UI on 443; webhooks on 8443 (optionally via Funnel); approved app routes."""
    tcp = {'443': {'HTTPS': True}}
    web = {f'{host}:443': {'Handlers': {'/': {'Proxy': f'http://127.0.0.1:{UI_PORT}'}}}}
    tcp['8443'] = {'HTTPS': True}
    web[f'{host}:8443'] = {'Handlers': {'/hooks/': {'Proxy': f'http://127.0.0.1:{HOOK_PORT}/hooks/'}}}
    for route in routes:
        port = str(route['https_port'])
        tcp[port] = {'HTTPS': True}
        web[f'{host}:{port}'] = {'Handlers': {'/': {'Proxy': f"http://host.docker.internal:{route['target_port']}"}}}
    config = {'TCP': tcp, 'Web': web}
    if funnel:
        config['AllowFunnel'] = {f'{host}:8443': True}
    return config


def apply_serve(config, path=SOCKET):
    _, etag = call(path, 'GET', '/localapi/v0/serve-config')
    headers = {'Content-Type': 'application/json'}
    if etag:
        headers['If-Match'] = etag
    call(path, 'POST', '/localapi/v0/serve-config', json.dumps(config).encode(), headers)
