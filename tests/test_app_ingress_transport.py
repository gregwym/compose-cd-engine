import copy
import json
import os
import socketserver
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from app_ingress.transport import Serve
from authorization.scope import Denied


class LocalAPI(unittest.TestCase):
    def test_real_unix_http_etag_version_gate_and_concurrent_drift(self):
        config={'TCP':{'9000':{'HTTPS':True}}}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                if self.path=='/localapi/v0/status':
                    body={'Version':self.server.version,'BackendState':'Running'}
                elif self.path=='/localapi/v0/serve-config':body=self.server.config
                else:raise AssertionError(self.path)
                raw=json.dumps(body).encode()
                self.send_response(200);self.send_header('ETag',str(self.server.revision));self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def do_POST(self):
                if self.path!='/localapi/v0/serve-config':raise AssertionError(self.path)
                if self.headers.get('If-Match')!=str(self.server.revision):
                    self.send_response(412);self.end_headers();return
                self.server.config=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                self.server.revision+=1
                self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'{}')
        with tempfile.TemporaryDirectory() as temp:
            path=temp+'/tailscaled.sock'
            with socketserver.UnixStreamServer(path,Handler) as server:
                server.config=config;server.revision=1;server.version='1.104.2-te26db7a57'
                threading.Thread(target=server.serve_forever,daemon=True).start()
                client=Serve(path)
                actual,tag=client.snapshot();self.assertEqual(actual,config)
                candidate=copy.deepcopy(config);candidate['TCP']['9444']={'HTTPS':True}
                client.replace(candidate,tag)
                self.assertEqual(client.snapshot()[0],candidate)
                with self.assertRaises(Denied):client.replace(config,tag)
                server.version='1.105.0'
                with self.assertRaises(Denied):client.snapshot()
                self.assertEqual(server.config,candidate)
                server.shutdown()
