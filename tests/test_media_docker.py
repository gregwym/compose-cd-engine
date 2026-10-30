"""AutoBangumi + qBittorrent, managed end to end: agent -> gateway -> Passkey -> runner -> Docker.

The project is the shape real media stacks take: anchors, no-new-privileges, a tmpfs named volume,
network_mode: service:..., media directories outside /volume1/docker. It starts as an existing
Container Manager project (docker compose up by the owner), then one permanent manage grant must
cover everything ordinary management needs, without code changes or further approval.

Opt in with CD_DOCKER_TESTS=1 CD_MEDIA_TESTS=1 (pulls the two images unless present).
CD_MEDIA_PREFIX sets where /volume1 lives (default: a temporary directory).
"""
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from helpers import Stack
from runner import compose, server
from runner.server import Runner

QB_IMAGE = os.environ.get('CD_QB_IMAGE', 'linuxserver/qbittorrent:latest')
AB_IMAGE = os.environ.get('CD_AB_IMAGE', 'estrellaxd/auto_bangumi:latest')
PROJECT = 'bangumi'

COMPOSE = '''x-common: &common
  restart: unless-stopped
  security_opt:
    - no-new-privileges:true
  logging:
    driver: json-file
    options: {max-size: 2m, max-file: "3"}

services:
  qbittorrent:
    <<: *common
    image: ${QB_IMAGE}
    environment:
      TZ: Asia/Shanghai
      PUID: ${PUID:-1026}
      PGID: ${PGID:-100}
      WEBUI_PORT: 8080
      TORRENTING_PORT: 6881
    volumes:
      - ./qbittorrent/config:/config
      - V1/download/bangumi:/downloads
      - cache:/cache
    ports:
      - "127.0.0.1::8080"
      - "127.0.0.1::7892"
    healthcheck:
      test: ["CMD", "curl", "-fsS", "-o", "/dev/null", "http://127.0.0.1:8080"]
      interval: 5s
      retries: 30

  autobangumi:
    <<: *common
    image: ${AB_IMAGE}
    network_mode: service:qbittorrent
    depends_on:
      qbittorrent: {condition: service_healthy}
    environment:
      TZ: Asia/Shanghai
      PUID: ${PUID:-1026}
      PGID: ${PGID:-100}
      UMASK: "022"
    volumes:
      - ./autobangumi/config:/app/config
      - ./autobangumi/data:/app/data
      - V1/video/bangumi:/media

volumes:
  cache:
    driver: local
    driver_opts: {type: tmpfs, device: tmpfs, o: "size=64m"}
'''

DEPLOYER = '''services:
  gateway:
    image: busybox:1.36
    command: ["sleep", "3600"]
'''


@unittest.skipUnless(os.environ.get('CD_DOCKER_TESTS') == '1' and os.environ.get('CD_MEDIA_TESTS') == '1',
                     'set CD_DOCKER_TESTS=1 CD_MEDIA_TESTS=1')
class MediaStack(unittest.TestCase):
    def setUp(self):
        compose.DOCKER = shutil.which('docker')
        prefix = os.environ.get('CD_MEDIA_PREFIX')
        self.temp = None if prefix is not None else tempfile.mkdtemp(prefix='cd-media-')
        self.v1 = Path((prefix if prefix is not None else self.temp) + '/volume1')
        self.docker = self.v1 / 'docker'
        self.deploy_root = self.docker / 'deployer'
        for path in (self.deploy_root, self.v1 / 'download/bangumi', self.v1 / 'video/bangumi',
                     self.v1 / 'download/other'):
            path.mkdir(parents=True, exist_ok=True)
        self.wd = self.docker / PROJECT
        self.wd.mkdir()
        self.compose_text = COMPOSE.replace('V1', str(self.v1))
        (self.wd / 'compose.yaml').write_text(self.compose_text)
        (self.wd / '.env').write_text(f'QB_IMAGE={QB_IMAGE}\nAB_IMAGE={AB_IMAGE}\nPUID=1026\nPGID=100\n')
        os.chmod(self.wd / '.env', 0o600)
        # The deployer's own project, so self-protection is exercised against real resources.
        (self.deploy_root / 'compose.yaml').write_text(DEPLOYER)
        self.cli('-p', 'cd-deployer', '--project-directory', str(self.deploy_root), 'up', '-d')
        # The owner's existing Container Manager project.
        self.cli('-p', PROJECT, '--project-directory', str(self.wd), 'up', '-d', '--wait', timeout=600)

        self.sockets = tempfile.mkdtemp(prefix='cd-', dir='/tmp')
        path = self.sockets + '/runner.sock'
        self.runner = Runner(self.docker, str(self.deploy_root), health_timeout=240, host_view=[str(self.v1)])
        threading.Thread(target=server.serve, args=(self.runner, path), daemon=True).start()
        while not os.path.exists(path):
            time.sleep(0.05)
        self.stack = Stack(runner_socket=path, fake=False)
        self.stack.enroll()
        self.stack.pair()
        self.agent = self.stack.agent

    def cli(self, *args, timeout=300):
        subprocess.run([compose.DOCKER, 'compose', *args], check=True, capture_output=True, timeout=timeout)

    def tearDown(self):
        self.stack.close()
        for name, wd in ((PROJECT, self.wd), ('cd-deployer', self.deploy_root)):
            subprocess.run([compose.DOCKER, 'compose', '-p', name, '--project-directory', str(wd), 'down',
                            '--remove-orphans', '-v'], capture_output=True)
        subprocess.run(['rm', '-rf', str(self.wd), str(self.deploy_root)])
        if self.temp:
            subprocess.run(['rm', '-rf', self.temp])
        subprocess.run(['rm', '-rf', self.sockets])

    def job(self, result):
        self.assertIn('job', result, result)
        state = self.stack.wait_job(result['job'])
        self.assertEqual(state['status'], 'success', json.dumps(state)[:3000])
        return state

    def denied(self, kind, compose_text):
        status, data = self.agent.send(self.agent.body('request', {'kind': kind, 'project': PROJECT,
                                                                  'compose': compose_text}))
        self.assertEqual(status, 403, data)
        return data

    def requests(self):
        with self.stack.store.db() as db:
            return db.execute('SELECT COUNT(*) FROM requests').fetchone()[0]

    def containers(self):
        return {c['service']: c for c in compose.project_containers(PROJECT)}

    def test_full_management_under_one_manage_grant(self):
        identity = {'project': PROJECT, 'working_dir': str(self.wd), 'config_files': [str(self.wd / 'compose.yaml')]}
        self.stack.approve(self.agent('request', kind='read', permanent=True))
        listed = {p['project']: p for p in self.agent('projects')['projects']}
        self.assertTrue(listed[PROJECT]['manageable'], listed[PROJECT])
        self.assertEqual(listed[PROJECT]['identity'], identity)
        self.assertFalse(listed['cd-deployer']['manageable'])

        # One manage request: the boundary is derived from the project's own files.
        request = self.agent('request', kind='manage', project=PROJECT, permanent=True)
        derived = request['detail']['boundary']
        self.assertEqual(derived['mounts'], [{'path': str(self.v1 / 'download/bangumi'), 'mode': 'rw'},
                                             {'path': str(self.v1 / 'video/bangumi'), 'mode': 'rw'}])
        self.assertEqual((derived['networks'], derived['volumes'], derived['host']), ([], [], []))
        status, page = self.stack.browser.request('GET', '/api/request/' + request['id'])
        self.assertEqual(page['detail']['boundary'], derived)  # what the owner approves
        grant = self.stack.approve(request)['outcome']['grant']
        approvals = self.requests()

        data = self.agent('read', project=PROJECT)
        self.assertEqual(data['compose'], self.compose_text)
        self.assertEqual(sorted(data['env_keys']), ['AB_IMAGE', 'PGID', 'PUID', 'QB_IMAGE'])
        self.agent('diagnose', project=PROJECT)
        self.agent('logs', project=PROJECT, service='qbittorrent', tail=20)
        before = {s: c['id'] for s, c in self.containers().items()}

        for op in ('stop', 'start', 'restart', 'up', 'update'):
            with self.subTest(op=op):
                self.job(self.agent(op, project=PROJECT))
        self.job(self.agent('restart', project=PROJECT, services=['autobangumi']))
        self.assertEqual({s: c['id'] for s, c in self.containers().items()}, before)  # nothing recreated

        # Edits inside the boundary: no approval, applied and healthy.
        edited = self.compose_text.replace('      UMASK: "022"', '      UMASK: "022"\n      AB_LOG_LEVEL: ${AB_LOG_LEVEL}')
        self.job(self.agent('request', kind='change', project=PROJECT, compose=edited, env_set={'AB_LOG_LEVEL': 'debug'}))
        self.assertEqual((self.wd / 'compose.yaml').read_text(), edited)
        self.assertIn('AB_LOG_LEVEL=debug', (self.wd / '.env').read_text())
        self.job(self.agent('request', kind='change', project=PROJECT, env_unset=['AB_LOG_LEVEL'],
                            compose=self.compose_text))
        self.assertEqual(self.requests(), approvals)

        # Leaving the boundary fails closed and says what would be needed.
        wider = self.compose_text.replace('      - cache:/cache', f'      - cache:/cache\n      - {self.v1}/download/other:/other')
        error = self.denied('change', wider)
        self.assertEqual(error['error'], 'boundary_exceeded')
        self.assertEqual(error['detail'], [f'mount {self.v1}/download/other (rw)'])

        # Host takeover and the deployer stay out of reach whatever is approved.
        deployer_id = compose.project_containers('cd-deployer')[0]['id']
        for text in (self.compose_text.replace('  autobangumi:\n    <<: *common', '  autobangumi:\n    <<: *common\n    privileged: true'),
                     self.compose_text.replace('network_mode: service:qbittorrent', f'network_mode: container:{deployer_id}'),
                     self.compose_text.replace('      - cache:/cache', f'      - cache:/cache\n      - {self.deploy_root}:/x'),
                     self.compose_text.replace('    healthcheck:', '    networks: [default, edge]\n    healthcheck:')
                     + 'networks:\n  edge:\n    external: true\n    name: cd-deployer_default\n'):
            with self.subTest(text=text[-80:]):
                self.assertEqual(self.denied('change', text)['error'], 'policy')
        self.assertEqual(self.requests(), approvals)

        # Expansion: one replacement manage request derived from the proposed file.
        expand = self.agent('request', kind='manage', project=PROJECT, permanent=True, compose=wider)
        self.assertIn({'path': str(self.v1 / 'download/other'), 'mode': 'rw'}, expand['detail']['boundary']['mounts'])
        replaced = self.stack.approve(expand)['outcome']['grant']
        self.assertNotEqual(replaced, grant)
        self.job(self.agent('request', kind='change', project=PROJECT, compose=wider))
        self.job(self.agent('request', kind='change', project=PROJECT, compose=self.compose_text))

        # Elevated: finite exec in both containers, including the one in qBittorrent's namespace.
        self.stack.approve(self.agent('request', kind='elevated', project=PROJECT, seconds=300))
        for service, argv in (('qbittorrent', ['sh', '-c', 'test -d /downloads && echo qb-ok']),
                              ('autobangumi', ['sh', '-c', 'test -d /media && echo ab-ok'])):
            with self.subTest(exec=service):
                state = self.job(self.agent('exec', project=PROJECT, container=self.containers()[service]['id'], argv=argv))
                self.assertEqual(state['result']['exit_code'], 0, state)
                self.assertIn({'qbittorrent': 'qb-ok', 'autobangumi': 'ab-ok'}[service], state['result']['output'])

        # down and bring back: same identity, same data.
        config = self.wd / 'qbittorrent/config'
        self.assertTrue(any(config.rglob('*')))
        self.job(self.agent('request', kind='down', project=PROJECT))
        self.assertEqual(self.containers(), {})
        self.job(self.agent('up', project=PROJECT))
        self.assertEqual(compose.observed_identity(PROJECT), identity)
        self.assertTrue(any(config.rglob('*')))
        self.assertEqual(self.requests(), approvals + 2)


if __name__ == '__main__':
    unittest.main()
