"""Opt-in checks for Synology Container Manager's db logging requirement.

This does not register projects or synchronize Container Manager metadata.
"""
import json

from runner import compose
from shared.wire import Denied


class Guard:
    def __init__(self, mode='off'):
        if mode not in ('off', 'logs'):
            raise ValueError('CD_CM_MODE must be off or logs')
        self.enabled = mode == 'logs'

    def preflight(self, config):
        if not self.enabled:
            return
        info = json.loads(compose.run([compose.DOCKER, 'info', '--format', '{{json .}}'], timeout=30))
        default = info.get('LoggingDriver')
        if default != 'db':
            raise Denied('cm_logging', 'Synology logs mode requires Docker default logging driver db')
        for name, service in (config.get('services') or {}).items():
            logging = service.get('logging') or {}
            if logging.get('driver', default) != 'db':
                raise Denied('cm_logging', f'{name}: remove the logging override or use db')
            # json-file options are not db options. Never silently discard approved settings.
            if logging.get('options'):
                raise Denied('cm_logging', f'{name}: db logging options require separate validation')

    def verify(self, identity, services=()):
        if not self.enabled:
            return
        items = compose.project_containers(identity['project'])
        relevant = [c for c in items if not services or c['service'] in services]
        if services and set(services) - {c['service'] for c in relevant}:
            raise Denied('cm_logging', 'requested service containers are missing')
        if not relevant or any(c.get('log_driver') != 'db' for c in relevant):
            raise Denied('cm_logging', 'containers must use db; recreate them because restart cannot change the driver')
