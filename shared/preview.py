"""Value-free structural Compose projection for anonymous capability previews."""
import difflib
import json


def project(config):
    # Names and structural presence only: images, commands, labels, URLs, paths,
    # environment and arbitrary scalar values can all carry secrets.
    config = config or {}
    return {'services': {name: {key: '[value hidden]' for key in sorted(service)}
                         for name, service in sorted((config.get('services') or {}).items())},
            **{kind: sorted((config.get(kind) or {})) for kind in ('volumes', 'networks', 'secrets', 'configs')
               if config.get(kind)}}


def diff(before, after):
    old = json.dumps(project(before), indent=2, sort_keys=True).splitlines(True)
    new = json.dumps(project(after), indent=2, sort_keys=True).splitlines(True)
    result = ''.join(difflib.unified_diff(old, new, 'current (values hidden)', 'proposed (values hidden)'))
    return result or 'Configuration values changed; values are hidden in this public preview.'
