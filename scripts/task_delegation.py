"""Explicit-stage task client. No automatic mutation retries or extra grant proposals."""
import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit
from authorization import agents
from deployer import schema
from scripts.agent import Client, private, Workflow, InspectWorkflow
from scripts.app_ingress import call as ingress_call


class TaskGrantWorkflow:
    """One full-scope request; poll only that request, never execute task stages."""
    save = Workflow.save
    locked = InspectWorkflow.locked
    step = InspectWorkflow.step
    stop = InspectWorkflow.stop
    terminal = staticmethod(InspectWorkflow.terminal)
    run_poll = InspectWorkflow.run

    def __init__(self, client, state, lifetime=3600, emit=None):
        self.client, self.path = client, Path(state).absolute()
        self.emit = emit or (lambda event: print(schema.canonical(event), flush=True))
        self.identity = {'endpoint': client.endpoint, 'agent': client.agent, 'project': client.project}
        schema.number(lifetime, 60, 86400)
        st = self.path.parent.lstat()
        schema.check(self.path.parent.is_dir() and not self.path.parent.is_symlink()
                     and st.st_uid == os.geteuid() and not st.st_mode & 0o077)
        with self.locked():
            if self.path.exists() or self.path.is_symlink():
                self.load()
            else:
                self.state = {'workflow': 'task-grant-v1', 'identity': self.identity,
                              'mode': 'expiring', 'lifetime': lifetime, 'phase': 'request'}
                self.save()

    def load(self):
        self.state = json.loads(private(self.path, 65536))
        schema.check(self.state['workflow'] == 'task-grant-v1' and self.state['identity'] == self.identity)
        schema.check(self.state['mode'] == 'expiring')
        schema.number(self.state['lifetime'], 60, 86400)

    def binding(self, result, initial=False):
        from authorization.delegation import envelope
        scope = result['scope']
        env = envelope(scope['envelope'])
        schema.check(result['agent'] == env['agent'] == self.client.agent
                     and result['project'] == scope['project'] == self.client.project
                     and scope['type'] == 'registered_task_v1'
                     and result['spec_hash'] == schema.fingerprint(scope)
                     and result['mode'] == self.state['mode']
                     and result['lifetime'] == self.state['lifetime'] <= env['max_lifetime'])
        for key in ('request_id', 'plan_id'):
            schema.check(isinstance(result[key], str) and schema.HEX.fullmatch(result[key]))
        schema.check(isinstance(result['policy'], str) and len(result['policy']) == 64
                     and all(c in '0123456789abcdef' for c in result['policy']))
        binding = {key: result[key] for key in ('request_id', 'plan_id', 'policy', 'spec_hash',
                                               'scope', 'mode', 'lifetime', 'agent', 'project')}
        if initial:
            self.state['request'] = binding
        else:
            schema.check(binding == self.state['request'])

    def _step(self):
        phase = self.state['phase']
        if phase == 'stopped':
            return {'status': self.state['result'], 'resume': str(self.path)}
        if phase == 'request_intent':
            return self.stop('outcome_unknown')
        if phase == 'request':
            self.state['phase'] = 'request_intent'; self.save()
            result = self.client.call('delegation_request', {'lifetime': self.state['lifetime']})
            if result.get('status') not in ('pending', 'approved'):
                return self.stop(self.terminal(result))
            self.binding(result, initial=True)
            approval = urlsplit(result['approval_url'])
            schema.check(approval.scheme == 'https' and approval.hostname and not approval.username
                         and not approval.password and not approval.query and not approval.fragment
                         and approval.path == '/requests/' + result['request_id'])
            self.state.update(phase='waiting', approval_url=result['approval_url'])
            self.save()
            return {'status': 'authorization_required', 'request_id': result['request_id'],
                    'approval_url': result['approval_url'], 'scope': result['scope'],
                    'mode': result['mode'], 'lifetime': result['lifetime'], 'resume': str(self.path)}
        schema.check(phase in ('waiting', 'done'))
        result = self.client.call('grant_status', {'approval_id': self.state['request']['request_id']})
        if result.get('status') in ('authorization_unavailable', 'unavailable', 'busy'):
            raise OSError('status read unavailable')
        if result.get('status') == 'rate_limited':
            return {'status': 'retry_later', 'resume': str(self.path)}
        if result.get('status') not in ('pending', 'approved'):
            return self.stop(self.terminal(result))
        self.binding(result)
        if result['status'] == 'pending':
            schema.check(phase == 'waiting')
            return {'status': 'waiting_for_authorization', 'request_id': result['request_id'],
                    'resume': str(self.path)}
        gid = result['delegation_id']
        schema.check(isinstance(gid, str) and schema.HEX.fullmatch(gid))
        if phase == 'done':
            schema.check(gid == self.state['delegation_id'])
        self.state.update(phase='done', delegation_id=gid); self.save()
        return {'status': 'success', 'request_id': result['request_id'],
                'delegation_id': gid, 'resume': str(self.path)}

    def run(self, follow=False, timeout=3600, interval=5):
        schema.number(timeout, 1, 86400)
        schema.number(interval, 1, 300)
        return self.run_poll(follow, timeout, interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--delegation-id')
    sub = parser.add_subparsers(dest='stage', required=True)
    req = sub.add_parser('request'); req.add_argument('--lifetime',type=int,default=3600)
    req.add_argument('--follow', action='store_true')
    req.add_argument('--state', help='private resumable grant state in an owner-only directory')
    req.add_argument('--timeout', type=int, default=3600)
    req.add_argument('--interval', type=int, default=5)
    sub.add_parser('grants'); sub.add_parser('inspect')
    plan = sub.add_parser('adoption-plan'); plan.add_argument('--action',choices=('observe','redeploy'),required=True)
    apply = sub.add_parser('adoption-apply'); apply.add_argument('--plan-id',required=True)
    task = sub.add_parser('adoption-task'); task.add_argument('--task-id',required=True)
    ip = sub.add_parser('ingress-plan'); ip.add_argument('--backend',required=True)
    ia = sub.add_parser('ingress-apply'); ia.add_argument('--plan-id',required=True)
    ir = sub.add_parser('ingress-receipt'); ir.add_argument('--plan-id',required=True)
    args = parser.parse_args()
    key = private(args.key,16384)
    signer = agents.load_private(key)
    agent = agents.identity(agents.public_key(signer))
    client = Client(args.endpoint,agent,args.project,key)
    stage = args.stage
    payload = {}
    if stage == 'request':
        schema.check(not args.follow or args.state is not None)
        if args.state:
            return TaskGrantWorkflow(client, args.state, args.lifetime).run(args.follow, args.timeout, args.interval)
        result = client.call('delegation_request',{'lifetime':args.lifetime})
    elif stage == 'grants':
        result = client.call('grants')
    elif stage.startswith('ingress-'):
        operation = stage.split('-')[1]
        payload = {'backend':args.backend} if operation == 'plan' else {'plan_id':args.plan_id}
        if operation != 'receipt':
            schema.check(args.delegation_id is not None)
            payload.update(delegation_id=args.delegation_id,project=args.project)
        result = ingress_call(args.endpoint,signer,operation,payload)
    else:
        operation = stage.replace('-','_')
        if stage == 'adoption-task': payload = {'task_id':args.task_id}
        else:
            schema.check(args.delegation_id is not None)
            payload = {'delegation_id':args.delegation_id}
            if stage == 'adoption-plan': payload['action'] = args.action
            if stage == 'adoption-apply': payload['plan_id'] = args.plan_id
        result = client.call(operation,payload)
    print(schema.canonical(result))


if __name__ == '__main__':
    sys.exit(main())
