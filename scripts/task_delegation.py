"""Explicit-stage task client. No automatic mutation retries or extra grant proposals."""
import argparse
from authorization import agents
from deployer import schema
from scripts.agent import Client, private
from scripts.app_ingress import call as ingress_call


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--delegation-id')
    sub = parser.add_subparsers(dest='stage', required=True)
    req = sub.add_parser('request'); req.add_argument('--lifetime',type=int,default=3600)
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
    main()
