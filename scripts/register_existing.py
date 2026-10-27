#!/usr/bin/env python3
"""Local administrator validator/assembler. Does not contact Docker or write NAS config."""
import argparse
import json
import os
from pathlib import Path
from deployer import schema, registration


def private_json(filename):
    p=Path(filename)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        import stat
        st=os.fstat(fd)
        schema.check(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and not st.st_mode&0o077 and st.st_size<=1048576)
        data=os.read(fd,1048577)
        schema.check(len(data)<=1048576)
        return json.loads(data)
    finally: os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',required=True)
    p.add_argument('--reviewed-compose-json',required=True)
    p.add_argument('--output',required=True,help='new private registry file; never overwrites')
    p.add_argument('--allow-redeploy',action='store_true')
    p.add_argument('--health-timeout',type=int,default=120)
    args=p.parse_args()
    baseline=private_json(args.baseline);compose=private_json(args.reviewed_compose_json)
    project=baseline['project']
    entry={'baseline':baseline,'compose':compose,'declaration_hash':schema.fingerprint(compose),
           'allow_redeploy':args.allow_redeploy,'health_timeout':args.health_timeout}
    registration.validate(project,entry)
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        stream.write(schema.canonical({'version':1,'targets':{project:entry}})+'\n')
        stream.flush();os.fsync(stream.fileno())
    print(schema.canonical({'project':project,'declaration_hash':entry['declaration_hash'],
                            'registry_hash':schema.fingerprint(entry),'installed':False}))


if __name__=='__main__': main()
