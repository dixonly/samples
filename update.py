#!/usr/bin/env python3
import json
import argparse
import json
import requests
import sys
import getpass
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def parseParameters():
    parser = argparse.ArgumentParser()
    parser.add_argument('--username', required=True,
                        help="NSX Username")
    parser.add_argument('--password', required=False,
                        help="NSX user password")
    parser.add_argument('--mgr', required=True,
                        help="NSX Manager IP or FQDN")
    parser.add_argument('--groups', required=False)
    parser.add_argument('--services', required=False)
    parser.add_argument('--policies', required=False)
    parser.add_argument('--ctx', required=False)
    parser.add_argument('--suffix', required=False)
    

    args=parser.parse_args()
    return args


def get(session, req, api):
    firstLoop = True
    cursor = None
    result={}
    while firstLoop or cursor:
        firstLoop = False
        if '?' in api:
            url = '%s&cursor=%s' %(api, cursor) if cursor else api
        else:
            url = '%s?cursor=%s'%(api, cursor) if cursor else api

        r = session.get(url, **req)
        if r.status_code != 200:
            print("Status code for API %s not 200, got: %d" %(api,r.status_code))
            exit()
        data=json.loads(r.text)
        if result:
            result['results'].extend(data['results'])
            if 'cursor' in data:
                result['cursor'] = data['cursor']
        else:
            result = data
        if 'cursor' not in data:
            if 'cursor' in result:
                result['cursor'] = None
            return result
        else:
            cursor=data['cursor']
            
def patch(session, req, api, data):
    r = session.patch(api, data=json.dumps(data), **req)
    print("PATCH: %s" %api)
    print("Result Code: %d" %r.status_code)
    if r.status_code != 200 and r.status_code !=201:
        print(r.text)
    print("   With Data:")
    print(json.dumps(data, indent=4))
def post(session, req, api, data):
    r = session.post(api, data=json.dumps(data), **req)
    print("POST: %s" %api)
    print("Result Code: %d" %r.status_code)
    if r.status_code != 200 and r.status_code !=201:
        print(r.text)
    
def main():
    args = parseParameters()
    

    output = {}
    if not args.password:
        password = getpass.getpass("%s password:"%args.username)
    else:
        password=args.password
        
    req = {'auth': (args.username, password),
           'headers': {'Content-Type': 'application/json',
                       'Accept': 'application/json'},
           'verify': False}
    s = requests.Session()
    mgr = "https://%s/policy/api/v1" % args.mgr

    if args.groups:
        fp = open(args.groups, "r")
        groups = json.load(fp)

        for i in groups:
            api=mgr+i['url']
            patch(session=s,
                  req=req,
                  api=api,
                  data=i['body'])
            
    if args.services:
        fp = open(args.services, "r")
        services=json.load(fp)
        for i in services:
            api=mgr+i['url']
            patch(session=s,
                  req=req,
                  api=api,
                  data=i['body'])
    if args.ctx:
        fp = open(args.ctx, "r")
        ctx=json.load(fp)
        for i in ctx:
            api=mgr+i['url']
            patch(session=s,
                  req=req,
                  api=api,
                  data=i['body'])

    if args.policies:
        fp=open(args.policies, "r")
        policies=json.load(fp)
        for k in policies.keys():
            if k != 'Application':
                continue
            first = True
            anchor=None
            for p in policies[k]:
                if args.suffix:
                    p['path'] = p['path'] + args.suffix
                api=mgr+p['path']
                if first:
                    p['sequence_number'] = 0
                    patch(session=s,
                          req=req,
                          api=api,
                          data=p)
                    api=api+"?action=revise&operation=insert_top"
                    post(session=s,
                         req=req,
                         api=api,
                         data={})
                    first=False
                else:
                    patch(session=s,
                          req=req,
                          api=api,
                          data=p)
                    api=api+"?action=revise&anchor_path=" + anchor + "&operation=insert_after"
                    post(session=s,
                         req=req,
                         api=api,
                         data={})
                anchor = p['path']
                
if __name__=="__main__":
    main()
