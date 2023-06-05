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
    parser.add_argument('--filename', required=True,
                        help="Filename for output")



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
            


def main():
    args = parseParameters()
    
    fp = open(args.filename, "w")
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
    mgr = "https://%s" % args.mgr

    url = mgr + '/api/v1/fabric/virtual-machines?page_size=10'
    
    vms = get(session=s, req=req, api=url)
    output['virtual-machines'] = vms
    url = mgr + '/policy/api/v1/infra/domains/default/security-policies'
    sections  = get(session=s, req=req, api=url)
    output['policies'] = sections

    output['rules'] = []
    for d in sections['results']:
        section  = {}
        section['path'] = d['path']
        url = mgr + '/policy/api/v1'+d['path']+'/rules'
        section['rules'] = get(session=s, req=req, api=url)
        output['rules'].append(section)
        
    #groups
    url = mgr + '/policy/api/v1/infra/domains/default/groups'
    output['groups'] = get(session=s, req=req, api=url)

    # services
    url = mgr + '/policy/api/v1/infra/services'
    output['services'] = get(session=s, req=req, api=url)
    fp.write(json.dumps(output, indent=4))
    fp.close()

if __name__=="__main__":
    main()
