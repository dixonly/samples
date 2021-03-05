#!/usr/bin/env python3
# Disclaimer: This product is not supported by VMware.
# License: https://github.com/vmware/pyvmomi-community-samples/blob/master/LICENSE
'''
   This script will connect to vCenter and retrieve all the VM instance UUIDs
   that matches the input filter.  This will output a JSON payload that can 
   be used with NSX-T's API: POST /api/v1/migration/cmgroup?action=pre_migrate
'''
from pyVim import connect
from pyVmomi import vim
from pyVmomi import vmodl
#from tools import tasks
import atexit
import argparse
import subprocess
import ssl
import OpenSSL
import json
import random

def parseParameters():

    parser = argparse.ArgumentParser(
        description='Arguments to connect to vCenter to add a hosts to a cluster')
    parser.add_argument('-s', '--sourcevc',
                        required = True,
                        action = 'store',
                        help = 'Source Vcenter server name or IP')
    parser.add_argument('-u', '--user',
                        required=True,
                        action='store',
                        help='User name to connect to vcenter')
    parser.add_argument('-p', '--password',
                        required=True,
                        action='store',
                        help = 'Password for connection to vcenter')

    parser.add_argument("-n", '--name',
                        required = True,
                        nargs="*",
                        action='store',
                        help = "VM name or name pattern to match for poweron ")
    parser.add_argument('-g', '--glob',
                        action='store_true',
                        help="Enable glob matching with any VMs containing the --name value")
    parser.add_argument('-i', '--ignorecase',
                        action='store_true',
                        help="Ignore case in match")
    parser.add_argument('-m', '--group',
                        help="Migration group number, random if not specified")
    args = parser.parse_args()
    return args

def getObjects(inv, vimtype, names, glob=False, ignorecase=False, verbose=False):
    """
    Get object by name from vcenter inventory
    """

    container = inv.viewManager.CreateContainerView(inv.rootFolder, vimtype, True)
    found=[]
    for i in container.view:
        try:
            if verbose:
                print("Checking %s %s against reference %s" %(i.name, i._moId, name))
            for n in names:
                if ignorecase:
                    inn=n.lower()
                    frm=i.name.lower()
                else:
                    inn = n
                    frm = i.name
                    
                if glob and inn in frm:
                    found.append(i)
                elif inn == frm:
                    found.append(i)
                    if len(found) == len(names):
                        return found
                
        except vmodl.fault.ManagedObjectNotFound:
            #print("VM %s no longer exist")
            # This is if object was deleted after container view was created
            pass
    return found

def main():
    print("This script is not supported by VMware.  Use at your own risk")
    args = parseParameters()
    password = args.password
    if hasattr(ssl, 'SSLContext'):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode=ssl.CERT_NONE
        si = connect.SmartConnect(host=args.sourcevc, user=args.user, pwd=password, sslContext=context)
    else:
        si = connect.SmartConnect(host=args.sourcevc, user=args.user, pwd=password)

    if not si:
        print("Could not connect to vcenter: %s " %args.sourcevc)
        return -1
    else:
        print("Connect to vcenter: %s" %args.sourcevc)
        atexit.register(connect.Disconnect, si)

    vms = getObjects(inv = si.RetrieveContent(),
                     vimtype=[vim.VirtualMachine],
                     glob=args.glob,
                     ignorecase=args.ignorecase,
                     names=args.name)
    data={}
    data['vm_instance_ids'] = []
    if args.group:
        data['group_id'] = args.group
    else:
        data['group_id'] = random.randint(1,10000)
    for i in vms:
        data['vm_instance_ids'].append(i.summary.config.instanceUuid)
    print(json.dumps(data, indent=4))

if __name__ == "__main__":
    main()



    
    
