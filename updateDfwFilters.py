#!/usr/bin/env python3
from pyVim import connect
from pyVmomi import vim
from pyVmomi import vmodl
import atexit
import ssl
import json
import paramiko
import argparse
import time
import re

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
    parser.add_argument('-w', '--hostpassword',
                        required=True,
                        action='store',
                        help = 'Password for ssh connection to host')


    parser.add_argument("-c", '--cluster',
                        required = False,
                        action='store',
                        help = "Cluster name, default will search all clusters")
    parser.add_argument('--update',
                        action='store_true',
                        help="Perform update the filter version")
    parser.add_argument('--version',
                        default=1000, type=int,
                        help="Default: 1000, desired new version")


    args = parser.parse_args()
    return args

def enableSshOnHost(host):
    serviceMgr = host.configManager.serviceSystem
    for s in  serviceMgr.serviceInfo.service:
        if s.key == "TSM-SSH":
            #print("      Service %s status: %s" %(s.key, s.running))
            if not s.running:
                #print("          Starting SSH Service")
                serviceMgr.StartService("TSM-SSH")
                return
def disableSshOnHost(host):
    serviceMgr = host.configManager.serviceSystem
    for s in  serviceMgr.serviceInfo.service:
        if s.key == "TSM-SSH":
            #print("      Service %s status: %s" %(s.key, s.running))
            if  s.running:
                #print("          Stopping SSH Service")
                serviceMgr.StopService("TSM-SSH")
                return
    
def getObject(inv, vimtype, name, verbose=False):
    """
    Get object by name from vcenter inventory
    """

    results=[]
    container = inv.viewManager.CreateContainerView(inv.rootFolder, vimtype, True)
    for i in container.view:
        try:
            if verbose:
                print("Checking %s %s against reference %s" %(i.name, i._moId, name))
            if name and name==i.name:
                results.append(i)
                return results
            else:
                results.append(i)
        except vmodl.fault.ManagedObjectNotFound:
            # This is if object was deleted after container view was created
            pass
    return results

def createSshToHost(host, password):
    h = host.name
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(h, username="root", password=password)
    return ssh

def closeSshToHost(ssh):
    ssh.close()

def getFiltersList(ssh, doSet=False):
    stdin,stdout,stderr = ssh.exec_command('summarize-dvfilter')
    vms = {}

    for i in stdout:
        #reObj =  re.search(("world [0-0]* vmm0:(.*) vcUuid"), i)
        reObj =  re.search("world ([0-9]*) vmm0:(.*) vcUuid", i)
        if reObj:
            currentVm = reObj.group(2)
            vms[currentVm] = []
        reObj = re.search("name: (.*-vmware-sfw.2)", i)
        if reObj:
            vms[currentVm].append((reObj.group(1)))


    return vms


def getSetFilterVersion(ssh, vms, change=False, ver = 1000):
    for v in vms:
        print("VM %s:" %v)
        for n in vms[v]:
            stdin,stdout,stderr = ssh.exec_command('vsipioctl getexportversion -f %s' % n)
            for i in stdout:
                reObj = re.search("Current export version: (.*)", i)
            if reObj:
                version = int(reObj.group(1))
                print("   %s: %s" %(n, reObj.group(1)))
                if change and version != ver:
                    print("   Changing to version %d" %ver)
                    stdin,stdout,stderr=ssh.exec_command('vsipioctl setexportversion -f %s -e %d'
                            % (n, ver))
                    for i in stdout:
                        if "ERROR" in i:
                            print("     %s" %i)





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

    clusters = getObject(inv = si.RetrieveContent(),
                         vimtype = [vim.ClusterComputeResource],
                         name=args.cluster)

    for c in clusters:
        print("Cluster: %s" % c.name)
        for h in c.host:
            print("   %s" %h.name)
            enableSshOnHost(h)
            ssh = createSshToHost(h, password=args.hostpassword)
            vms = getFiltersList(ssh)
            getSetFilterVersion(ssh, vms, change=args.update, ver=args.version)
            closeSshToHost(ssh)
            disableSshOnHost(h)
            
            
            
    

if __name__ == "__main__":
    main()
