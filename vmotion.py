#!/usr/bin/env python3
# Disclaimer: This product is not supported by VMware.
# License: https://github.com/vmware/pyvmomi-community-samples/blob/master/LICENSE
from pyVim import connect
from pyVmomi import vim
from pyVmomi import vmodl
#from tools import tasks
import atexit
import argparse
import subprocess
import ssl
import OpenSSL

def parseParameters():

    parser = argparse.ArgumentParser(
        description='Arguments to connect to vCenter to add a hosts to a cluster')
    parser.add_argument('-s', '--sourcevc',
                        required = True,
                        action = 'store',
                        help = 'Source Vcenter server name or IP')
    parser.add_argument('-d', '--destvc',
                        required=False,
                        action='store',
                        help="Destination VC server name or IP")
    
    parser.add_argument('-u', '--user',
                        required=True,
                        action='store',
                        help='User name to connect to vcenter')
    parser.add_argument('-p', '--password',
                        required=True,
                        action='store',
                        help = 'Password for connection to vcenter')
    parser.add_argument('--duser',
                        required=False,
                        help="Destination VC Username, default to same as source VC user")
    parser.add_argument('--dpassword',
                        required=False,
                        help="Destination VC user password, default to same as source VC user password")
    parser.add_argument('-c', '--cluster',
                        required=False,
                        action='store',
                        help = 'Destination cluster name to poweron VM. Overides the --servers argument ')
    parser.add_argument("-e", '--server',
                        required=False,
                        action = 'store',
                        help = "Destination ESXi server to power on VM.  Ignored if cluster provided")
    parser.add_argument('-v', '--datastore',
                        required=False,
                        help="Destination datastore volume")
    parser.add_argument('-l', '--network',
                        required=True, nargs="*",
                        help="Destination network, must match number of VM vNICs in VM's HW ordering")
    parser.add_argument('--autovif',
                        action="store_true",
                        help="Automatically use vm Instance UUID to specify VIF, do not use --vif.  This is the option to use with NSX Migration Coordinator")
    parser.add_argument('-f', '--vifs',
                        required=False,
                        help="VIF when attaching to NVDS portgroup, must match number of VM vNICs in order")
    parser.add_argument("-n", '--names',
                        required = True,
                        nargs="*",
                        action='store',
                        help = "VM name or name pattern to match for poweron ")
    parser.add_argument('--glob', required=False,
                        choices=["exact", "startswith", "endswith", "contains"],
                        default="exact",
                        help="VM name matching method")

    args = parser.parse_args()
    if not args.server and not args.cluster:
        print("Either destination server or cluster must be provided")
        exit()
    return args


def getObject(inv, vimtype, name, verbose=False):
    """
    Get object by name from vcenter inventory
    """

    obj = None
    container = inv.viewManager.CreateContainerView(inv.rootFolder, vimtype, True)
    for i in container.view:
        try:
            if verbose:
                print("Checking %s %s against reference %s" %(i.name, i._moId, name))
            if i.name == name:
                obj = i
                break
        except vmodl.fault.ManagedObjectNotFound:
            #print("VM %s no longer exist")
            # This is if object was deleted after container view was created
            pass
    return obj

def getVms(inv, names, glob, verbose=False):
    vms = []
    container = inv.viewManager.CreateContainerView(inv.rootFolder,
                                                    [vim.VirtualMachine],
                                                    True)
    print("Searching through %d VMs for name matching" % len(container.view))
    count = 0
    for i in container.view:
        if count % 100 == 0:
            print("Completed search of %d of %d VMs.." %(count, len(container.view)))
        try:
            if verbose:
                print("Checking %s %s against reference %s" %(i.name, i._moId, name))

            if glob.lower() == 'exact':
                if i.name in names:
                    vms.append(i)
                    continue
            elif glob.lower() == 'contains':
                for n in names:
                    if n in i.name:
                        vms.append(i)
            elif glob.lower() == 'startswith':
                for n in names:
                    if i.name.startswith(n):
                        vms.append(i)
            elif glob.lower() == 'endswith':
                for n in names:
                    if i.name.endswith(n):
                        vms.append(i)
            count+=1
        except vmodl.fault.ManagedObjectNotFound:
            #print("VM %s no longer exist")
            # This is if object was deleted after container view was created
            pass
    return vms

def validateSourceNetworks(vms):
    nicCount = -1
    nics = []
    keys=[]
    error=0
    for v in vms:
        n=0
        thisNics = []
        thisKeys = []
        for d in v.config.hardware.device:
            if isinstance(d, vim.vm.device.VirtualEthernetCard):
                n+=1
                thisNics.append(d)
                thisKeys.append(d.key)
        if nicCount == -1:
            nicCount=n
            nics=thisNics
            keys=thisKeys
        if len(thisNics) != len(nics):
            print("Number of nics (%d) on %s does not match previously found VMs (%d)"
                  %(len(thisNics), v.name, len(nics)))
            error+=1
            continue
            
        for i,vnic in enumerate(thisNics):
            if type(vnic.backing) != type(nics[i].backing):
                print("Network backing (%s) of vNIC index %d for %s does not match previously found VMs (%s)"
                      %(type(vnic.backing), thisKeys[i], v.name, type(nics[i].backing)))
                error+=1
                continue

            if isinstance(vnic.backing, vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo):
                if vnic.backing.opaqueNetworkId != nics[i].backing.opaqueNetworkId:
                    print("NSX Network %s of vNIC index %d for %s doe not match previously found VMs (%s)"
                          %(vnic.backing.opaqueNetworkId, thisKeys[i], v.name,
                            nics[i].backing.opaqueNetworkId))
                    error+1
                    continue
                elif isinstance(vnic.backing, vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo):
                    if vnic.backing.port.key != nics[i].backing.port.key \
                       or vnic.backing.port.switchUuid != nics[i].backing.port.switchUuid:
                        print("VDS key,switch (%s,%s) ofvNIC index %d for %s does not match previoulsy found VM (%s,%s)"
                              %(vnic.backing.port.key,
                                vnic.backing.port.switchUuid,
                                thisKeys[i], v.name,
                                nics[i].backing.port.key,
                                nics[i].backing.port.switchUuid))
                        error+=1
                        continue
                elif isinstance(vnic.backing, vim.vm.device.VirtualEthernetCard.NetworkBackinfoInfo):
                    if vnic.backing.network != nics[i].backing.network:
                        print("Portgroup %s of vNIC index %d for %s not match previously found VM"
                              %(vnic.backing.network, thisKeys[i], v.name,
                                nics[i].backing.network))
                        error+=1
                        continue
                else:
                    print("Unhandled network backing for VM %s: %s"
                          %(v.name, type(vnic.backing)))
                    
    if error > 0:
        print("Network backing not the same for all VMs")
        return False
    else:
        return True
        
def setupNetworks(vm, host, networks, vifs=None, autovif=False):
    # this requires vsphere 7 API
    nics = []
    keys = []
    vmId = vm.config.instanceUuid
    for d in vm.config.hardware.device:
        if isinstance(d, vim.vm.device.VirtualEthernetCard):
            nics.append(d)
            keys.append(d.key)


    if len(nics) > len(networks):
        print("not enough networks for %d nics on vm" %len(nics))
        return None

    if vifs and len(vifs) != len(nics):
        print("Number of VIFs must match number of vNICS")
        return None

    netdevs = []
    for i in range(0,len(nics)):
        v = nics[i]
        n = networks[i]
        if isinstance(n, vim.OpaqueNetwork):
            # Is the source opaque net same as destination?
            opaque=False
            if isinstance(v.backing, vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo):
                if v.backing.opaqueNetworkId == n.summary.opaqueNetworkId:
                    opaque=True
                    originalLs=v.backing.opaqueNetworkId

            v.backing = vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo()
            v.backing.opaqueNetworkId = n.summary.opaqueNetworkId
            v.backing.opaqueNetworkType = n.summary.opaqueNetworkType

            print("Migrating VM %s NIC %d to destination network %s.." %(vm.name, i, v.backing.opaqueNetworkId))
            if vifs:
                v.externalId = vifs[i]
                print("...with vif %s" %v.externalId)
            elif autovif:
                v.externalId = "%s:%s" % (vmId, keys[i])
                
                
                
        elif isinstance(n, vim.DistributedVirtualPortgroup):
            # create dvpg handling
            vdsPgConn = vim.dvs.PortConnection()
            vdsPgConn.portgroupKey = n.key
            vdsPgConn.switchUuid = n.config.distributedVirtualSwitch.uuid
            v.backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
            v.backing.port = vdsPgConn
            print("Migrating VM %s NIC %d to destination dvpg %s on switch %s...." %(vm.name, i, vdsPgConn.portgroupKey, vdsPgConn.switchUuid))
            if vifs:
                v.externalId = vifs[i]
                print("...with vif %s" %v.externalId)
            elif autovif:
                v.externalId = "%s:%s" %(vmId, keys[i])

        else:
            v.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
            v.backing.network = n
            v.backing.deviceName = n.name

        virdev = vim.vm.device.VirtualDeviceSpec()
        virdev.device = v
        virdev.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
        netdevs.append(virdev)
    return netdevs
def main():
    print("This script is not supported by VMware.  Use at your own risk")
    args = parseParameters()
    password = args.password
    user = args.user
    if hasattr(ssl, 'SSLContext'):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode=ssl.CERT_NONE
        si = connect.SmartConnect(host=args.sourcevc, user=user, pwd=password, sslContext=context)
    else:
        si = connect.SmartConnect(host=args.sourcevc, user=user, pwd=password)

    if not si:
        print("Could not connect to source vcenter: %s " %args.sourcevc)
        return -1
    else:
        print("Connect to vcenter: %s" %args.sourcevc)
        atexit.register(connect.Disconnect, si)

    if not args.destvc or args.sourcevc == args.destvc:
        di = si
    else:
        if args.dpassword:
            password=args.dpassword
        if args.duser:
            user=args.duser
        
        
        if hasattr(ssl, 'SSLContext'):
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode=ssl.CERT_NONE
            di = connect.SmartConnect(host=args.destvc, user=user, pwd=password, sslContext=context)
        else:
            di = connect.SmartConnect(host=args.destvc, user=user, pwd=password)
        if not di:
            print("Could not connect to destination vcenter: %s " %args.destvc)
            return -1
        else:
            print("Connect to vcenter: %s" %args.destvc)
            atexit.register(connect.Disconnect, di)

    
    sinv = si.RetrieveContent()
    sdc = sinv.rootFolder.childEntity[0]

    if args.destvc:
        dinv = di.RetrieveContent()
        ddc = dinv.rootFolder.childEntity[0]
    else:
        dinv = sinv
        ddc = sdc
        
    relocSpec = vim.vm.RelocateSpec()
    #print(sinv)
    #print(dinv)
    if sinv != dinv:
        if not args.server and not args.cluster and not args.datastore and not args.network:
            print("XV Vmotion requires host, cluster, datastore, and network")
            return None

        cert = ssl.get_server_certificate((args.destvc, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        thumbprint = x509.digest("SHA1").decode('utf-8')
        
        up = vim.ServiceLocator.NamePassword(username=args.user, password=password)
        sl = vim.ServiceLocator(credential=up,
                                instanceUuid=dinv.about.instanceUuid,
                                url="https://%s" % args.destvc,
                                sslThumbprint=thumbprint)
        relocSpec.service = sl

    #vm = getObject(sinv, [vim.VirtualMachine], args.name, verbose=False)
    vms = getVms(sinv, args.names, args.glob, verbose=False)
    print("Found %d VMs for migration." %len(vms))
    if not validateSourceNetworks(vms):
        exit()

    host=None
    if args.server:
        host = getObject(dinv, [vim.HostSystem], args.server)
        if not host:
            print("Host %s not found" %args.server)
            return
        else:
            print("Destination host %s found." % host.name)
                

    cluster=None
    if  args.cluster:
        cluster = getObject(dinv, [vim.ClusterComputeResource], args.cluster)
        if not cluster:
            print("Cluster %s not found" % args.cluster)
            return
        else:
            print("Destination cluster %s found, checking for DRS recommendation..." % cluster.name)
            if host and host.parent.resourcePool != cluster.resourcePool:
                print("Destination host %s and cluster %s are not resource pool"
                      %(host.name, cluster.name))
                return
            if not cluster.configuration.drsConfig.enabled and not host:
                print("Destination cluster %s is not DRS enabled, must specify host"
                      %cluster.name)
                return


            if not host:
                if (sinv != dinv):
                    print("Cross VC migration must specify a host")
                    return
                rhost = cluster.RecommendHostsForVm(vm=vm, pool=cluster.resourcePool)
                if len(rhost) == 0:
                    print("No hosts found in cluster %s from DRS recommendation for migration"
                          %args.cluster)
                    return
                else:
                    print("DRS recommends %d hosts" %len(rhost))
                    host = rhost[0].host
    if host:
        relocSpec.host = host
        
    if cluster:
        relocSpec.pool = cluster.resourcePool
        
    datastore=None
    if args.datastore:
        datastore = getObject(dinv, [vim.Datastore], args.datastore)
        if not datastore:
            print("Datastore %s not found" % args.datastore)
            return
        else:
            print("Destination datastore  %s found." % datastore.name)
            relocSpec.datastore = datastore

    networks=[]
    for n in args.network:
        print("Searching VCenter for destination network(s)")
        network = getObject(dinv, [vim.Network], n, verbose=False)
        if not network:
            print("Network %s not found" % args.network)
            return 
        else:
            print("Destination network %s found." % network.name)
            networks.append(network)

    for vm in vms:
        if cluster:
            if not host and cluster.resourcePool == vm.resourcePool and sinv == dinv:
                print("Must provide host when migrating within same cluster for VM %s" %vm.name)
                continue
        netSpec=setupNetworks(vm, host, networks, vifs=args.vifs, autovif=args.autovif)
        relocSpec.deviceChange = netSpec
        print("Initiating migration of VM %s" %vm.name)
        vm.RelocateVM_Task(spec=relocSpec, priority=vim.VirtualMachine.MovePriority.highPriority)

if __name__ == "__main__":
    main()

