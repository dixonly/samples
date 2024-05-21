#!/usr/bin/env python3
# Disclaimer: This product is not supported by VMware.
# License: https://github.com/vmware/pyvmomi-community-samples/blob/master/LICENSE
from pyVim import connect
from pyVmomi import vim
from pyVmomi import vmodl
#from tools import tasks
import atexit
import argparse
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
    parser.add_argument('-c', '--cluster',
            required=False,
            action='store',
            help = 'Destination cluster name to poweron VM. Overides the --servers argument ')
    parser.add_argument("-e", '--server',
            required=False,
            action = 'store',
            help = "ESXi server to power on VM.  Ignored if servers provided")
    parser.add_argument('-v', '--datastore',
                        required=False,
                        help="Destination datastore volume")
    parser.add_argument('--dvs',
                        required=False,
                        help="Name of the VDS switch, provide this to remove ambiguity when searching for the networks with the same name across different VDS")
    parser.add_argument('-l', '--network',
                        required=False, nargs="*",
                        help="Destination network, must match number of VM vNICs in VM's HW ordering")
    parser.add_argument('-f', '--vifs',
                        required=False,
                        nargs="*",
                        help="VIF when attaching to NVDS portgroup, must match number of VM vNICs in order")
    parser.add_argument('--autovif',
                        action="store_true",
                        help="Automatically use vm Instance UUID to specify VIF, do not use --vif")
    parser.add_argument('--srcCluster',
                        help="Specify the source cluster to search for the VM")
    parser.add_argument("-n", '--name',
                        required = False,  nargs="*",
                        action='store',
                        help = "VM name ")


    args = parser.parse_args()
    if not args.server and not args.cluster:
        print("Either destination server or cluster must be provided")
        return False
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

def getVmList(inv, names, cluster=None):
    vmList=[]
    if cluster:
        src = getObject(inv, [vim.ClusterComputeResource], cluster)
        if not src:
            print("Cluster %s not found in source VC inventory" %cluster)
            return None
        else:
            print("Looking for VMs in cluster %s" %cluster)
        clusterVms = []
        print("Caching VM names in cluster %s to speed up search" %cluster)
        for vm in src.resourcePool.vm:
            clusterVms.append(vm.name)
        for n in names:
            found=False
            if n in clusterVms:
                vmList.append(src.resourcePool.vm[clusterVms.index(n)])
                found=True
                continue
            if not found:
                print("VM %s not found in cluster %s" %(n, cluster))
                return None
    else:
        for n in names:
            vm = getObject(inv, [vim.VirtualMachine], n)
            if not vm:
                print("VM %s not found in VC inventory" %n)
                return None
            vmList.append(vm)
    return vmList

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
        print("not enough networks for %d nics on vm...only migrating first %d" %(len(nics), len(networks)))

    if vifs and len(vifs) != len(networks):
        print("Number of VIFs must match number of vNICS: vifcount: %d network count: %d"%(len(vifs), len(networks)))
        return None

    netdevs = []
    for i in range(0,len(networks)):
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
    if hasattr(ssl, 'SSLContext'):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode=ssl.CERT_NONE
        si = connect.SmartConnect(host=args.sourcevc, user=args.user, pwd=password, sslContext=context)
    else:
        si = connect.SmartConnect(host=args.sourcevc, user=args.user, pwd=password)

    if not si:
        print("Could not connect to source vcenter: %s " %args.sourcevc)
        return -1
    else:
        print("Connect to vcenter: %s" %args.sourcevc)
        atexit.register(connect.Disconnect, si)

    if not args.destvc or args.sourcevc == args.destvc:
        di = si
    else:
        if hasattr(ssl, 'SSLContext'):
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode=ssl.CERT_NONE
            di = connect.SmartConnect(host=args.destvc, user=args.user, pwd=password, sslContext=context)
        else:
            di = connect.SmartConnect(host=args.destvc, user=args.user, pwd=password)
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

    vds=None
    if args.dvs:
        vds = getObject(dinv, [vim.DistributedVirtualSwitch], args.dvs)
        if not vds:
            print("VDS with name '%s' not ound" % args.dvs)
            return

    vmList = []
    if args.vifs and len(args.name) > 1:
        print("This script does not support migrating more than 1 VM at a time when specifying a VIF")
        return
    print("Finding VMs")
    vmList = getVmList(sinv, args.name, args.srcCluster)
    if not vmList:
        print("Either not all VMs found or no VMs specified...quiting")
        return

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

            if not host and cluster.resourcePool == vm.resourcePool and sinv == dinv:
                print("Must provide host when migrating within same cluster")
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
        network = None
        if vds:
            for pg in vds.portgroup:
                if pg.name == n:
                    network = pg
                    break
            if not network:
                print("Network '%s' not found in in VDS '%s'" %(n, args.dvs))
                return
        else:
            network = getObject(dinv, [vim.Network], n, verbose=False)
            if not network:
                print("Network %s not found" % args.network)
                return 
        print("Destination network %s found." % network.name)
        networks.append(network)

    for vm in vmList:
        netSpec=setupNetworks(vm, host, networks, vifs=args.vifs, autovif=args.autovif)
        relocSpec.deviceChange = netSpec
        print("Initiating migration of VM %s" %vm.name)
        vm.RelocateVM_Task(spec=relocSpec, priority=vim.VirtualMachine.MovePriority.highPriority)
    

if __name__ == "__main__":
    main()

