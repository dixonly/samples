#!/usr/bin/env python3
# Disclaimer: This product is not supported by Broadcom
# License: https://github.com/vmware/pyvmomi-community-samples/blob/master/LICENSE
from pyVim import connect
from pyVmomi import vim
from pyVmomi import vmodl
from vmware.vapi.vsphere.client import create_vsphere_client
#from tools import tasks
import atexit
import argparse
import json
import csv
from datetime import datetime

def parseParameters():

    parser = argparse.ArgumentParser(
            description='Arguments to connect to vCenter to add a hosts to a cluster')
    parser.add_argument('-s', '--vcenter',
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
    parser.add_argument('-c', '--cluster',
                        required=False,
                        nargs="*",
                        action='store',
                        help = 'Destination cluster name to poweron VM. Overides the --servers argument ')
    parser.add_argument("--verifySSL", action="store_true",
                        help="Verify vCenter certificate")
    parser.add_argument("--out",
                        required=True,
                        help="Filename to store host level CSV summary")
    parser.add_argument("--jsonOut", required=False,
                        help="Filename to store JSON outputof all retrieved and processed data")
    args = parser.parse_args()
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
            if i.name.strip() == name:
                obj = i
                break
        except vmodl.fault.ManagedObjectNotFound:
            #print("VM %s no longer exist")
            # This is if object was deleted after container view was created
            print("error in find")
            pass
    return obj

def getObjectList(inv, vimtype, names, verbose=False):
    obj = []
    container = inv.viewManager.CreateContainerView(inv.rootFolder, vimtype, True)
    objNames = [obj.name for obj in container.view]
    for n in names:
        if n in objNames:
            obj.append(container.view[objNames.index(n)])
            continue
    return obj

def getObjectListFromContainer(inv, container, vimtype):
    """
    Find and return all objects of vimtype in container
    Containers: Folder, Datacenter, ComputeResource, ResourcePool, HostSystem
    """
    view =  inv.viewManager.CreateContainerView(container, vimtype, True)
    return view.view


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

def processHostResults(counters, data, counterInfo):
    data["aggregated"] = {}
    data["max"] = {}
    data["vmcount"] = 0
    for c in counters:
        data["aggregated"][c] = []
        data["max"][c] = []
        
    for vm in data["vmdata"]:
        # should only be one key per data
        data["vmcount"]+=1
        for c in vm.keys():
            if c == "name":
                continue
            if len(data["aggregated"][c]) == 0:
                data["aggregated"][c] = vm[c].copy()
                data["max"][c] = vm[c].copy()
            else:
                for i in range(0,len(vm[c])):
                    if vm[c][i] > data["max"][c][i]:
                        data["max"][c][i] = vm[c][i]
                    data["aggregated"][c][i]+=vm[c][i]
        
    for c in counters:
        if counterInfo[c]["type"] == "delta":
            data["aggregated"][c] = [v/data["interval"] for v in data["aggregated"][c]]
            data["max"][c] = [v/data["interval"] for v in data["max"][c]]
    
def processCluster(inv, cluster, counters, verbose=False):
    data={}
    data["hosts"] = {}
    if not cluster.host:
        return None

    count=0
    for host in cluster.host:
        print("%s - Processing host %s" %(datetime.now(),host.name))
        #vmMetrics = inv.perfManager.QueryAvailablePerfMetric(entity=host,
        #                                                     intervalId=20)

        #vmNetMetrics = [m for m in vmMetrics if m.counterId in counters.keys()]
        vmNetMetrics=counters.keys()
        queryMetrics=[]
        for m in vmNetMetrics:
            #queryMetrics.append(vim.PerformanceManager.MetricId(counterId=m.counterId))
            queryMetrics.append(vim.PerformanceManager.MetricId(counterId=m))
            # QueryPerfComposite does not accept instance
            #                                                    instance="*"))
            if verbose:
                print("%d: %s.%s.%s.%s - inst: %s - %s" %
                      (m.counterId,
                       counters[m.counterId].groupInfo.key,
                       counters[m.counterId].nameInfo.key,
                       counters[m.counterId].rollupType,
                       counters[m.counterId].statsType,
                       m.instance,
                       counters[m.counterId].nameInfo.summary))

            spec = vim.PerformanceManager.QuerySpec(entity=host,
                                                    metricId=queryMetrics,
                                                    format=vim.PerformanceManager.Format.csv,
                                                    intervalId=20)
        results=inv.perfManager.QueryPerfComposite(querySpec=spec)
        #print(results)
        #return
        hresults = {}
        hresults["timestamps"] = [t for t in results.entity.sampleInfoCSV.split(',') if t!="20"]
        hresults["interval"] = int(results.entity.sampleInfoCSV.split(',')[0])
        hresults["vmdata"] = []
        hresults["vmnames"] = []
        data["counterInfo"] = {}
        found=[]
        for child in results.childEntity:
            if type(child.entity) != vim.VirtualMachine:
                continue
            vmRes = {}
            vmRes["name"] = child.entity.name
            found=[]
            for v in child.value:
                counter=v.id.counterId
                if counter in found:
                    # Testing so far has shown that the metrics are aggregated for all vNICs.
                    # i.e. even for edge VM with multiple NICs, only one of each was seen
                    # It seems host level has the same counter repeated; this check avoids that
                    # in case it shows up on VM
                    print("%s: Already Exist: %s" %(child.entity.name,vmRes[counter]))
                    print("%s:           new: %s" %(child.entity.name, v.value.split(",")))
                    continue
                else:
                    data["counterInfo"][counter] = {}
                    data["counterInfo"][counter]["counterId"] = counter
                    data["counterInfo"][counter]["name"] = "%s.%s.%s" % (counters[counter].groupInfo.key, counters[counter].nameInfo.key, counters[counter].unitInfo.key)
                    data["counterInfo"][counter]["type"] = counters[counter].statsType
                    data["counterInfo"][counter]["description"] = counters[counter].nameInfo.summary
                    data["counterInfo"][counter]["rollup"] = counters[counter].rollupType
                    
                found.append(counter)
                vmRes[counter] = v.value.split(',')
                vmRes[counter] = list(map(int, vmRes[counter]))
                # Let's calculate rate only at host level
                #if data["counterInfo"][counter]["type"] == "delta":
                #    vmRes[counter] = [v/hresults["interval"] for v in vmRes[counter]]

            hresults["vmdata"].append(vmRes)
        processHostResults(found, hresults,data["counterInfo"])
        #print(hresults["aggregated"])
        #print(hresults["max"])
        #print("  RxPkts Agg: %s" %hresults["aggregated"][153])
        #print("  RxPkts Max: %s" %hresults["max"][153])
        #print("  TxPkts Agg: %s" %hresults["aggregated"][154])
        #print("  TxPkts Max: %s" %hresults["max"][154])
        data["hosts"][host.name] = hresults
        
    return data

def main():
    args = parseParameters()
    password = args.password
    try:
        if not args.verifySSL:
            si = connect.SmartConnect(host=args.vcenter,
                                      user=args.user, pwd=password,
                                      disableSslCertValidation=True)
        else:
            si = connect.SmartConnect(host=args.vcenter,
                                      user=args.user, pwd=password)

    except IOError as io_error:
        print(io_error)

    if not si:
        print("Could not connect to source vcenter: %s " %args.vcenter)
        return -1
    else:
        print("Connected to vcenter: %s" %args.vcenter)
        atexit.register(connect.Disconnect, si)

    if args.jsonOut:
        jsonOut = open(args.jsonOut, "w")
    if args.out:
        csvfp  = open(args.out, "w")
        csvOut = csv.writer(csvfp)
        
    inv = si.RetrieveContent()
    perf = inv.perfManager

    dclist = getObjectListFromContainer(inv, inv.rootFolder, [vim.Datacenter])
    if args.cluster:
        clusters = getObjectList(inv,
                                 [vim.ClusterComputeResource],
                                 args.cluster)
    else:
        for dc in dclist:
            clusters = getObjectListFromContainer(inv,
                                                  dc,
                                              [vim.ClusterComputeResource])
    counter_info = {}
    desiredCounters = [150, 153, 154, 155, 156, 530, 531]
    #desiredCounters = [150, 153,154,533,539, 531, 535,156, 534, 530,429, 429, 532, 540]
    for counter in perf.perfCounter:
        ''''
        150: net.usage.average.rate - inst: 4000 - Network utilization (combined transmit-rates and receive-rates) during the interval
        153: net.packetsRx.summation.delta - inst: 4000 - Number of packets received during the int        154: net.packetsTx.summation.delta - inst: 4000 - Number of packets transmitted during the         155: net.received.average.rate - inst: 4000 - Average rate at which data was received during the interval
        156: net.transmitted.average.rate - inst: 4000 - Average rate at which data was transmitted during the interval
        530: net.bytesRx.average.rate - inst: 4000 - Average amount of data received per second
interval
        531: net.bytesTx.average.rate - inst: 4000 - Average amount of data transmitted per second
erval
            '''
        if counter.groupInfo.key != "net":
            continue
        if counter.key not in desiredCounters:
            continue
        #full_name = counter.groupInfo.key+"." + counter.nameInfo.key + "." + counter.rollupType
        counter_info[counter.key] = counter
        #print("%s: %s - %s" %(counter_info[full_name].key, full_name, counter_info[full_name].nameInfo.summary))


    data={}
    for cluster in clusters:
        data[cluster.name] = processCluster(inv, cluster, counter_info)

    for cluster in data.keys():
        csvOut.writerow([cluster])
        hostD = data[cluster]["hosts"]
        hosts = hostD.keys()
        first=True
        for h in hosts:
            hd = data[cluster]["hosts"][h]
            if first:
                csvOut.writerow(["", "", "counterId", "name", "type", "rollup", "description"])
                for c in data[cluster]["counterInfo"].keys():
                    csvOut.writerow(["", "", c,
                                     data[cluster]["counterInfo"][c]["name"],
                                     data[cluster]["counterInfo"][c]["type"],
                                     data[cluster]["counterInfo"][c]["rollup"],
                                     data[cluster]["counterInfo"][c]["description"]])
                    first=False
            # hostname, indented one column
            csvOut.writerow(["", h])
            csvOut.writerow(["", "", "Type", "Metric", "Note: All delta types for 'agg'  have been converted to rates based on sampling interval, Max is highest of all the VM for that sampling interval"]),
            row = ["", "", "",  "timestamps"] + hd["timestamps"]
            csvOut.writerow(row)
            for c in hd["aggregated"].keys():
                row=["", "",  "agg", data[cluster]["counterInfo"][c]["name"]] + hd["aggregated"][c]
                csvOut.writerow(row)
            for c in hostD[h]["max"].keys():
                row=["", "", "max", data[cluster]["counterInfo"][c]["name"]] + hd["max"][c]
                csvOut.writerow(row)


    if args.jsonOut:
        jsonOut.write(json.dumps(data,indent=3))


    
if __name__ == "__main__":
    main()

