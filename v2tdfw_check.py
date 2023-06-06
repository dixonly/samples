#!/usr/bin/env python3
import json
import argparse
from operator import itemgetter
import copy

def parseParameters():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apis', required=True,
                        help="source api.json")
    parser.add_argument('--storage', required=True,
                        help="source storage.json")
    parser.add_argument('--data', required=True,
                        help="NSX-T data with getdfw.py")

    args=parser.parse_args()
    return args


def cleanUpGroup(group, temps):
    if not temps:
        return group

    body = group['body']
    newE = []
    for idx,e in enumerate(body['expression']):
        found=False
        if e['resource_type'] == "PathExpression":
            for t in temps:
                if t in e['paths']:
                    e['paths'].remove(t)
                    found = True
                    break

            if len(e['paths']) == 0:
                if idx+1 != len(body['expression']):
                    n = body['expression'][idx+1]
                else:
                    n = None

                body['expression'].remove(e)
                if n and n['resource_type'] == 'ConjunctionOperator':
                    body['expression'].remove(n)

    return group


            
               
def findGroupByPath(groups, path):
    for g in groups:
        if g['path'] == path:
            return g
    return None

def compareExpression(s, t):
    errors = []
    sCon = 0
    tCon = 0
    curCon = None
    if isinstance(s,list) and isinstance(t, list):
        for e in s:
            if e['resource_type'] == 'ConjunctionOperator':
                if sCon == 0:
                    sCon+=1
                    curCon = e['conjunction_operator']
                else:
                    sCon+=1
                    if e['conjunction_operator'] != curCon:
                        raise ValueError("Unhandled different conjunction ops in same source group %s" % s['id'])
                
        for e in t:
            if e['resource_type'] == 'ConjunctionOperator':
                if sCon == 0:
                    tCon+=1
                    if e['conjunction_operator'] != curCon:
                        error.append("Source conjunction %s not same as target %s" % (curCon, e['conjunction_operator']))
                        curCon = e['conjunction_operator']
                    else:
                        tCon+=1
                        if e['conjunction_operator'] != curCon:
                            raise ValueError("Unhandled different conjunction ops in same dest group %s" % t['path'])

        for e in s:
            if e['resource_type'] == 'IPAddressExpression':
                if len(e['ip_addresses']) > 4000:
                    errors.append("source ip address length over 4k: %d" % len(e['ip_addresses']))
                if len(te['ip_addresses']) > 4000:
                    errors.append("dest ip address length over 4k: %d" % len(te['ip_addresses']))
                allIps = True

                for c in s:
                    if c['resource_type'] != 'ConjunctionOperator' and c['resource_type'] != 'IPAddressExpression':
                        errors.append("IP AddressExpression subtype not IP: %s"
                                      %c['resource_type'])
                        allIps = False
                        break
                if allIps:
                    sIps=[]
                    dIPs=[]
                    for c in s:
                        if c['resource_type'] == 'IPAddressExpression':
                            sIps.extend(c['ip_addresses'])
                    for c in t:
                        if c['resource_type'] == 'IPAddressExpression':
                            tIps.extend(c['ip_addresses'])
                    smissing = []
                    tmissing = []
                    for i in sIps:
                        if i not in dIps:
                            smissing.append(i)
                    for i in dIps:
                        if i not in sIps:
                            tmissing.append(i)
                    if len(smissing) > 0:
                        errors.append("Source IPs missing in target: %s" %json.dumps(smissing))
                    if len(tmissing) > 0:
                        errors.append("Target IPs missing in source: %s" %json.dumps(tmissing))
        return errors
    if s['resource_type'] != t['resource_type']:
        pass

    elif s['resource_type'] == 'ConjunctionOperator':
        if e['conjunction_operator'] != t['conjunction_operator']:
            errors.append("Diff conjunction")
        
    elif s['resource_type'] == 'NestedExpression':
        subErrors = compareExpression(s['expressions'], t['expressions'])
        if subErrors:
            errors.extend(subErrors)
    elif s['resource_type'] == 'PathExpression':
        smissing=[]
        tmissing=[]
        for i in s['paths']:
            if i not in t['paths']:
                smissing.append(i)
        for i in t['paths']:
            if i not in s['paths']:
                tmissing.append(i)
        
        if len(smissing) > 0:
            errors.append("Source paths missing in target: %s" %json.dumps(smissing))
        if len(tmissing) > 0:
            errors.append("Target paths missing in source: %s" %json.dumps(tmissing))
                    
    elif s['resource_type'] == 'IPAddressExpression':
        '''
        if len(s['ip_addresses']) > 4000:
            errors.append("source ip address length over 4k: %d" % len(s['ip_addresses']))
        if len(t['ip_addresses']) > 4000:
            errors.append("dest ip address length over 4k: %d" % len(t['ip_addresses']))
            allIps = True
        '''
        smissing=[]
        tmissing=[]
        for i in s['ip_addresses']:
            if i not in t['ip_addresses']:
                smissing.append(i)
        for i in t['ip_addresses']:
            if i not in s['ip_addresses']:
                tmissing.append(i)
        if len(smissing) > 0:
            errors.append("Source IPs missing in target: %s" %json.dumps(smissing))
        if len(tmissing) > 0:
            errors.append("Target IPs missing in source: %s" %json.dumps(tmissing))

    elif s['resource_type'] == 'MACAddressExpression':
        smissing=[]
        tmissing=[]
        for m in s['mac_addresses']:
            if m not in t['mac_addresses']:
                smissing.append(m)
        for m in t['mac_addresses']:
            if m not in s['mac_addresses']:
                tmissing.append(m)
        if len(smissing) > 0:
            errors.append("Source MACs missing in target: %s" %json.dumps(smissing))
        if len(tmissing) > 0:
            errors.append("Target MACs missing in source: %s" %json.dumps(tmissing))
                
                    
    elif s['resource_type'] == 'ExternalIDExpression':
        smissing=[]
        tmissing=[]
        for i in s['external_ids']:
            if i not in t['external_ids']:
                smissing.append(i)
        for i in t['external_ids']:
            if i not in s['external_ids']:
                tmissing.append(i)
        if len(smissing) > 0:
            errors.append("Source External IDs missing in target: %s" %json.dumps(smissing))
        if len(tmissing) > 0:
            errors.append("Target External IDs missing in source: %s" %json.dumps(tmissing))
            

    elif s['resource_type'] == 'Condition':
        if s['key'] != t['key']:
            errors.append("Condition key: source: %s, target: %s" %(s['key'], t['key']))
            if s['operator'] != t['operator']:
                errors.append("Condition operator: source: %s, target: %s"
                              %(s['operator'], t['operator']))
                if s['value'] == t['value']:
                    errors.append("Condition value: source: %s, target %s"
                                  %(s['value'], t['value']))
    else:
        print(("Unhandled group resource_type: %s" %e['resource_type']))

    return errors




        
def compareGroups(s, t):
    errors=[]
    if not 'expression' in s.keys():
        s['expression'] = []
    if len(s['expression']) != len(t['expression']):
        errors.append("expression length")
    if 'extended_expression' in s.keys() and (len(s['extended_expression']) != len(t['extended_expression'])):
        errors.append("extended expression length")
        if len(s['extended_expression']) > 0 or len(t['extended_expression']) > 0:
            raise ValueError("Unhandled extended expression checking")

    
    sCon = 0
    tCon = 0
    curCon = None
    for e in s['expression']:
        if e['resource_type'] == 'ConjunctionOperator':
            if sCon == 0:
                sCon+=1
                curCon = e['conjunction_operator']
            else:
                sCon+=1
                if e['conjunction_operator'] != curCon:
                    raise ValueError("Unhandled different conjunction ops in same source group %s" % s['id'])

        
    for e in t['expression']:
        if e['resource_type'] == 'ConjunctionOperator':
            if sCon == 0:
                tCon+=1
                if e['conjunction_operator'] != curCon:
                    error.append("Source conjunction %s not same as target %s" % (curCon, e['conjunction_operator']))
                curCon = e['conjunction_operator']
            else:
                tCon+=1
                if e['conjunction_operator'] != curCon:
                    raise ValueError("Unhandled different conjunction ops in same dest group %s" % t['path'])

    # by this point, we can just compare the non-conjunctions
    for e in s['expression']:
        if e['resource_type'] == 'ConjunctionOperator':
            continue
        found=False
        allIps=True
        if e['resource_type'] == 'IPAddressExpression':
            for se in s['expression']:
                if se['resource_type'] != 'ConjunctionOperator' and se['resource_type'] != 'IPAddressExpression':
                    errors.append("IP AddressExpression subtype not IP: %s" %se['resource_type'])
                    allIPs = Falkse
                    break
            if allIps:
                sIps = []
                dIps=[]
                for c in s['expression']:
                    if c['resource_type'] == 'IPAddressExpression':
                        sIps.extend(c['ip_addresses'])
                for c in t['expression']:
                    if c['resource_type'] == 'IPAddressExpression':
                        dIps.extend(c['ip_addresses'])
                smissing=[]
                tmissing=[]
                for i in sIps:
                    if i not in dIps:
                        smissing.append(i)
                for i in dIps:
                    if i not in sIps:
                        tmissing.append(i)
                                    
                if len(smissing)> 0:
                    errors.append("Source IPs missing in target: %s" % json.dumps(smissing))
                if len(tmissing) > 0:
                    errors.append("Target IPs  missing in source: %s" % json.dumps(tmissing))
                if len(smissing) == 0 and len(tmissing) == 0:
                    found=True
        else:
            for te in t['expression']:
                subErrors = compareExpression(e, te)
                if not subErrors:
                    found=True
                    break
                else:
                    errors.extend(subErrors)
                
        if not found:
            errors.append("expression")
    return errors

def getPolicyFromData(policy, mc):
    if mc:
        if 'body' not in policy:
            return None
        else:
            if policy['url'][0] != '/':
                policy['url'] = '/'+policy['url']
            policy['body']['path'] = policy['url']
            return policy['body']
    else:
        return policy
    
def classifyPolicies(policies,mc=False):
    # if mc True, then policies is read from api.json
    data={}
    for i in policies:
        p = getPolicyFromData(i, mc)
        if mc and p['display_name'] == 'Edge Pre Rules Section':
            continue
        if p['category'] not in data.keys():
            data[p['category']] = []
        data[p['category']].append(p)
    for i in data.keys():
        data[i].sort(key=itemgetter('sequence_number'))
    return data

def findPolicyFromList(policies, p):
    for i in policies:
        if i['path'] == p['path']:
            return i
    return None

def getData(args):
    data={}
    data['storageJson'] = json.load(open(args.storage, "r"))
    data['api'] = json.load(open(args.apis, "r"))
    target = json.load(open(args.data, "r"))
    data['vms'] = target['virtual-machines']
    data['services'] = target['services']
    data['rules'] = target['rules']
    data['groups'] = target['groups']
    data['policies'] = target['policies']['results']

    return data


def getRuleByID(rules, id):
    for r in rules:
        if r['id'] == id:
            return r
    return None

def compareRules(r1, r2):
    errors = []
    if len(r1) != len(r2):
        errors.append("Rule length: %d vs %d" %(len(r1), len(r2)))
    smissing=[]
    tmissing=[]
    common=[]
    for i in r1:
        found=False
        for j in r2:
            if i['id'] == j['id']:
                found=True
                common.append(i['id'])
                break
        if not found:
            smissing.append(i['id'])
    for j in r2:
        found=False
        for i in r1:
            if j['id'] == i['id']:
                found=True
                break
        if not found:
            tmissing.append(j['id'])

    if len(smissing) > 0:
        errors.append("Rules missing in target: %s" % json.dumps(smissing))
    if len(tmissing) > 0:
        errors.append("New rules added in target: %s" % json.dumps(tmissing))

    for c in common:
        ruleErr=[]
        s = getRuleByID(r1, c)
        t = getRuleByID(r2, c)
        #print(json.dumps(s, indent=4))
        #print(json.dumps(t, indent=4))
        if s['action'] != t['action']:
            ruleErr.append("ID: %s  ACTION -  source: %s, target: %s"
                           %(s['id'], s['action'].lower(), t['action'].lower()))
        if str(s['logged']).lower() != str(t['logged']).lower():
            ruleErr.append("ID: %s LOGGED - source: %s, target: %s"
                           %(s['id'], str(s['logged']).lower(), str(t['logged']).lower()))
        if s['source_groups'].sort() != t['source_groups'].sort():
            ruleErr.append("ID: %s SOURCE - source: %s, target: %s"
                           %(s['id'], json.dumps(s['source_groups']),
                             json.dumps(t['destination_groups'])))
        if s['destination_groups'].sort() != t['destination_groups'].sort():
            ruleErr.append("ID: %s DESTINATION - source: %s, target: %s"
                           %(s['id'], json.dumps(s['destination_groups']),
                             json.dumps(t['destination_groups'])))
        if s['services'].sort() != t['services'].sort():
            ruleErr.append("ID: %s SERVICES - source: %s, target: %s"
                           %(s['id'], json.dumps(s['services']),
                             json.dumps(t['services'])))
        if str(s['disabled']).lower() != str(t['disabled']).lower():
            ruleErr.append("ID: %s DISABLED - source: %s, target: %s"
                           %(s['id'], str(s['disabled']).lower(), str(t['disabled']).lower()))
        if s['direction'] != t['direction']:
            ruleErr.append("ID: %s DIRECTION - source: %s, target: %s"
                           %(s['id'], s['direction'].lower(), t['direction'].lower()))
        '''
        if s['ip_protocol'] != t['ip_protocol']:
            ruleErr.append("ID: %s IP_PROTOCOL - source: %s, target: %s"
                           %(s['id'], s['ip_protocol'], t['ip_protocol']))
        '''
        if s['scope'].sort() != t['scope'].sort():
            ruleErr.append("ID: %s SERVICES - source: %s, target: %s"
                           %(s['id'], json.dumps(s['scope']),
                             json.dumps(t['scope'])))
        if ruleErr:
            errors.extend(ruleErr)
        
    return errors
def compareTag(src, dst):

    for t1 in src:
        found = False
        for t2 in dst:
            if t1['scope'] == t2['scope'] and t1['tag'] == t2['tag']:
                found=True
                break
        if not found:
            return False
    return True

def compareVMTags(data):
    if 'vm_id_sec_tag_api_dict' not in data['storageJson']:
        print("VM Security tags section not found in storage.json")
        exit()
    importTags = data['storageJson']['vm_id_sec_tag_api_dict']
    errors = []
    for v in importTags.keys():
        #print("Checking %s" %v)
        found = False
        e={}
        e['id'] = v
        e['name'] = importTags[v]['source_name']
        e['source'] = []
        e['target'] = []
        e['error'] = []
        for t in data['vms']['results']:
            if v == t['external_id']:
                vm = t
                if importTags[v]['source_name'] != vm['display_name']:
                    e['error'].append("NSXV name %s different than in T: %s"%(importTags[v]['source_name'], vm['display_name']))
                found = True
                if 'tags' in importTags[v]['body']:
                    if len(importTags[v]['body']['tags']) > 0:
                        if 'tags' not in vm:
                            e['error'].append("VM in target missing tags %s" %e['name'])
                            e['source'].append(json.dumps(importTags[v]['body']['tags']))
                        else:
                            found=True
                            break
                elif not compareTag(importTags[v]['body']['tags'],
                                  vm['tags']):
                    e = {}
                    e['error'].append("tag diff")
                    e['source'].append(json.dumps(importTags[v]['body']['tags']))
                    e['target'].append(json.dumps( vm['tags']))
                    errors.append(e)
                    break
                if not found:
                    e['error'].append("Tag Missing in target: %s" %(importTags[v]['source_name']))
                    e['source'] = importTags[v]['body']['tags']
                    if 'tags' in vm.keys():
                        e['target'].append(json.dumps(vm['tags']))
        if len(e['error']) > 0:
            errors.append(e)
    return errors
            
        
               
        
def compareServices(src, dst):
    errors = []
    
    for s in src:
        sfound=None
        e={}
        e['service'] = s['url']
        e['error'] = []
        if not s['body']:
            continue
        if not 'tags' in s['body']:
            print("Service has no tags")
            continue
        for stag in s['body']['tags']:
            if stag['scope'] == 'v_origin':
                stagv = stag['tag']
            found=None
            for tgt in dst:
                if tgt['path'] == s['url']:
                    found=tgt
                    break
                if not 'tags' in tgt:
                    continue
                for dtag in tgt['tags']:
                    if dtag['scope'] == 'v_origin':
                        if dtag['tag'] == stagv:
                            found=tgt
                            break
                if found:
                    break
            if not found:
                e['error'].append("missing service")

            else:
                b=s['body']
                t = found
                if len(b['service_entries']) != len(t['service_entries']):
                    print(json.dumps(b, indent=4))
                    print(json.dumps(t, indent=4))
                    exit()
                    e['error'].append('LENGTH source: %d, target: %d - source: %s target: %s'
                                      %(len(b['service_entries']),
                                        len(t['service_entries']),
                                        json.dumps(b['service_entries'], indent=4),
                                        json.dumps(t['service_entries'], indent=4)))
                    for se in b['service_entries']:
                        seFound=False
                        for de in t['service_entries']:
                            if de['resource_type'] == se['resource_type']:
                                if ('l4_protocol' in de.keys() and de['l4_protocol'] == se['l4_protocol']) or ('alg' in de.keys() and de['alg'] == se['alg']):
                                    if sorted(de['source_ports']) == sorted(se['source_ports']):
                                        if sorted(de['destination_ports']) == sorted(se['destination_ports']):
                                            seFound=True
                                            break
                        if not seFound:
                            e['error'].append("Service Entry not found: %s in target"% json.dumps(se))
        if e['error']:
            errors.append(e)

    return errors
                                         
                                                

def main():
    args = parseParameters()

    inputData=getData(args)
    storageJson = inputData['storageJson']

    storageGroups = []
    tempGroups = []
    for g in storageJson['policy_group_runtime_mappings']:
        if 'internal_paths_to_delete' in g.keys():
            if not 'temp_apis' in g.keys():
                print("  ***Unhandled temp_apis and no internal to delete")
            else:
                ng = cleanUpGroup(g['api'], g['internal_paths_to_delete'])
                storageGroups.append(ng)
                for ipath in g['internal_paths_to_delete']:
                    if ipath not in tempGroups:
                        tempGroups.append(ipath)

    finalGroups = []
    apiJson = inputData['api']
    for a in apiJson:
        if 'default/groups' in a['url']:
            if a['url'] in tempGroups:
                continue
            else:
                found=False
                for x in storageGroups:
                    if x['url'] == a['url']:
                        finalGroups.append(x)
                        found=True
                        break
                if not found:
                    finalGroups.append(a)
                
    tgroups = inputData['groups']['results']
    missingGroups = []
    for g in finalGroups:
        tg = findGroupByPath(tgroups, g['url'])
        if not tg:
            error={}
            error['errors'] = "missing group"
            error['source'] = g
            error['dest'] ={}
            missingGroups.append(error)
            continue

        err = compareGroups(g['body'], tg)
        if len(err) > 0:
            error={}
            error['errors'] = err
            error['source'] = g
            error['dest'] = tg
            missingGroups.append(error)
    print("***Group Validaton***")
    print(json.dumps(missingGroups, indent=4))
            

    # Check Services
    services=[]
    for svc in apiJson:
        if 'infra/services' in svc['url']:
            services.append(svc)

    tservices=inputData['services']['results']
    svcErrors = compareServices(services, tservices)
    print("*** Service Validation ***")
    for i in svcErrors:
        print(json.dumps(i))
        

    
    #check VM tags
    print("***VM Tag Validation***")
    vmTags = compareVMTags(inputData)
    for i in vmTags:
        print("%s - %s" % (i['id'], i['error']))
        #if i['source'] or i['target']:
        print("  source: %s" %(json.dumps(i['source'])))
        print("  target: %s" %(json.dumps(i['target'])))

    # DFW policies
    policies=[]
    for p in apiJson:
        if '/security-policies/' in p['url']:
            policies.append(p)
            
    sourcePolicies = classifyPolicies(policies, True)
    '''
    for i in sourcePolicies.keys():
        for p in sourcePolicies[i]:
            print("%s - %d" %(i, p['sequence_number']))
    '''
    tpolicies = inputData['policies']

    activePolicies = classifyPolicies(tpolicies, False)
    '''
    for i in activePolicies.keys():
        for p in activePolicies[i]:
            print("%s - %d" %(i, p['sequence_number']))
    '''
    newPolicies=[]
    missingPolicies=[]
    tmpSourcePolicies = sourcePolicies
    tmpActivePolicies = activePolicies

    sourcePaths={}
    activePaths={}
    
    for k in tmpSourcePolicies.keys():
        sourcePaths[k] = []
        for p in tmpSourcePolicies[k]:
            sourcePaths[k].append(p['path'])
                               
    for k in tmpActivePolicies.keys():
        activePaths[k] = []
        for p in tmpActivePolicies[k]:
            activePaths[k].append(p['path'])

    psa = []
    pas = []
    for k in tmpSourcePolicies.keys():
        for x in sourcePaths[k]:
            if x not in activePaths[k]:
                psa.append(x)
        for x in activePaths[k]:
            if x not in sourcePaths[k]:
                pas.append(x)
            
    print("*** DFW Policy Validation ***")
    print("  ***-->Source Policies (sections) missing in Target")
    print(json.dumps(psa))
    print("  ***-->Target Policies not from source")
    print(json.dumps(pas))
                               
    for p in psa:
        for k in sourcePaths.keys():
            if p in sourcePaths[k]:
                sourcePaths[k].remove(p)

    for p in pas:
        for k in activePaths.keys():
            if p in activePaths[k]:
                activePaths[k].remove(p)
    print("   ***Policy ordering from source vs target")
    for k in sourcePaths.keys():
        print("Policy Category: %s" %k)
        for i in range(0,len(sourcePaths[k])):
            if sourcePaths[k][i] != activePaths[k][i]:
                print("   %s - %s" %(sourcePaths[k][i], activePaths[k][i]))
    print("   *** Rule validation for migrated policies")
    for k in sourcePolicies.keys():
        for p in sourcePolicies[k]:
            if p['path'] in psa:
                continue
            t = findPolicyFromList(inputData['rules'], p)
            if not t:
                raise ValueError("Policy %s not found in Active Rules" %p['path'])

            err = compareRules(p['rules'], t['rules']['results'])
            if err:
                errors = {}
                errors['path'] = p['path']
                errors['errors'] = err
                print(json.dumps(errors))
                               
if __name__=="__main__":
    main()
