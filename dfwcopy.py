#/usr/bin/env python3
import sys, os
import argparse
import ipaddress
import uuid
import copy
import json
import csv
from utils.nsxconnect import NsxConnect
import getpass
from utils.logger import Logger

#
# The input file is taken return from GET /policy/api/v1/infra?filter=Type-Domain%7CGroup%7CService%7CPolicyContextProfile%7CSecurityPolicy%7CRule
# Note that I've only tested this against Local Manager without Federation or Projects/VPCs.
#
class Tag():
    def __init__(self):
        self.tags = []

    def update(self, taglist, tags=None):
        if not isinstance(tags, list):
            tags=self.tags
        for tag in taglist:
            if tag not in tags:
                tags.append(tag)
        return ta8gs
    
    def remove(self, taglist, tags=None):
        if not tags:
            tags=self.tags
            tags = [tag for tag in tags if tag not in taglist]
        return tags
        
    def create(self, value, scope=None):
        if scope:
            return {"scope": scope, "tag": value}
        else:
            return {"tag": value}

    def getTags(self):
        return self.tags

        
def parseParameters():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nsx", required=True, help="Target NSX Manager")
    parser.add_argument("--user", required=True, help="NSX User")
    parser.add_argument("--password", required=False, help="NSX User password")
    parser.add_argument("--file", required=True, help="Input File")
    parser.add_argument("--output", required=False)
    parser.add_argument("--logfile", required=False, default="logfile.txt")
    args = parser.parse_args()
    return args

def checkGroupTypes(groups):
    for g in groups:
        print("Group: %s" % g["path"])
        print("  e")
        for e in g["expression"]:
            print("   %s" % e["resource_type"])
            if e["resource_type"] == "PathExpression":
                print("      %s" %e["paths"])
        print("  x")
        for e in g["extended_expression"]:
            print("   %s" % e["resource_type"])
        
                  
def processCtxProfile(ctx):
    data=ctx["PolicyContextProfile"]
    alist=[]
    if data["_system_owned"]:
        return None, None
    else:
        for a in data["attributes"]:
            if a["key"] == "DOMAIN_NAME" or a["key"] == "CUSTOM_URL":
                alist.append(a)
        return alist, data

def processService(svc):
    data=svc["Service"]
    if data["_system_owned"]:
        return None
    else:
        return data

def applyAttributes(nsx, attributes,reverse=False):
    print("Updating custom attribute values for context profiles")
    customAtt=[]
    results = nsx.get(api="/policy/api/v1/infra/context-profiles/custom-attributes/default",
                        verbose=False, codes=[200])

    for r in results["results"]:
        if "attributes" in r.keys():
            customAtt.extend(r["attributes"])
                             
    for a in attributes:
        preC=None
        for c in customAtt:
            changed = False
            if c["key"] == a["key"]:
                for v in a["value"]:
                    if reverse:
                        if v in c["value"]:
                            c["value"].remove(v)
                            changed=True
                    else:
                        if v not in c["value"]:
                            c["value"].append(v)
                            changed=True
            
            if changed:
                #print(json.dumps(c,indent=4))
                r = nsx.patch(api="/policy/api/v1/infra/context-profiles/custom-attributes/default",
                              data=c,
                              verbose=True,
                              codes=[200])

def applyCtx(nsx, ctx):
    for c in ctx:
        print("Updating context profile: %s" %c["display_name"])
        r = nsx.patch(api="/policy/api/v1%s" %c["path"], data=c, verbose=True,
                      codes=[200])
def applyServices(nsx, services):
    for s in services:
        print("Updating service: %s" % s["display_name"])
        r = nsx.patch(api="/policy/api/v1%s" %s["path"],
                      data=s, verbose=True, codes=[200])
def applyGroups(nsx, groups):
    for g in groups:
        print("Updating group: %s" %g["display_name"])
        r = nsx.patch(api="/policy/api/v1%s" %g["path"],
                      data=g, verbose=True, codes=[200])
def applyPolicies(nsx, policies):
    for p in policies:
        print("Updating Policy: %s" %p["display_name"])
        p["rules"]=[]
        for c in p["children"]:
            if "Rule" in c.keys():
                p["rules"].append(c["Rule"]) 
        r = nsx.patch(api="/policy/api/v1%s" %p["path"],
                      data=p, verbose=True, codes=[200])
        
def main():
    args = parseParameters()
    logger=Logger(args.logfile)

    if not args.password:
        args.password=getpass.getpass("NSX Manager %s password: " %args.nsx)

    nsx = NsxConnect(server=args.nsx, logger=logger, user=args.user, password=args.password)
    
    with open(args.file, 'r', newline='') as fp:
        data=json.load(fp)

        
    kids=data["children"]
    kidTypes=["ChildPolicyContextProfile", "ChildDomain", "ChildLBService", "ChildService"]
    for k in kids:
        if k["resource_type"] not in kidTypes:
            print("   %s" %k.keys())

    userCtx=[]
    userSvc=[]
    customAttributes = []
    domain=None
    for k in kids:
        if k["resource_type"] == "ChildPolicyContextProfile":
            alist, ctx=processCtxProfile(k)
            if alist:
                customAttributes.extend(alist)
            if ctx:
                userCtx.append(ctx)
                #print(json.dumps(ctx, indent=4))
        elif k["resource_type"] == "ChildService":
            svc = processService(k)
            if svc:
                userSvc.append(svc)
                #print(json.dumps(svc))
        elif k["resource_type"] == "ChildDomain":
            domain=k
    #print("User Context Length: %d" %len(userCtx))
    #print("User Service Length: %d" %len(userSvc))

    domain=domain["Domain"]
    #print(domain.keys())
    domainTypes=["ChildSecurityPolicy", "ChildGroup"]
    policies=[]
    groups=[]
    for k in domain["children"]:
        if k["resource_type"] not in domainTypes:
            print("  domainChild: %s" % k["resource_type"])
    
        if k["resource_type"] == "ChildSecurityPolicy":
            policies.append(k["SecurityPolicy"])
        elif k["resource_type"] == "ChildGroup":
            groups.append(k["Group"])
            #if k["Group"]["_system_owned"]:
            #    print(json.dumps(k["Group"]))


    outfp = open(args.output, "w")
    outdata={}
    outdata["services"] = userSvc
    outdata["groups"] = groups
    outdata["rules"] = policies
    outdata["attributes"] = customAttributes
    outdata["ctx"] = userCtx
    
    outfp.write(json.dumps(outdata, indent=3))
    outfp.close()

    applyAttributes(nsx, customAttributes, reverse=False)
    applyCtx(nsx, userCtx)
    applyServices(nsx,userSvc)
    applyGroups(nsx, groups)
    applyPolicies(nsx, policies)

                
def processServices(services):
    matches=[]
    for s in services:
        if s["_system_owned"]:
            continue
        else:
            matches.append(s)
    return matches

        
def compareValues(src, dst, keys):
    for k in keys:
        if k not in src.keys():
            if k not in dst.keys():
                return True
            else:
                return False
        if k not in dst.keys():
            if k in src.keys():
                return False
            else:
                return True
        if src[k] != dst[k]:
            return False
    return True

def findGroup(group, groups):
    for g in groups.keys():
        if groups[g]["group"]["path"] == group:
            return groups[g]
    #raise ValueError("Group %s not found" %group)
    return None
    
def processPolicies(policies, groups, services, ctx, args):
    rules=[]
    total_matches=0
    for p in policies:
        print("  Checking rules in Policy: %s - %s" %(p["display_name"], p["path"]))
        if not "children" in p.keys():
            print("***No rules for Policy %s" %p["display_name"])
            continue
        for crule in p["children"]:
            rule=crule["Rule"]
            rdata={"rule": rule, "matches": []}
            rules.append(rdata)

            
if __name__ == "__main__":
    main()
