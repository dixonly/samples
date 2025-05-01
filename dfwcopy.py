#!/usr/bin/env python3
import sys, os
import argparse
import ipaddress
import uuid
import copy
import json
import csv
from operator import itemgetter
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
    parser.add_argument("--file", required=True, help="Input File, or output to export config")
    parser.add_argument("--export", required=False, action="store_true",
                        help="If specified, call H-API to the NSX Manager to export configs that can be used for migration")
    parser.add_argument("--prefix", required=False, help="Prefix to append to all object names and IDs")
    parser.add_argument("--prefixrules", required=False, action="store_true")
    parser.add_argument("--anchor", required=False, default=None,
                        help="Name of anchor policy for insertion")
    parser.add_argument("--position", required=False, choices=["insert_before", "insert_after"], default="insert_before",
                        help="Insert above or below anchor policy")
    parser.add_argument("--output", required=False)
    parser.add_argument("--logfile", required=False, default="logfile.txt")
    parser.add_argument("--retries", required=False, default=5, help="# of retries for services and group configs to resolve failures due to order of config for nested dependencies")
    parser.add_argument("--undo", action="store_true",
                        help="Undo the configs stored in --output argument")
    parser.add_argument("--apply", required=False,
                        help="Set all the policies to apply to this group at destination")
    parser.add_argument("--gm", required=False, action="store_true",
                        help="Target is Federation GM instead of local NSX Manager")
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
    failed=0
    for r in results["results"]:
        if "attributes" in r.keys():
            customAtt.extend(r["attributes"])
        else:
            customAtt = attributes
            for c in customAtt:
                r = nsx.patch(api="/policy/api/v1/infra/context-profiles/custom-attributes/default",
                              data=c,
                              verbose=True,
                              codes=[200])
                if r.status_code != 200:
                    print("   ***ERROR: code %d" %r.status_code)
                    print("    " + r.text)
                    failed+=1
            return failed
                             
    for a in attributes:
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
            
            else:
                c = a
                changed=True
            if changed:
                r = nsx.patch(api="/policy/api/v1/infra/context-profiles/custom-attributes/default",
                              data=c,
                              verbose=True,
                              codes=[200])
                if r.status_code != 200:
                    print("   ***ERROR: code %d" %r.status_code)
                    print("    " + r.text)
                    failed+=1
    return failed

def applyCtx(nsx, ctx):
    failed=0
    for c in ctx:
        print("Updating context profile: %s" %c["display_name"])
        r = nsx.patch(api="/policy/api/v1%s" %c["path"], data=c, verbose=True,
                      codes=[200])
        if r.status_code != 200:
            print("   ***ERROR: code %d" %r.status_code)
            print("    " + r.text)
            failed+=1
            
def applyServices(nsx, services):
    errorCount=0
    failed = []
    for s in services:
        print("Updating service: %s" % s["display_name"])
        r = nsx.patch(api="/policy/api/v1%s" %s["path"],
                      data=s, verbose=True, codes=[200])
        if r.status_code != 200:
            print("   ***ERROR: code %d" %r.status_code)
            print("    " + r.text)
            errorCount+=1
            failed.append(s)
    if errorCount>0:
        return failed
    else:
        log.info("All services applied without errors") 
        print("All services applied without errors")
        return None
        
def applyGroups(nsx, groups):
    errorCount=0
    failed = []
    for g in groups:
        print("Updating group: %s" %g["display_name"])
        r = nsx.patch(api="/policy/api/v1%s" %g["path"],
                      data=g, verbose=True, codes=[200])
        if r.status_code != 200:
            print("   ***ERROR: code %d" %r.status_code)
            print("    " + r.text)
            errorCount+=1
            failed.append(g)
    if errorCount > 0:
        return failed
    else:
        log.info("All groups applied without errors")
        print("All groups applied without errors")
        return None
        
        
def applyPolicies(nsx, policies, logger, anchor=None, position=None):
    failed=0
    first=True
    firstPolicy=None
    for p in policies:
        print("Updating Policy: %s" %p["display_name"])
        p["rules"]=[]
        for c in p["children"]:
            if "Rule" in c.keys():
                p["rules"].append(c["Rule"])
        if first and anchor:
            pconfig = nsx.get(api="/policy/api/v1/infra/domains/default/security-policies",
                              verbose=False, codes=[200])
            anchorPolicy=None
            for pc in pconfig["results"]:
                if pc["display_name"] == anchor:
                    anchorPolicy=pc
                    break
            if not anchorPolicy:
                print("Migration failed - Policies - Anchor Policy %s not found" %anchor)
                logger.warn("Migration failed - Policies - Anchor Policy %s not found" %anchor)
                failed+=1
                return failed
            
            r = nsx.patch(api="/policy/api/v1%s" %p["path"],
                          data=p, verbose=True, codes=[200])
            if r.status_code != 200:
                print("   ***ERROR: code %d" %r.status_code)
                print("    " + r.text)
                failed+=1
                print("Migration failed - Policies - failed to migrate first policy: %s" %p["display_name"])
                logger.warn("Migration failed - Policies - failed to migrate first policy: %s" %p["display_name"])
                return failed

            firstPolicy=nsx.get(api="/policy/api/v1%s" %
                                (p["path"]))
            r = nsx.post(api="/policy/api/v1%s/?action=revise&anchor_path=%s&operation=%s" %
                         (p["path"], anchorPolicy["path"], position),
                         data=firstPolicy, verbose=True, codes=[200])
            first=False
            
        else:
            r = nsx.patch(api="/policy/api/v1%s" %p["path"],
                          data=p, verbose=True, codes=[200])
            if r.status_code != 200:
                print("   ***Configuration migration failed for Policy %s ERROR: code %d" %
                      (p["display_name"], r.status_code))
                print("    " + r.text)
                logger.warn("   ***Configuration migration failed for Policy %s ERROR: code %d" %
                            (p["display_name"], r.status_code))
                logger.warn("    " + r.text)
                failed+=1
            if anchor:
                currentPolicy = nsx.get(api="/policy/api/v1%s" %
                                        p["path"], verbose=False, codes=[200])
                r = nsx.post(api="/policy/api/v1%s?action=revise&anchor_path=%s&operation=insert_after" %
                             (p["path"], firstPolicy["path"]) , data=currentPolicy, verbose=True,codes=[200])
                if not r:
                    print("   ***Configuration positioning failed for Policy %s ERROR: code %d" %
                          (p["display_name"], r.status_code))
                    print("    " + r.text)
                    logger.warn("   ***Configuration positioning  failed for Policy %s ERROR: code %d" %
                            (p["display_name"], r.status_code))
                    logger.warn("    " + r.text)
                    failed+=1
                firstPolicy = currentPolicy
    if failed == 0:
        logger.info("All polices migrated successfully")
        print("All policies migrated successfully")
    return failed

def Undo(nsx, configs, logger, retries):
    flow = ["rules", "groups", "services", "ctx"]
    failed={"groups": [], "services": [], "rules": [], "ctx": []}
    for otype in flow:
        if otype not in configs.keys():
            print("No %s to delete")
            continue
        faile=None
        for t in configs[otype]:
            print("Deleting %s: %s - %s" %(otype, t["display_name"], t["path"]))
            logger.info("Deleting %s: %s - %s" %(otype, t["display_name"], t["path"]))
            r = nsx.delete(api="/policy/api/v1%s" % t["path"], verbose=True, codes=[200])
            if r.status_code != 200 and otype in ["services", "groups"]:
                logger.warn("Failed to delete %s - %s" %(otype, t["display_name"]))
                failed[otype].append(t)
    return failed

def doExport(nsx, filename):
    print("Retrieving data from NSX")
    data = nsx.get(api="/policy/api/v1/infra?filter=Type-Domain|Group|Service|PolicyContextProfile|SecurityPolicy|Rule", verbose=False, codes=[200])
    print("Writing data to output file %s"%filename)
    with open(filename, "w") as fp:
        fp.write(json.dumps(data, indent=3))
        fp.close
    print("Complete")

def findGroup(nsx, name):
    groups = nsx.get(api="/policy/api/v1/search/query?query=resource_type:Group",
                     verbose=False, display=False,  codes=[200])
    for g in groups["results"]:
        if g["display_name"] == name:
            return g
    return None

def main():
    args = parseParameters()
    logger=Logger(args.logfile)
    
    if not args.password:
        args.password=getpass.getpass("NSX Manager %s password: " %args.nsx)

    nsx = NsxConnect(server=args.nsx, logger=logger, user=args.user, password=args.password, global_gm=args.gm)

    if args.export:
        doExport(nsx, args.file)
        return
    
        
    if args.undo:
        if not args.output:
            print("The undo action is specified, but missing the input JSON via the --output argument")
            return
        with open(args.output, "r", newline='') as fp:
            configs = json.load(fp)
        attempt=0
        while (attempt < args.retries and
               (len(configs["groups"]) > 0 or len(configs["services"]) > 0) ):
            configs = Undo(nsx, configs, logger, args.retries)
            if len(configs["groups"]) > 0 or len(configs["services"]) > 0:
                print("Failed to delete %d groups and %d services" %
                      (len(configs["groups"]), len(configs["services"])))
                logger.info("Failed to delete %d groups and %d services" %
                      (len(configs["groups"]), len(configs["services"])))
                
                attempt+=1
                if attempt < args.retries:
                    print("Retrying...")
                    logger.info("Retrying...")

        return
    applytogroup = None
    if args.apply:
        print("Finding apply-to group %s" %args.apply)
        applytogroup = findGroup(nsx, args.apply)
        if not applytogroup:
            print("Error - Apply to group %s not found...exiting" %args.apply)
            log.error("Error - Apply to group %s not found...exiting" %args.apply)

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

    domain=domain["Domain"]
    domainTypes=["ChildSecurityPolicy", "ChildGroup"]
    policies=[]
    groups=[]
    sequence = 0
    for k in domain["children"]:
        if k["resource_type"] not in domainTypes:
            print("  domainChild: %s" % k["resource_type"])
    
        if k["resource_type"] == "ChildSecurityPolicy":
            if k["SecurityPolicy"]["category"] == "Ethernet":
                logger.info("Not migrating default layer 2 policy")
                continue
            elif k["SecurityPolicy"]["sequence_number"] > sequence and k["SecurityPolicy"]["sequence_number"] < 999999:
                sequence = k["SecurityPolicy"]["sequence_number"]
            if applytogroup:
                if "ANY" in k["SecurityPolicy"]["scope"]:
                    k["SecurityPolicy"]["scope"] = [applytogroup["path"]]
                else:
                    k["SecurityPolicy"]["scope"].append(applytogroup["path"])
            policies.append(k["SecurityPolicy"])
        elif k["resource_type"] == "ChildGroup":
            # these are DFW exclusion list,etc
            if k["Group"]["_system_owned"]:
                continue
            groups.append(k["Group"])

    policies = sorted(policies, key=itemgetter('sequence_number'))
    
    if args.prefix:
        userSvc = addPrefixToSvc(userSvc, args.prefix)
        groups = addPrefixToGroups(groups, args.prefix)
        userCtx = addPrefixToCtx(userCtx, args.prefix)
        policies = addPrefixToPolicies(policies,  args.prefix,
                                       userSvc, groups, userCtx,
                                       sequence,
                                       args.prefixrules)

        # don't have anything to do for customAttributes
        
            
    outfp = open(args.output, "w")
    outdata={}
    outdata["services"] = userSvc
    outdata["groups"] = groups
    outdata["rules"] = policies
    outdata["attributes"] = customAttributes
    outdata["ctx"] = userCtx

        
    outfp.write(json.dumps(outdata, indent=3))
    outfp.close()
    logger.info("Starting to apply attributes")
    attfailed = applyAttributes(nsx, customAttributes, reverse=False)
    if attfailed:
        print("Migration Failed - Attributes: failed count: %d" %attfailed)
        logger.error("Migration Failed - Attributes: failed count: %d" %attfailed)
        
    logger.info("Starting to apply Context Profiles")
    ctxfailed = applyCtx(nsx, userCtx)
    if ctxfailed:
        print("Migration Failed - Context Profiles: failed count: %d" %ctxfailed)
        logger.error("Migration Failed - ContextProfiless: failed count: %d" %ctxfailed)
        
    logger.info("Starting to apply Services")
    failed=userSvc
    attempts=0
    while failed:
        failed = applyServices(nsx,failed)
        if failed:
            print("Not all services applied successfully, retrying the %d failed ones..." % len(failed))
            attempts+=1
            if attempts >=5:
                print("Migration Failed - Services: failed count: %d" %len(failed))
                print("Services configuration failed for %d configs. # of retries have reached %d, exiting" %(len(failed), attempts))
                logger.warn("Migration Failed - Services: failed count: %d" %len(failed))
                logger.error("Services configuration failed for %d configs. # of retries have reached %d, exiting" %(len(failed), attempts))
            logger.warn("Not all services applied successfully, retrying the %d failed ones..." % len(failed))


    failed = groups
    while failed:
        failed = applyGroups(nsx, failed)
        if failed:
            attempts+=1
            if attempts >=5:
                print("Migration Failed - Groups: failed count: %d" %len(failed))
                print("Group configuration failed for %d configs. # of retries have reached %d, exiting" %(len(failed), attempts))
                logger.warn("Migration Failed -  Groups: failed count: %d" %len(failed))
                logger.error("Group configuration failed for %d configs. # of retries have reached %d, exiting" %(len(failed), attempts))
            print("Not all groups applied successfully, retrying the %d failed ones..." %len(failed))
            logger.warn("Not all groups applied successfully, retrying the %d failed ones..." %len(failed))
    logger.info("Starting to apply Policies")
    pfailed = applyPolicies(nsx, policies, logger, anchor=args.anchor, position=args.position)
    if pfailed:
        print("Migration Failed - Policies: failed count: %d" %pfailed)
        logger.error("Migration Failed - Policies: failed count: %d" %pfailed)
        

def newPath(path, prefix):
    if not prefix:
        return path
    npath = path.split("/")
    npath[-1] = prefix + npath[-1]
    p  = "/".join(npath)
    return p
    
def addPrefixToSvc(services, prefix):
    for s in services:
        s["path"] = newPath(s["path"], prefix)
        s["id"] = prefix + s["id"]
        s["display_name"] = prefix + s["display_name"]

        for e in s["service_entries"]:
            e["id"] = prefix + e["id"]
            e["display_name"] = prefix + e["display_name"]
            # delete ro parent to make output less confusing
            if "path" in e.keys():
                #e["path"] = newPath(e["path"], prefix)
                del e["path"]
            if "parent" in e.keys():
                del e["parent"]
                
        # don't need the children, already in service_entries
        if "children" in s.keys():
            del s["children"]

    for s in services:
        for e in s["service_entries"]:
            if e["resource_type"] == "NestedServiceServiceEntry":
                ns = findObject(services, e["nested_service_path"], prefix)
                if ns:
                    e["nested_service_path"] = ns["path"]
    return services

def findObject(groups, oldPath, prefix):
    npath = newPath(oldPath, prefix)
    #print("Finding %s with prefix %s, new path: %s" % (oldPath, prefix, npath))
    for g in groups:
        if g["path"] == npath:
            return g
    return None
        
        
def handleGroupExpression(expression, prefix, groups):
    '''
    # these don't  reference any paths
    if expression["resource_type"] in ["ConjunctionOperator",
                                       "Condition",
                                       "ExternalIDExpression",
                                       "GroupScopeExpression",
                                       "IPAddressExpression",
                                       "IdentityGroupExpression",
                                       "MACAddressExpression"]:
        return expression
    '''
    if expression["resource_type"] == "PathExpression":
        paths = expression["paths"]
        for i in range(0, len(expression["paths"])):
            # only change if it's referring to another group path
            grp = findObject(groups, expression["paths"][i], prefix)
            if grp:
                expression["paths"][i] = grp["path"]
    elif expression["resource_type"] == "NestedExpression":
        expression = handleGroupExpression(expression, prefix, groups)

    # Let's clean out any references to path and parent path
    # in case it causes problems
    if 'path' in expression.keys():
        del expression["path"]
    if 'parent' in expression.keys():
        del expression["parent"]

    '''
    # this would be onerous and not needed
    if prefix:
        if "display_name" in expression.keys():
            expression["display_name"] = prefix+expression["display_name"]
        if "id" in expression.keys():
            expression["id"] = prefix+expression["id"]
    '''
    return expression

def addPrefixToGroups(groups, prefix):
    # Change all the group paths first
    for g in groups:
        g["path"] = newPath(g["path"], prefix)
        g["id"] = prefix + g["id"]
        g["display_name"] = prefix + g["display_name"]

    # change any expression references to groups
    for g in groups:
        for i in range(0, len(g["expression"])):
            g["expression"][i] = handleGroupExpression(g["expression"][i],
                                                       prefix, groups)
        for i in range(0, len(g["extended_expression"])):
            g["extended_expression"][i] = handleGroupExpression(g["extended_expression"][i],
                                                                prefix, groups)
    return groups

            
def addPrefixToPolicies(policies, prefix, services, groups, ctx, sequence, renamerules=False):
    for p in policies:
        p["path"] = newPath(p["path"], prefix)
        p["id"] = prefix + p["id"]
        p["display_name"] = prefix + p["display_name"]
        # migrate the default-layer3-section as a non default policy
        if p["sequence_number"] > 999999 and p["id"] == prefix+"default-layer3-section":
            p["sequence_number"] = sequence + 100
            print("Changed default layer 3 section sequence to %d" %p["sequence_number"])
        else:
            print("Policy: %s: Sequence[: %d, ref: %d" %(p["id"], p["sequence_number"], sequence))
        if "scope" in p.keys():
            for i in range(0, len(p["scope"])):
                nscope = findObject(groups, p["scope"][i], prefix)
                if nscope:
                    p["scope"][i] = nscope["path"]

        for c in p["children"]:
            r = c["Rule"]
            if renamerules:
                r["display_name"] = prefix+r["display_name"]
            r["parent_path"] = p["path"]
            r["path"] = r["parent_path"] + "/rules/" + r["id"]
            # we should not have to change the rule ID because the new path
            # already has the prefix from the policy

            for i in range(0,len(r["source_groups"])):
                sg = r["source_groups"][i]
                if sg == "ANY":
                    continue
                newg = findObject(groups, sg, prefix)
                if not newg:
                    r["source_groups"][i] = sg
                else:
                    r["source_groups"][i] = newg["path"]
                
            for i in range(0,len(r["destination_groups"])):
                sg = r["destination_groups"][i]
                if sg == "ANY":
                    continue
                newg = findObject(groups, sg, prefix)
                if not newg:
                    r["destination_groups"][i] = sg
                else:
                    r["destination_groups"][i] = newg["path"]

            for i in range(0, len(r["services"])):
                if r["services"][i] == "ANY":
                    continue
                nsvc = findObject(services, r["services"][i], prefix)
                if nsvc:
                    r["services"][i] = nsvc["path"]
                    
            for i in range(0, len(r["profiles"])):
                if r["profiles"][i] == "ANY":
                    continue
                np = findObject(ctx, r["profiles"][i], prefix)
                if np:
                    r["profiles"][i] = np["path"]

            if "scope" in r.keys():
                for i in range(0, len(r["scope"])):
                    nscope = findObject(groups, r["scope"][i], prefix)
                    if nscope:
                        r["scope"][i] = nscope["path"]
                        
    return policies
                                
def addPrefixToCtx(ctx, prefix):
    if not prefix:
        return ctx
    for c in ctx:
        c["id"] = prefix+c["id"]
        c["display_name"] = prefix+c["display_name"]
        c["path"] = newPath(c["path"], prefix)

    return ctx

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
