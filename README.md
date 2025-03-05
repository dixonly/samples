## vmotion.py

   Demonstrates how to migrate VMs from and to NSX-T networks
   - Supports migration of VM using vSphere vmotion
   - Migrate VMs from within the same or different VCs, with or without 
     enhanced linked mode
   - Supports NSX-T networks
   
   
## updateDfwFilters.py  

   Retrieve and the DFW filter version for VM vnics on hosts.
   When upgrading between NSX-V versions, the DFW filter version that's 
   applied to each vNIC is not automatically updated to the newest version.
   When performing vmotion migrations of VMs from NSX-V to NSX-T networks, 
   the minimum vNIC's filter version must be 1000 or newer.  Otherwise,
   the destination NSX-T controllers do not understand the older versions
   and will prevent the vNIC from getting connected successfully.
   Note that the source NSX-V version must be 6.4.4 or newer to support
   filter version 1000.
 
   - By default, connect to VC and print out the current DFW filter version 
    of all vNICs in all clusters
   - scope can be limited to a specific cluster
   - Can also update all DFW filter versions to a specified version
  
## getVmInstanceId.py

   Connect to VCenter and retrieve all the VM instance UUIDs
   and output a payload that's compatible with the NSX-T
   VM group migration API POST /api/v1/migration/vmgroup?action=pre_migrate.
   For NSX-V to NSX-T migration, if your NSX-V DFW 
   configurations use any apply-to based on dynamic security
   groups based on VMs, the Migration Coordinator will precreate
   apply-to definitions based on VIFs.  The API will help pre-create
   segment ports with VIFs based on the VM instance UUIDs.


## getdfw.py

   Connects to NSX-T Manager and retrieves the running config for:
   - Groups
   - Services
   - VMs
   - DFW Policies and Rules


## v2tdfw_check.py

   When the NSX V2T migration coordinator completes translating the
   NSX-V configuration, it'll store the imported data and
   transient translations in /var/log/migration-coordinator/v2t/storage.json
   and /var/log/migration-coordinator/v2t/api.json.

   This script will compare the temporary data to the data
   retrieved via the getdfw.py script.  The comparison will produce
   output detailing any changes made to the translated groups,
   services, VM inventory and tags, and DFW policies and rules and print
   out those differences to standout.  For DFW rules, it currently only
   compares the order of the policies.

   Gives options to write out the differences as API payloads to
   files.  Especially if NSX-V has the newer differences, you can use
   these API payloads to update NSX-T's group, services, and context profile
   definitions.  The policies API dump will be a complete dump of
   all the NSX-V policies, not just the difference.

   There's a --suffix option where it'll only compare polices imported
   from getdfw.py with a matching suffix.

   When to use this script?
   - A user could have made changes to the target NSX-T configurations
     that unexpectedly changed the DFW security posture in an
     unexpected way.  The script will report what has been changed
   - New changes were made to the NSX-V configuration after the initial
     configuration was imported to the migration coordinator.  Because
     the MC will only import the config once, these new changes would
     not be included in the migration.  The config import and translation
     stages of the MC do not make any changes to the target NSX-T
     instance, you could re-run the MC to re-import and translate the
     configs again.  You can then compare the new api.json and storage.json
     to the running NSX-T config to determine the list of changes
     that need to be rectified.

## update.py

   Takes API payloads generated by v2tdfw_check.py and applies them to
   the NSX Manager.  Note that the --suffix option will append a
   suffix to the policies.  Using the suffix option is recommended
   if you want to re-apply the rules and not overwrite the configuration
   that has been previously migrated by the Migration Coordinator.  Update.py
   will add the new rules to the top of the policy list.  If you do
   not use the --suffix option, then update.py will update the rules
   as is and will most likely overwrite the previously migrated configs.
   It's better to have newly imported ones for re-validation, and then delete
   the previously migrated ones afterwards.

   
## vmtraffic.py
  Connect to VC and retrieve VM network traffic; reports on total
  VM traffic rates per host and max traffic rate of any VM during the 
  sampling interval.  The sampling interval is 20s.

  Outputs the summaries to a CSV file; also optionally outputs all of
  the collected details to a JSON file     

## dfwcopy.py
  Apply the DFW configurations of one manager to another one.  The
  input to the script is the JSON return from the API to the source
  NSX Manager: GET 
  /policy/api/v1/infra?filter=Type-Domain%7CGroup%7CService%7CPolicyContextProfile%7CSecurityPolicy%7CRule

  The GET API will return the domain, groups, services, context profiles,
  and policies from the source NSX Manager.  In lieu of externally retrieving
  this data via an API call, the script can do the same with the
  "--export --file <filename>" parameters.  The script will extract
  only the user defined configs (i.e. exclude the system defined ones) from
  the input file, and then apply them to the target NSX Manager. Note
  that I've only tested against non-Federation and non-VPC/Projects configurations.

  Note that when applying to the target NSX Manager, the script does 
  not perform any conflict checks.  Within NSX Manager, each configuration
  is uniquely identified within its configuration by its "path" property.
  If a configuration with exactly the same path already exists on the
  destination, it will be updated with the configuration from the source.
 
  When applying to the target, all updates will detect for conflicts because
  we assume that the source contains the most up-to-date source of truth
  for the configs. The config updates will be performed with PATCH APIs where
  the source's  revision number is not removed - hence, if the destination has a config
  with the same path but newer revision, that specific update may fail.
 
  The --output parameter optionally saves all the configuration that
  will be applied to the target.  The --logfile parameter will
  optionally save all the API results for the configurations for 
  auditing.

  This script requires the contents of the utils directory.

  Any configuration errors will be recorded in the log file and
  printed on screen.  Because configuration is performed sequentially,
  there may be some configurations that reference other ones
  that haven't been submitted yet.  For example, a Group could
  be referencing an as-yet to be configured IPSET.  If any
  errors are referencing invalid or missing configs, just 
  re-run the script again with the same input again.  All the
  configurations are configured using REST PATCH APIs and
  idempotent.  

  <code>

usage: dfwcopy.py [-h] --nsx NSX --user USER [--password PASSWORD] --file FILE [--export] [--prefix PREFIX] [--prefixrules] [--anchor ANCHOR] [--position {insert_before,insert_after}]
                  [--output OUTPUT] [--logfile LOGFILE] [--retries RETRIES] [--undo]

options:
  -h, --help            show this help message and exit
  --nsx NSX             Target NSX Manager
  --user USER           NSX User
  --password PASSWORD   NSX User password
  --file FILE           Input File, or output to export config
  --export              If specified, call H-API to the NSX Manager to export configs that can be used for migration
  --prefix PREFIX       Prefix to append to all object names and IDs
  --prefixrules
  --anchor ANCHOR       Name of anchor policy for insertion
  --position {insert_before,insert_after}
                        Insert above or below anchor policy
  --output OUTPUT
  --logfile LOGFILE
  --retries RETRIES     # of retries for services and group configs to resolve failures due to order of config for nested dependencies
  --undo                Undo the configs stored in --output argument
  usage: dfwcopy.py [-h] --nsx NSX --user USER [--password PASSWORD] --file FILE [--output OUTPUT] [--logfile LOGFILE]

  </code>

  
Use cases:
1. Export the security and related configs from an NSX Manager
<code>
./dfwcopy.py --nsx <NSX Manager> --user <NSX User> [--password <user password>] --file <output filename> --export
</code>

2. Migrate exported configs to a target NSX Manager

- Migrate as is - all names, path IDs, and sequences will be retained.  This will merge the configs into the target, and may update or overwrite any previously existing configs on the target that have the same ID & path.
<code>
./dfwcopy.py --nsx <NSX Manager> --user <NSX User> [--password <user password>] --file <input filename> [--output <output file to store all parsed and migrated configs>] [--logfile <logfile name to store all migrate results>]

</code>

- Prefix all the configs and then migrate to a target NSX Manager.  This will add a prefix to all the config names, IDs, and paths.  When prefix is provided, the migration will update all the sequence numbers of the Policies - the ordering will be maintained.

<code>
./dfwcopy.py --nsx <NSX Manager> --user <NSX User> [--password <user password>] --file <input filename> [--output <output file to store all parsed and migrated configs>] [--logfile <logfile name to store all migrate results>] --prefix <prefix string>

</code>

- Migrate all the configs to a target NSX Manager and position the migrated policies before or afer a specified anchor policy.  You can create a new empty anchor policy or use an pre-existing policy.  If the position is not specified, the default behavior is to migrate to before the anchor policy.

<code>
./dfwcopy.py --nsx <NSX Manager> --user <NSX User> [--password <user password>] --file <input filename> [--output <output file to store all parsed and migrated configs>] [--logfile <logfile name to store all migrate results>] --prefix <prefix string> --anchor <name of anchor policy> [--position <insert_before | insert_after]

- Especially when multiple NSX configs into one common target, it may be prudent to pre-set the migrated policies to apply-to only a limited scope.  The addition --apply option will let you specify the name of a group to which ALL of the migrated policies will use for their apply-to configuration.  If the existing apply-to is DFW or ANY, then the specify group will be the only apply-to group.  If there's already one or more apply-to group, the new policy's apply-to list will be extended to incude the specified group.

</code>

3. Undo, i.e. delete, all the migrated policies from the target.  Using the --output file, delete all the migrated Policies, Groups, Services, and Context Profiles from the destination.  This can be done by just adding the "--undo" parameter to any of the above example commands.
