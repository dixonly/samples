vmotion.py
   Demonstrates how to migrate VMs from and to NSX-T networks
   - Supports migration of VM using vSphere vmotion
   - Migrate VMs from within the same or different VCs, with or without 
     enhanced linked mode
   - Supports NSX-T networks
updateDfwFilters.py   
   Retrieve and the DFW filter version for VM vnics on hosts.
   When upgrading between NSX-V versions, the DFW filter version that's 
   applied to each vNIC is not automatically updated to the newest version.
   When performing vmotion migrations of VMs from NSX-V to NSX-T networks, 
   the minimum vNIC's filter version must be 1000 or newer.  Otherwise,
   the destination NSX-T controllers do not understand the older versions
   and will prevent the vNIC from getting connected successfully.
   Note that the source NSX-V version must be 6.4.4 or newer to support
   filter version 1000.
 
   -By default, connect to VC and print out the current DFW filter version 
    of all vNICs in all clusters
        -scope can be limited to a specific cluster
   -Can also update all DFW filter versions to a specified version
  
