# ADLab
 Active Directory Lab for Penetration Testing

 The ADComrade.ps1 Script can be used to configure a domian controller and workstation for setting up an Active directory penetration testing lab.

 Once a server and workstation is installed this script can be used to configure the domain controller, create users, create GPO to disable windows defender etc.

Usage: This script can be used to setup an AD environment for Penetration testing lab. The scirpt can be used to configure both Domain Controller and Workstation.

Option 1: Will Initialize a Domain Controller. You will be able to setup a friednly machine name and configure a static IP address for the domain controller.

Option 2: This will installa the role and promote the machine to be a Primary Domian Controller. 

Option 3: This option can be used to configure a share on both Domain controller or Workstation. You need this for opening up port 445 and 139.

Option 4: This option will configure the Group policy to disable Windows Defender.

Option 5: This option will Add user accounts on the domain controller.

Option 6: Similar to Option 1 but used to configure machine name for workstation

Option 7: This adds the workstation to the domain controller.
