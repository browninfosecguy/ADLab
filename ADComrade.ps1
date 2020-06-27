#Requires -RunAsAdministrator 
#Requires -Version 3.0


function Get-OSType{
<#
.SYNOPSIS
Get the Operating system type
ProductType 1 is Client operating systems
ProductType 2 is Domain controllers
ProductType 3 is Servers that are not domain controllers
.
.DESCRIPTION
Get-OSType returns the operating system type.
.EXAMPLE
 Get-OSType 
#>

    [CmdletBinding()]
    param()

    $osType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
    Write-Output $osType
}

function Install-ADLabDomainController{
<#
.SYNOPSIS
Install Active Directory Role and promote the server to Primary Domain Controller.
.DESCRIPTION
Install-ADLabDomainController is used to install the Role of AD Domain Services and promote the server to Primary Domain Controller.
.EXAMPLE
 Install-ADLabDomainController
#>
    [CmdletBinding()]
    param()

        if((Get-OSType) -ne 3)
        {
            Write-Verbose "Server Install not detected. Exiting!!" -BackgroundColor Yellow -ForegroundColor Black
            exit
        }

        $ForestName = Read-Host "Enter Forest name. For example covid.inc"
        try {
            Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to Install AD Domain Services Role"
            exit     
        }
        
        try {
            Install-ADDSForest -DomainName $ForestName -InstallDNS -SafeModeAdministratorPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to Install Domain Controller"    
        }       
}

function Initialize-ADLabDomainController{
<#
.SYNOPSIS
Configures Machine name and Static IP address.
.DESCRIPTION
Initialize-ADLabDomainController is used to configure friendly machine name and assign static IP address to the server .
.PARAMETER NewComputerName
The name of the machine.
.EXAMPLE
 Initialize-ADLabDomainController -NewComputerName Skynet
#>
    [CmdletBinding()]
    Param()

    if((Get-OSType) -ne 3)
    {
        Write-Host "Server Install not detected. Exiting!!" -BackgroundColor Yellow -ForegroundColor Black
        exit
    }
    
    Write-Host ("Machine will be restarted after the changes").ToUpper() -BackgroundColor Yellow -ForegroundColor Black

    $choice = Read-Host "Do you want to change the name of the machine? (Y/N)"

    switch ($choice) {
        Y { try {
            $NewComputerName = Read-Host "Please enter new machine name."
            Rename-Computer -NewName $NewComputerName -PassThru -ErrorAction Stop}
            catch {Write-Warning "Unable to rename the Machine."} 
        }
        Default {Write-Host "Keeping the same machine name" -BackgroundColor Yellow -ForegroundColor Black }
    }
     
    $netInterface = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPv4Address,InterfaceIndex | Sort-Object InterfaceIndex

    Write-Host "Following are the network interfaces configured on this machine" -BackgroundColor Yellow -ForegroundColor Black
    foreach($obj in $netInterface)
    {
        Write-Host "Interface: " $obj.InterfaceIndex " IP Address: " $obj.IPv4Address
    }
    
    try{
        [Int32] $selection = Read-Host "Select the InterfaceIndex for Primary Domain Controller" -ErrorAction Stop
        $StaticIP = Read-Host "Enter the static IP adress to assign this machine" -ErrorAction Stop
        [Int32]$SubnetMask = Read-Host "Enter the Prefix length for the subnet mask. Example: Enter 24 for Subnet 255.255.255.0" -ErrorAction Stop 
        $GatewayIP = Read-Host "Enter the IP address of the Gateway" -ErrorAction Stop

        
        Remove-NetIpAddress -InterfaceIndex $selection -AddressFamily IPv4 -ErrorAction Stop
        Remove-NetRoute -InterfaceIndex $selection -AddressFamily IPv4 -Confirm:$false -ErrorAction Stop
        New-NetIpAddress -InterfaceIndex $selection -IpAddress $StaticIP -PrefixLength $SubnetMask -DefaultGateway $GatewayIP -AddressFamily IPv4 -ErrorAction Stop
        Set-DnsClientServerAddress -InterfaceIndex $selection -ServerAddresses $StaticIP -ErrorAction Stop
        Restart-Computer
    }
    catch {
        Write-Warning "Unable to set the IP Address. Manully restart the machine!"
    }
}

function Initialize-ADLabWorkstation{
<#
.SYNOPSIS
Assign a friednly machine name and configure the DNS to Domain Controllers IP address.
.DESCRIPTION
Initialize-ADLabWorkstation is used to assign the workstation a friendly name and configure the DNS IP address to point to Domain Controller.
.PARAMETER NewComputerName
The name of the machine
.EXAMPLE
 Initialize-ADLabWorkstation -NewComputerName Terminator1
#>   
    [CmdletBinding()]
    Param()
    
    if((Get-OSType) -ne 1)
    {
        Write-Host "Workstation install not detected. Exiting!!" -BackgroundColor Yellow -ForegroundColor Black
        exit
    }
    
    Write-Host ("Machine will be restarted after the changes").ToUpper() -BackgroundColor Yellow -ForegroundColor Black

    $choice = Read-Host "Do you want to change the name of the machine? (Y/N)"

    switch ($choice) {
        Y { try {
            $NewComputerName = Read-Host "Please enter new machine name."
            Rename-Computer -NewName $NewComputerName -PassThru -ErrorAction Stop}
            catch {Write-Warning "Unable to rename the machine."} 
        }
        Default {Write-Host "Keeping the same machine name" -BackgroundColor Yellow -ForegroundColor Black }
    }
    
    
    $netInterface = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPv4Address,InterfaceIndex |Sort-Object InterfaceIndex
    Write-Host "Following are the network interfaces configured on this machine" -BackgroundColor Yellow -ForegroundColor Black
    foreach($obj in $netInterface)
    {
        Write-Host "Interface: " $obj.InterfaceIndex " IP Address: " $obj.IPv4Address
    }
    
    $selection = Read-Host "Select the InterfaceIndex for Workstation"

    try {
        Set-DnsClientServerAddress -InterfaceIndex $selection -ServerAddresses ($DomainControllerIPaddress) -ErrorAction Stop
        Restart-Computer
    }
    catch {
        Write-Warning "Unable to configure IP address for the DNS. Restart the machine manually."
    }        
}

function New-ADLabDomainUser{
<#
.SYNOPSIS
Adds new users to the Domian Controller.
.DESCRIPTION
New-ADLabDomainUser configures three users on the domain controller and promote one of them to be Domain Admin.
.EXAMPLE
 New-ADLabDomainUser
#>   
    [cmdletbinding()]
    param()

    if((Get-OSType) -ne 2)
    {
        Write-Host "Domain Controller not detected. Exiting!!" -BackgroundColor Yellow -ForegroundColor Black
        exit          
    }
    
    #Add 3 Users Sarah Conner, Kyle Reese and John Conner. All with password "Password1"
    try {
        New-ADUser -Name "Sarah Conner" -GivenName "Sarah" -Surname "Conner" -SamAccountName "sconner" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
        New-ADUser -Name "Kyle Reese" -GivenName "Kyle" -Surname "Reese" -SamAccountName "kreese" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
        New-ADUser -Name "John Conner" -GivenName "John" -Surname "Conner" -SamAccountName "jconner" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true 
    }
    catch {
        Write-Warning "Unable to create user account"    
    }
    
    #Add John Conner to Domain Admins Group
    try {
        Add-ADGroupMember -Identity "Domain Admins" -Members "jconner"
    }
    catch {
        Write-Warning "Unable to add John Conner to Domain Admins group"
        }
}

function New-ADLabAVGroupPolicy{
<#
.SYNOPSIS
Adds new group policy to disable windows defender.
.DESCRIPTION
New-ADLabAVGroupPolicy configures a new group policy to disable windows defender.
.EXAMPLE
 New-ADLabAVGroupPolicy
#> 
    [cmdletbinding()]
    param()

    if((Get-OSType) -ne 2)
    {
        Write-Host "Domain Controller not detected. Exiting!!" -BackgroundColor Yellow -ForegroundColor Black
        exit
                
    }
    
    try {
        $someerror = $true
        New-GPO -Name "Disable Windows Defender" -Comment "This policy disables windows defender" -ErrorAction Stop
    }
    catch {
        $someerror = $false
        Write-Warning "Unable to create the Policy."
        
    }
    
    if($someerror)
    {
        Set-GPRegistryValue -Name "Disable Windows Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Type DWord -Value 1
        Set-GPRegistryValue -Name "Disable Windows Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 1                
        New-GPLink -Name "Disable Windows Defender" -Target ((Get-ADDomain).DistinguishedName)
    }

}

function New-ADLabSMBShare{
<#
.SYNOPSIS
Adds new share called hackme on the Domain controller and Share on workstation.
.DESCRIPTION
New-ADLabSMBShare configures a a share on both Domain Controller and workstation.
.EXAMPLE
 New-ADLabSMBShare
#> 
    [cmdletbinding()]
    param()
    
    if((Get-OSType) -eq 2)
    {
        try {
            $someerror = $true
            New-Item "C:\hackMe" -Type Directory -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to create hackme folder"
            
        }
        if($someerror)
        {
            try {
                New-SmbShare -Name "hackMe" -Path "C:\hackMe" -ErrorAction Stop
            }
            catch {
                Write-Warning "Unable to create Share"
            }
        }            
    }
    elseif ((Get-OSType) -eq 1) {
        try {
            $someerror = $true
            New-Item "C:\Share" -Type Directory -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to create hackme folder"
            $someerror = $false
            
        }
        if($someerror)
        {
            try {
                New-SmbShare -Name "Share" -Path "C:\Share" -ErrorAction Stop
            }
            catch {
                Write-Warning "Unable to create Share"
            }
        }    
    }
    else {
        Write-Warning "Invalid install. Exiting!!"
        exit        
    }            
}

function Add-ADLabWorkstationToDomain{
<#
.SYNOPSIS
Adds the workstation to the Domain.
.DESCRIPTION
Add-ADLabWorkstationToDomain adds the new workstation to our domain.
.EXAMPLE
 Add-ADLabWorkstationToDomain
#> 
    [cmdletbinding()]
    param()

    if((Get-OSType) -ne 1)
    {
        Write-Host "Workstation install not detected. Exiting!!" -BackgroundColor Yellow -ForegroundColor Black
        exit
    }
     
    try {
        Add-Computer -DomainName (Read-Host "Enter Domain Name") -Restart -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to Add workstation to the Domain."     
    }
    

}

$psComrade = @"


           _____     _____ ____  __  __ _____            _____  ______   __         __
     /\   |  __ \   / ____/ __ \|  \/  |  __ \     /\   |  __ \|  ____| /  \.-"""-./  \
    /  \  | |  | | | |   | |  | | \  / | |__) |   /  \  | |  | | |__    \    -   -    /
   / /\ \ | |  | | | |   | |  | | |\/| |  _  /   / /\ \ | |  | |  __|    |   o   o   |
  / ____ \| |__| | | |___| |__| | |  | | | \ \  / ____ \| |__| | |____   \  .-'''-.  /
 /_/    \_\_____/   \_____\____/|_|  |_|_|  \_\/_/    \_\_____/|______|   '-\__Y__/-'
                                                                             '---'
                                                                       

Author: @browninfosecguy
Version: 1.0

Usage: This Scirpt can be used to configure both Domain Controller and Workstation.

OPTIONS APPLICABLE TO SERVER:

Option 1: Configure friendly machine name and static IP address for the domain controller.

Option 2: Install Active Directory Domain Services role on the server and configure Primary Domian Controller. 

Option 3: Configure network share on the Domain controller and workstation.

Option 4: Create a Group policy to disable Windows Defender.

Option 5: Create user accounts on the domain controller.

OPTIONS APPLICABLE TO WORKSTATION:

Option 3: Configure network share on the Domain controller and workstation.

Option 6: Configure friendly machine name and set the DNS to IP address of Domain Controller.

Option 7: Add the wrokstation to the Domain.


"@

$psComrade

while ($true) {
    $option = Read-Host "Select an option to continue (Choose Wisely)"

switch ($option) {
    1 { Initialize-ADLabDomainController }
    2 { Install-ADLabDomainController }
    3 { New-ADLabSMBShare }
    4 { New-ADLabAVGroupPolicy }
    5 { New-ADLabDomainUser }
    6 {Initialize-ADLabWorkstation}
    7 {Add-ADLabWorkstationToDomain}
    Default {"AD Comrade does not accept wrong answers!!!"}
    
}

}