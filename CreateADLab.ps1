#Requires -RunAsAdministrator 

$osType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

function Install-DomainController{
    [CmdletBinding()]
   
    param(
        [Parameter(Mandatory=$true)]
        [string]$forestName
        )

        if($osType -ne 3)
        {
            Write-Verbose "Server Install not detected. Exiting!!"
            exit
        }

        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

        Install-ADDSForest -DomainName $forestName -InstallDNS
}

function Initialize-DomainController{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)]
    [string]$newComputerName

    )

    if($osType -ne 3)
    {
        Write-Verbose "Server Install not detected. Exiting!!"
        exit
    }
    
        
    Rename-Computer -NewName $newComputerName -PassThru

    $netInterface = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPv4Address,InterfaceIndex 

    Write-Host $netInterface

    $selection = Read-Host "Select the InterfaceIndex for Primary Domain Controller"

    $ipAddress = Read-Host "Enter the IP Address to assing to the interface"
    $prefixLength = Read-Host "Enter Subnet Mask (For example enter 24 for Subnet mask 255.255.255.0)"
    $defaultGateway = Read-Host "Enter Default gateway"

    Remove-NetIpAddress -InterfaceIndex $selection -AddressFamily IPv4
    Remove-NetRoute -InterfaceIndex $selection -AddressFamily IPv4 -Confirm:$false
    New-NetIpAddress -InterfaceIndex $selection -IpAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $defaultGateway -AddressFamily IPv4
    Set-DnsClientServerAddress -InterfaceIndex $selection -ServerAddresses $ipAddress

}

function Initialize-Workstation{
    
    [CmdletBinding()]
    
    Param(
    [Parameter(Mandatory=$true)]
    [string]$newComputerName
    )
    
    if($osType -ne 1)
    {
        Write-Host "Workstation install not detected. Exiting!!"
        exit
    }
    
    Rename-Computer -NewName $newComputerName -PassThru

    $netInterface = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPv4Address,InterfaceIndex 
    Write-Host $netInterface
    $selection = Read-Host "Select the InterfaceIndex for Workstation"
    $dcIPAddress = Read-Host "Enter the IP Address of Domain Controller"
    Set-DnsClientServerAddress -InterfaceIndex $selection -ServerAddresses ($dcIPAddress) 

}

function New-DomainUser{
    [cmdletbinding()]
    param()

    if($osType -ne 2)
    {
        Write-Host "Domain Controller not detected. Exiting!!"
        exit
                
    }
    
    #Add 3 Users Sarah Conner, Kyle Reese and John Conner. All with password "Password1"
    New-ADUser -Name "Sarah Conner" -GivenName "Sarah" -Surname "Conner" -SamAccountName "sconner" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
    New-ADUser -Name "Kyle Reese" -GivenName "Kyle" -Surname "Reese" -SamAccountName "kreese" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
    New-ADUser -Name "John Conner" -GivenName "John" -Surname "Conner" -SamAccountName "jconner" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true 

    #Add Kyle Reese to Domain Admins Group
    Add-ADGroupMember -Identity "Domain Admins" -Members "kreese"

}

function New-GroupPolicy{
    [cmdletbinding()]
    param()

    if($osType -ne 2)
    {
        Write-Host "Domain Controller not detected. Exiting!!"
        exit
                
    }
    
    New-GPO -Name "Disable Windows Defender" -Comment "This policy disables windows defender"
    Set-GPRegistryValue -Name "Disable Windows Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Type DWord -Value 1
    Set-GPRegistryValue -Name "Disable Windows Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 1
                
}

function New-SMBShare{

    [cmdletbinding()]
    param()
    
    if($osType -eq 2)
    {
        New-Item "C:\Share\hackMe" -Type Directory
        New-SmbShare -Name "hackMe" -Path "C:\Share\hackMe" -FullAccess "COVID\Domain Users"
        
                
    }
    elseif ($osType -eq 1) {
        New-Item "C:\Share" -Type Directory
        New-SmbShare -Name "Share" -Path "C:\Share" -FullAccess "COVID\Domain Users"
        
    }
    else {
        Write-Host "Invalid install. Exiting!!"
        exit
        
    }
                        
}

function Add-WorkstationToDomain{

    [cmdletbinding()]
    param()

    if($osType -ne 1)
    {
        Write-Host "Workstation install not detected. Exiting!!"
        exit
    }
            
    Add-Computer -DomainName (Read-Host "Enter Domain Name") -Credential covid\Administrator -Restart -Force

}