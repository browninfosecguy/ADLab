#Requires -RunAsAdministrator 

$osType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

function Install-ADLabDomainController{
    [CmdletBinding()]
   
    param(
        [Parameter(Mandatory=$true)]
        [string]$ForestName
        )

        if($osType -ne 3)
        {
            Write-Verbose "Server Install not detected. Exiting!!"
            exit
        }

        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

        Install-ADDSForest -DomainName $ForestName -InstallDNS -SafeModeAdministratorPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force)

        
}

function Initialize-ADLabDomainController{
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

    $netInterface

    $selection = Read-Host "Select the InterfaceIndex for Primary Domain Controller"

    $ipAddress = Read-Host "Enter the IP Address to assing to the interface"
    $prefixLength = Read-Host "Enter Subnet Mask (For example enter 24 for Subnet mask 255.255.255.0)"
    $defaultGateway = Read-Host "Enter Default gateway"

    Remove-NetIpAddress -InterfaceIndex $selection -AddressFamily IPv4
    Remove-NetRoute -InterfaceIndex $selection -AddressFamily IPv4 -Confirm:$false
    New-NetIpAddress -InterfaceIndex $selection -IpAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $defaultGateway -AddressFamily IPv4
    Set-DnsClientServerAddress -InterfaceIndex $selection -ServerAddresses $ipAddress

    Write-Host "Restart the Machine before continuing with rest of the setup" -BackgroundColor Yellow -ForegroundColor Black

}

function Initialize-ADLabWorkstation{
    
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
    $netInterface
    $selection = Read-Host "Select the InterfaceIndex for Workstation"
    $dcIPAddress = Read-Host "Enter the IP Address of Domain Controller"
    Set-DnsClientServerAddress -InterfaceIndex $selection -ServerAddresses ($dcIPAddress) 

    Write-Host "Restart the Machine before continuing with rest of the setup" -BackgroundColor Yellow -ForegroundColor Black
}

function New-ADLabDomainUser{
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

function New-ADLabAVGroupPolicy{
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

function New-ADLabSMBShare{

    [cmdletbinding()]
    param()
    
    if($osType -eq 2)
    {
        New-Item "C:\hackMe" -Type Directory
        New-SmbShare -Name "hackMe" -Path "C:\hackMe"
        
                
    }
    elseif ($osType -eq 1) {
        New-Item "C:\Share" -Type Directory
        New-SmbShare -Name "Share" -Path "C:\Share"
        
    }
    else {
        Write-Host "Invalid install. Exiting!!"
        exit
        
    }
                        
}

function Add-ADLabWorkstationToDomain{

    [cmdletbinding()]
    param()

    if($osType -ne 1)
    {
        Write-Host "Workstation install not detected. Exiting!!"
        exit
    }
            
    Add-Computer -DomainName (Read-Host "Enter Domain Name") -Restart -Force

}