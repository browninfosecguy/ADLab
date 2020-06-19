#Requires -RunAsAdministrator 

$osType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

function Initialize-DCSetUp{
    [CmdletBinding()]
   
    param(
        [Parameter(Mandatory=$true)]
        [string]$forestName
        )


    Begin{
            if($osType -eq 3)
            {
                Write-Host "Server install detected. Initializing Domain Controller configuration"
                
            }else {
                Write-Host "This cmdlet should be run on Server. Exiting"
                exit
                
            }       
        }
    Process{

        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

        Install-ADDSForest -DomainName $forestName -InstallDNS
    
    }
    End{}

       
}

function Initialize-WorkstationSetup{
    [CmdletBinding()]
   
    param(
        [Parameter(Mandatory=$true)]
        [string]$forestName,

        [Parameter(Mandatory=$true)]
        [string]$computerName
    )

    Begin{
            Write-Host $osType
            if($osType -eq 1)
            {
                Write-Host "Workstation install detected. Initializing Workstation setup"
                
            }else {
                Write-Host "This cmdlet should be run on Workstation. Exiting"
                exit
                
            }   

    }
    Process{
        Write-Host "CAT"
    }
    End{}


}

function Set-DCPreConfig{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)]
    [string]$newComputerName

    )
    Begin{
        if($osType -eq 3)
            {
                Write-Host "Server install detected. Initializing Domain Controller configuration"
                
            }else {
                Write-Host "This cmdlet should be run on Server. Exiting"
                exit
                
            }  
    }
    Process{
        
        Rename-Computer -NewName $newComputerName -PassThru

        $netInterface = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPv4Address,InterfaceIndex 

        $netInterface

        $selection = Read-Host "Select the InterfaceIndex for Primary Domain Controller"

        $ipAddress = Read-Host "Enter the IP Address to assing to the interface"
        $prefixLength = Read-Host "Enter Subnet Mask (For example enter 24 for Subnet mask 255.255.255.0)"
        $defaultGateway = Read-Host "Enter Default gateway"

        Set-ItemProperty -Path “HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\$((Get-NetAdapter -InterfaceIndex $selection).InterfaceGuid)” -Name EnableDHCP -Value 0
        Remove-NetIpAddress -InterfaceIndex $selection -AddressFamily IPv4
        Remove-NetRoute -InterfaceIndex $selection -AddressFamily IPv4 -Confirm:$false
        New-NetIpAddress -InterfaceIndex $selection -IpAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $defaultGateway -AddressFamily IPv4
        Set-DnsClientServerAddress -InterfaceIndex $selection -ServerAddresses $ipAddress
        
        
        #New-NetIPAddress -InterfaceIndex $selection -IPAddress $ipAddress -DefaultGateway $defaultGateway -PrefixLength $prefixLength -ValidLifetime $true

        }
   
    End{Write-Host "Restart the Machine for changes to take effect"}


}

function Set-WorkstationPreConfig{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)]
    [string]$newComputerName

    )
    Begin{
        Write-Host "Changing Name of the Computer."
        Write-Host $osType
            if($osType -eq 1)
            {
                Write-Host "Workstation install detected. Initializing Workstation setup"
                
            }else {
                Write-Host "This cmdlet should be run on Workstation. Exiting"
                exit
                
            }   
    }
    
    Process{
        
        Rename-Computer -NewName $newComputerName -PassThru

        $netInterface = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPv4Address,InterfaceIndex 

        $netInterface

        $selection = Read-Host "Select the InterfaceIndex for Workstation"

        $dcIPAddress = Read-Host "Enter the IP Address of Domain Controller"
        
        
        Set-DnsClientServerAddress -InterfaceIndex $selection -ServerAddresses ($dcIPAddress) 

        }

    End{Write-Host "Restart the Machine for changes to take effect"}


}

function Initialize-UserCreation{
    [cmdletbinding()]
    param()

    if($osType -eq 2)
    {
        Write-Host "Domain Controller detected. Initalizing new user account creation"
                
    }else {
        Write-Host "This cmdlet should be run on Domain Controller. Exiting"
        exit
                
            }  
    
            #Add 3 Users Sarah Conner, Kyle Reese and John Conner. All with password "Password1"
    New-ADUser -Name "Sarah Conner" -GivenName "Sarah" -Surname "Conner" -SamAccountName "sconner" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true

    New-ADUser -Name "Kyle Reese" -GivenName "Kyle" -Surname "Reese" -SamAccountName "kreese" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true

    New-ADUser -Name "John Conner" -GivenName "John" -Surname "Conner" -SamAccountName "jconner" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true 

    #Add Kyle Reese to Domain Admins Group
    Add-ADGroupMember -Identity "Domain Admins" -Members "kreese"

}

function Initialize-GroupPolicy{
    [cmdletbinding()]
    param()

    begin{

            if($osType -eq 2)
            {
                Write-Host "Domain Controller detected. Initalizing Group Policy creation"
                        
            }else {
                Write-Host "This cmdlet should be run on Domain Controller. Exiting"
                exit

            }
        }
        
        Process{

            New-GPO -Name "Disable Windows Defender" -Comment "This policy disables windows defender"

            Set-GPRegistryValue -Name "Disable Windows Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Type DWord -Value 1

            Set-GPRegistryValue -Name "Disable Windows Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 1

            
        }
        
        end{}
                    
    }

    function Initialize-SMBShare{
        [cmdletbinding()]
        param()
    
        begin{
    
                if($osType -eq 2)
                {
                    Write-Host "Domain Controller detected. Initalizing SMB Share creation"
                            
                }else {
                    Write-Host "This cmdlet should be run on Domain Controller. Exiting"
                    exit
    
                }
            }
            
            Process{
    
                New-Item "C:\Share\hackMe" -Type Directory
    
                New-SmbShare -Name "hackMe" -Path "C:\Share\hackMe" -FullAccess "COVID\Domain Users"
                
            }
            
            end{}
                        
        }


        function Initialize-DomainJoin{
            [cmdletbinding()]
            param()

            Write-Host $osType
            if($osType -eq 1)
            {
                Write-Host "Workstation install detected. Joining Domain"
                
            }else {
                Write-Host "This cmdlet should be run on Workstation. Exiting"
                exit
                
            }   

            Add-Computer -DomainName (Read-Host "Enter Domain Name") -Credential covid\Administrator -Restart -Force
            


        }