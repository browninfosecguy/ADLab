#Requires -RunAsAdministrator 

$osType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

if($osType -eq 3)
{
    Write-Host "Server install detected. Initializing Domain Controller configuration"
    
}
elseif ($osType -eq 1) {

    Write-Host "Workstation install detected. Initializing workstation configuration"
}
else {
    
    Write-Host "Fatal Error. Cannot Proceed."
}


function Initialize-DomainController{
    [CmdletBinding()]
   
    param(
        [Parameter(Mandatory=$true)]
        [string]$forestName

        



    )

    Begin{Write-Host "Starting Domain Controller Configuration."}
    Process{
        
    }
    End{}

       
}

function Initialize-Workstation{
    [CmdletBinding()]
   
    param(
        [Parameter(Mandatory=$true)]
        [string]$forestName,

        [Parameter(Mandatory=$true)]
        [string]$computerName



    )

    Begin{}
    Process{}
    End{}


}

function Set-PreConfig{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)]
    [string]$newComputerName

    )
    Begin{Write-Host "Changing Name of the Computer."}
    Process{
        
        Rename-Computer -NewName $newComputerName -PassThru

        $netInterface = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPv4Address,InterfaceIndex 

        $netInterface

        $selection = Read-Host "Select the InterfaceIndex for Primary Domain Controller"

        $ipAddress = Read-Host "Enter the IP Address to assing to the interface"
        $prefixLength = Read-Host "Enter Subnet Mask (For example enter 24 for Subnet mask 255.255.255.0)"
        $defaultGateway = Read-Host "Enter Default gateway"
        
        
        New-NetIPAddress -InterfaceIndex $selection -IPAddress $ipAddress -DefaultGateway $defaultGateway -PrefixLength $prefixLength

        }



    
    End{}


}