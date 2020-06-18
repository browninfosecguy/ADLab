#Requires -RunAsAdministrator 

$osType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

if($osType -eq 3)
{
    Write-Host "Server install detected. Initializing Domain Controller configuration"
    Initialize-DomainController
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
        [string]$forestName,

        [Parameter(Mandatory=$true)]
        [string]$computerName



    )

    Begin{Write-Host "Starting Domain Controller Configuration."}
    Process{}
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