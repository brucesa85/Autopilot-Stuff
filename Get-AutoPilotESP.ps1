<#
.SYNOPSIS
    Get AutoPilot ESP logs from a VM
.DESCRIPTION
    This script will connect to your Hyper-V VM and read the ESP logs
.PARAMETER VM
    Line 22 Set your VM names in the $VM variable set 
.NOTES
	Version: 1.0
	Author: Bruce Sa
	Twitter: @BruceSaaaa
	Creation date: 03-04-202020
.LINK
    https://github.com/brucesa85/AutoPilot
.EXAMPLE
    .\Get-AutoPilotESP.ps1 -VM AutoPilotVM-1
#>

Param
(
[String]$User = "azuread\YOUR UPN",
[Parameter(Mandatory=$true)][String][ValidateSet('AutoPilotVM-1','AutoPilotVM-2')]$VM
)
$session = New-PSSession -vmname $VM -Credential $User
Invoke-Command -Session $Session -ScriptBlock {Set-ExecutionPolicy bypass -force}
Invoke-Command -Session $Session -ScriptBlock {Install-PackageProvider -Name Nuget -MinimumVersion 2.8.5.201 -Force}
Invoke-Command -Session $Session -ScriptBlock {Install-Script Get-AutopilotESPStatus -force}
Invoke-Command -Session $Session -ScriptBlock {if (!(Get-InstalledModule -Name "Microsoft.Graph.Intune")){Install-Module -Name MSGraph -Force}}
Invoke-Command -Session $Session -ScriptBlock {Connect-MSGraph -ForceNonInteractive}
Invoke-Command -Session $Session -ScriptBlock {Get-AutopilotESPStatus -Online}
$Session | Remove-PSSession