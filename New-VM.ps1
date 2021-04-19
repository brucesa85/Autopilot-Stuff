<#

    .SYNOPSIS

    .DESCRIPTION
        
    .NOTES

        Author: Bruce Sa

        Twitter: @BruceSaaaa
		
		Created: 04/19/2021

    .LINK
		
    .EXAMPLE
        .\New-VM.ps1
		
		.\New-VM.ps1 -VMName Hello-1 -Start
		
		.\New-VM.ps1 -BaseName VM_For-Work- -Start -BootFromISO -ExposeVirtualization
    .HISTORY  
		#Version 1.0 Create VMs

    
#>


Param
(
[String]$VMName,
[String]$BaseName = "GenericVM-",
[String]$VMLocation = "D:\Test1",
[String]$VMISO = "D:\ISO\SW_DVD9_Win_Pro_10_20H2.5_64BIT_English_Pro_Ent_EDU_N_MLF_X22-55724.ISO",
[String]$VMNetwork = "Default Switch",
[String]$CPUCount = "4",
[switch]$ExposeVirtualization,
[switch]$Start,
[switch]$BootFromISO
)

#Get Existing VMs and delete
if(!($VMName)){
    [array]$CurrentVms = (Get-Vm).name
    [array]$VMNames = 1..99 |%{"$BaseName{0}" -f $_}
    $VMName = (compare $CurrentVms $VMNames |select -first 1 ).inputobject
    }
    
$scriptPath = $PSScriptRoot
$VHDX = "$VMLocation\$VMName\Disk\$VMName-OSDisk.vhdx"
# Set VM Variables ***Please change the variables to match your environment.***


# Create Virtual machine

    New-VM -Name $VMName -MemoryStartupBytes 8GB -Generation 2 -SwitchName $VMNetwork -Path $VMLocation | Out-Null
    Enable-VMIntegrationService -vmName $VMName -Name "Guest Service Interface"
	New-VHD -Path $VHDX -SizeBytes 50gb -Dynamic
	Add-VMHardDiskDrive -VMName $VMName -Path $VHDX
    Set-VM $VMName -AutomaticCheckpointsEnabled $false
    Set-VMProcessor -VMName $VMName -Count $CPUCount
    Set-VMFirmware -VMName $VMName -EnableSecureBoot On
    $owner = Get-HgsGuardian UntrustedGuardian -ErrorAction SilentlyContinue
    If (!$owner) {
        # Creating new UntrustedGuardian since it did not exist
        $owner = New-HgsGuardian -Name UntrustedGuardian -GenerateCertificates
    }
    $kp = New-HgsKeyProtector -Owner $owner -AllowUntrustedRoot
    Set-VMKeyProtector -VMName $VMName -KeyProtector $kp.RawData
    Enable-VMTPM -VMName $VMName
    #Start-VM -Name $VMName
    #Set VM Info with Serial number
    $vmSerial = (Get-CimInstance -Namespace root\virtualization\v2 -class Msvm_VirtualSystemSettingData | Where-Object { ($_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized") -and ($_.elementname -eq $VMName )}).BIOSSerialNumber
    Get-VM -Name $VMname | Set-VM -Notes "Serial# $vmSerial"

# Boot Device
if ($BootFromISO)
{   
    Add-VMDvdDrive -VMName $VMName -Path $VMISO
    # Set DVD drive boot first
    $DVD = Get-VMDVDDrive -VMName $VMName
    Set-VMFirmware -VMName $VMName -FirstBootDevice $DVD
}

# Expose Virtualization
if ($ExposeVirtualization)
{   
    Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true
}

if ($Start)
{
# Start Virtual Machine
Start-VM -VMName $VMName

# Open Virtual Machine Console
VMConnect localhost $VMName
}