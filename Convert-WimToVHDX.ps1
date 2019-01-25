<#

    .SYNOPSIS

    .DESCRIPTION
        
    .NOTES

        Author: Bruce Sa

        Twitter: @BruceSaaaa
		
		Created: 12/11/2018

    .LINK
        
    .EXAMPLE
        
    .HISTORY         
    
#>

Param
(
    [Parameter(Position=0, HelpMessage="Operating System Name to be serviced.")]
    [ValidateSet("Enterprise","Professional","1")]
    [string]$OSEdition="Enterprise",
    [String]$vhdxName,
    [String]$SourcePath="D:\Setup\OSBuilder\OSMedia\Windows 10 Enterprise x64 1809 17763.253\OS\sources\install.wim",
    [String]$vhdxPath="C:\Setup\VHDs\"
)
# Install Convert-WindowsImage module 
If(!(Get-Module -Name Convert-WindowsImage)) {
    Install-Module -Name Convert-WindowsImage -Scope AllUsers -Force
}

Import-Module -Name Convert-WindowsImage -Force

If(Test-Path -Path $SourcePath) {
    Convert-WindowsImage -SourcePath $SourcePath -Edition $OSEdition -VhdType Dynamic -VhdFormat VHDX -VhdPath "$($vhdxPath)$($vhdxName).vhdx" -DiskLayout UEFI
}
Else {
    Write-Error "No ISO Found!"
    break;
}