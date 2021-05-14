[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Try{
If(!(Get-PackageProvider -Name NuGet)) {Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force}
If(!(Get-Module -Name Microsoft.Graph.Intune)) {Install-Module -Name Microsoft.Graph.Intune -Force}
}
Catch
{
	#Write-LogEntry -Message "$Error[0]" -Severity 3 @LogParams
	Write-Warning $_
	Exit 1
}

Connect-MSGraph

$AppID = Get-IntuneMobileApp | Where-Object {"$_.@odata.type" -match "microsoft.graph.win32LobApp"} | Select-Object DisplayName,ID | Out-GridView -OutputMode Single -Title "Please select the correct application name"

$ID = $AppID.id + "_1"

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID\ComplianceStateMessage") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID\ComplianceStateMessage" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID\EnforcementStateMessage") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID\EnforcementStateMessage" -force -ea SilentlyContinue };
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID" -Name 'LastUpdatedTimeUtc' -Value '11/05/2021 10:55:30' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID" -Name 'Intent' -Value '3' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID" -Name 'ResultCreatedTimeUTC' -Value '11/05/2021 10:44:44' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID" -Name 'DownloadStartTimeUTC' -Value '01/01/0001 00:00:00' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID" -Name 'RebootStatus' -Value 'Clean' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID" -Name 'RebootReason' -Value 'None' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID" -Name 'RebootSetTimeUTC' -Value '01/01/0001 00:00:00' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID" -Name 'Ack' -Value 'True' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID\ComplianceStateMessage" -Name 'ComplianceStateMessage' -Value '{\"Applicability\":1008,\"ComplianceState\":2,\"DesiredState\":2,\"ErrorCode\":null,\"TargetingMethod\":0,\"InstallContext\":2,\"TargetType\":1,\"ProductVersion\":null,\"AssignmentFilterIds\":null}' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\1180e2b2-fd37-46bc-aedf-15e8db5bbec7\$ID\EnforcementStateMessage" -Name 'EnforcementStateMessage' -Value '{\"EnforcementState\":3000,\"ErrorCode\":null,\"TargetingMethod\":0}' -PropertyType String -Force -ea SilentlyContinue;

Restart-Service -Name IntuneManagementExtension -Force