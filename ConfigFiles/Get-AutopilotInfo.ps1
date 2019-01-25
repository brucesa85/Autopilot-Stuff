Set-ExecutionPolicy Bypass -Force
Install-PackageProvider -Name Nuget -MinimumVersion 2.8.5.201 -Force
Install-Module AzureAD -Force
Install-Script -Name Get-WindowsAutoPilotInfo -Force
Install-Module  windowsautopilotintune -Force
Connect-AutoPilotIntune
If (!(Test-Path "C:\Windows\Provisioning\Autopilot")){ New-Item -ItemType Directory -Path "C:\Windows\Provisioning\Autopilot" }
Get-WindowsAutoPilotInfo.ps1 -OutputFile C:\Windows\Provisioning\Autopilot\Info.csv
Import-AutoPilotCSV C:\Windows\Provisioning\Autopilot\Info.csv
Invoke-AutopilotSync