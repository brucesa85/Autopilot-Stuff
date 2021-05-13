$File = "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\layoutmodification.xml"
	if (test-path -Path $File) {
    Remove-Item -Path $File -Force
    }Else{
		Write-Host "Installed"
	}