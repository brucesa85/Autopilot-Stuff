    <#
        .SYNOPSIS
            Enables/Disables Windows features
        .DESCRIPTION
			Enables/Disables Windows features. The feature name has to be spelled exactly as it is in Windows

        .NOTES
            Author:      Yannick Van Landeghem
            Contact:     Yannick, Bruce Sa
            Created:     2021-04-13
            Updated:     2020-04-13
    #>
param (
	$AppName = "Linux Subsystem",
	#Enter the exact Windows optional feature name
	$FeatureName = "Microsoft-Windows-Subsystem-Linux",
	#Action can be either 'enable' or 'disable'
	$Action = "Enable",
	#Don't forget to adjust the Appname and Action in the toast notification, line 694/695
	[bool]$Remediate = $true
)

Function Write-LogEntry
{
    <#
        .SYNOPSIS
            Write to a log file in the CMTrace Format
        .DESCRIPTION
            The function is used to write to a log file in a CMTrace compatible format. This ensures that CMTrace or OneTrace can parse the log
            and provide data in a familiar format.
        .PARAMETER Value
            String to be added it to the log file as the message, or value
        .PARAMETER Severity
            Severity for the log entry. 1 for Informational, 2 for Warning, and 3 for Error.
        .PARAMETER Component
            Stage that the log entry is occuring in, log refers to as 'component.'
        .PARAMETER FileName
            Name of the log file that the entry will written to - note this should not be the full path.
        .PARAMETER Folder
            Path to the folder where the log will be stored.
        .PARAMETER Bias
            Set timezone Bias to ensure timestamps are accurate. This defaults to the local machines bias, but one can be provided. It can be
            helperful to gather the bias once, and store it in a variable that is passed to this parameter as part of a splat, or $PSDefaultParameterValues
        .PARAMETER MaxLogFileSize
            Maximum size of log file before it rolls over. Set to 0 to disable log rotation. Defaults to 5MB
        .PARAMETER LogsToKeep
            Maximum number of rotated log files to keep. Set to 0 for unlimited rotated log files. Defaults to 0.
        .EXAMPLE
            C:\PS> Write-LogEntry -Value 'Testing Function' -Component 'Test Script' -FileName 'LogTest.Log' -Folder 'c:\temp'
                Write out 'Testing Function' to the c:\temp\LogTest.Log file in a CMTrace format, noting 'Test Script' as the component.
        .NOTES
            FileName:    Write-LogEntry.ps1
            Author:      Cody Mathis, Adam Cook
            Contact:     @CodyMathis123, @codaamok
            Created:     2020-01-23
            Updated:     2020-01-23
    #>
	param (
		[parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('Message', 'ToLog')]
		[string[]]$Value,
		[parameter(Mandatory = $false)]
		[ValidateSet(1, 2, 3)]
		[int]$Severity = 1,
		[parameter(Mandatory = $false)]
		[string]$Component = [string]::Format("Autopilot-{0}:{1}", $Purpose, $($MyInvocation.ScriptLineNumber)),
		[parameter(Mandatory = $true)]
		[string]$FileName,
		[parameter(Mandatory = $true)]
		[string]$Folder,
		[parameter(Mandatory = $false)]
		[int]$Bias = (Get-CimInstance -Query "SELECT Bias FROM Win32_TimeZone").Bias,
		[parameter(Mandatory = $false)]
		[int]$MaxLogFileSize = 5MB,
		[parameter(Mandatory = $false)]
		[int]$LogsToKeep = 0
	)
	begin
	{
		# Determine log file location
		$LogFilePath = Join-Path -Path $Folder -ChildPath $FileName
		
		#region log rollover check if $MaxLogFileSize is greater than 0
		switch (([System.IO.FileInfo]$LogFilePath).Exists -and $MaxLogFileSize -gt 0)
		{
			$true {
				#region rename current file if $MaxLogFileSize exceeded, respecting $LogsToKeep
				switch (([System.IO.FileInfo]$LogFilePath).Length -ge $MaxLogFileSize)
				{
					$true {
						# Get log file name without extension
						$LogFileNameWithoutExt = $FileName -replace ([System.IO.Path]::GetExtension($FileName))
						
						# Get already rolled over logs
						$AllLogs = Get-ChildItem -Path $Folder -Name "$($LogFileNameWithoutExt)_*" -File
						
						# Sort them numerically (so the oldest is first in the list)
						$AllLogs = Sort-Object -InputObject $AllLogs -Descending -Property { $_ -replace '_\d+\.lo_$' }, { [int]($_ -replace '^.+\d_|\.lo_$') } -ErrorAction Ignore
						
						foreach ($Log in $AllLogs)
						{
							# Get log number
							$LogFileNumber = [int][Regex]::Matches($Log, "_([0-9]+)\.lo_$").Groups[1].Value
							switch (($LogFileNumber -eq $LogsToKeep) -and ($LogsToKeep -ne 0))
							{
								$true {
									# Delete log if it breaches $LogsToKeep parameter value
									[System.IO.File]::Delete("$($Folder)\$($Log)")
								}
								$false {
									# Rename log to +1
									$NewFileName = $Log -replace "_([0-9]+)\.lo_$", "_$($LogFileNumber + 1).lo_"
									[System.IO.File]::Copy("$($Folder)\$($Log)", "$($Folder)\$($NewFileName)", $true)
								}
							}
						}
						
						# Copy main log to _1.lo_
						[System.IO.File]::Copy($LogFilePath, "$($Folder)\$($LogFileNameWithoutExt)_1.lo_", $true)
						
						# Blank the main log
						$StreamWriter = New-Object -TypeName System.IO.StreamWriter -ArgumentList $LogFilePath, $false
						$StreamWriter.Close()
					}
				}
				#endregion rename current file if $MaxLogFileSize exceeded, respecting $LogsToKeep
			}
		}
		#endregion log rollover check if $MaxLogFileSize is greater than 0
		
		# Construct date for log entry
		$Date = (Get-Date -Format 'MM-dd-yyyy')
		
		# Construct context for log entry
		$Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	}
	process
	{
		foreach ($MSG in $Value)
		{
			#region construct time stamp for log entry based on $Bias and current time
			$Time = switch -regex ($Bias)
			{
				'-' {
					[string]::Concat($(Get-Date -Format 'HH:mm:ss.fff'), $Bias)
				}
				Default
				{
					[string]::Concat($(Get-Date -Format 'HH:mm:ss.fff'), '+', $Bias)
				}
			}
			#endregion construct time stamp for log entry based on $Bias and current time
			
			#region construct the log entry according to CMTrace format
			$LogText = [string]::Format('<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="">', $MSG, $Time, $Date, $Component, $Context, $Severity, $PID)
			#endregion construct the log entry according to CMTrace format
			
			#region add value to log file
			try
			{
				$StreamWriter = New-Object -TypeName System.IO.StreamWriter -ArgumentList $LogFilePath, 'Append'
				$StreamWriter.WriteLine($LogText)
				$StreamWriter.Close()
			}
			catch [System.Exception] {
				try
				{
					$LogText | Out-File -FilePath $LogFilePath -Append -ErrorAction Stop
				}
				catch
				{
					Write-Warning -Message "Unable to append log entry to $FileName file. Error message: $($_.Exception.Message)"
				}
			}
			#endregion add value to log file
		}
	}
}

#Set variables#
# Script version that will be noted in log files
$ScriptVersion = '1.0'
$Client = "NTT"
$FileName = "AutoPilot-ProActiveRemediation"

#region Logging Parameters
If ($Remediate -eq $false)
{
	$Purpose = "detection"
}
Else
{
	$Purpose = "remediation"
}
$LogPath = "$env:ProgramData\$Client\Logs"
if (!(Test-Path $logPath -ErrorAction SilentlyContinue)) {
    New-Item $LogPath -ItemType Directory -Force | Out-Null
}
$LogFileName = "$FileName`.log"
$LogParams = @{
	FileName = $LogFileName
	Folder   = $LogPath
	Bias	 = (Get-WmiObject -Query "SELECT Bias FROM Win32_TimeZone").Bias
	MaxLogFileSize = 2mb
	LogsToKeep = 1
}
#endregion

#region Proxy function for logging
# #Write-Verbose
$WriteVerboseMetadata = New-Object System.Management.Automation.CommandMetadata (Get-Command Write-Verbose)
$WriteVerboseBinding = [System.Management.Automation.ProxyCommand]::GetCmdletBindingAttribute($WriteVerboseMetadata)
$WriteVerboseParams = [System.Management.Automation.ProxyCommand]::GetParamBlock($WriteVerboseMetadata)
$WriteVerboseWrapped = {
	Microsoft.PowerShell.Utility\Write-Verbose @PSBoundParameters; switch ($VerbosePreference)
	{
		'Continue' {
			Write-LogEntry -Message $Message @LogParams
		}
	}
}
${Function:Write-Verbose} = [string]::Format('{0}param({1}) {2}', $WriteVerboseBinding, $WriteVerboseParams, $WriteVerboseWrapped)
#endregion proxy function for logging

#region typeclasses
$script:source = @"
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace RunAsUser
{
    internal class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }
    }

    internal class NativeMethods
    {
        [DllImport("kernel32", SetLastError=true)]
        public static extern int WaitForSingleObject(
          IntPtr hHandle,
          int dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(
            IntPtr hSnapshot);

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(
            ref IntPtr lpEnvironment,
            SafeHandle hToken,
            bool bInherit);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUserW(
            SafeHandle hToken,
            String lpApplicationName,
            StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref NativeHelpers.STARTUPINFO lpStartupInfo,
            out NativeHelpers.PROCESS_INFORMATION lpProcessInformation);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyEnvironmentBlock(
            IntPtr lpEnvironment);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            SafeHandle ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out SafeNativeHandle DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            SafeHandle TokenHandle,
            uint TokenInformationClass,
            SafeMemoryBuffer TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(
            IntPtr pMemory);

        [DllImport("kernel32.dll")]
        public static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(
            uint SessionId,
            out SafeNativeHandle phToken);
    }

    internal class SafeMemoryBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeMemoryBuffer(int cb) : base(true)
        {
            base.SetHandle(Marshal.AllocHGlobal(cb));
        }
        public SafeMemoryBuffer(IntPtr handle) : base(true)
        {
            base.SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeNativeHandle() : base(true) { }
        public SafeNativeHandle(IntPtr handle) : base(true) { this.handle = handle; }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(handle);
        }
    }

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3,
    }

    internal enum SW
    {
        SW_HIDE = 0,
        SW_SHOWNORMAL = 1,
        SW_NORMAL = 1,
        SW_SHOWMINIMIZED = 2,
        SW_SHOWMAXIMIZED = 3,
        SW_MAXIMIZE = 3,
        SW_SHOWNOACTIVATE = 4,
        SW_SHOW = 5,
        SW_MINIMIZE = 6,
        SW_SHOWMINNOACTIVE = 7,
        SW_SHOWNA = 8,
        SW_RESTORE = 9,
        SW_SHOWDEFAULT = 10,
        SW_MAX = 10
    }

    internal enum TokenElevationType
    {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited,
    }

    internal enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation = 2
    }

    internal enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive,
        WTSConnected,
        WTSConnectQuery,
        WTSShadow,
        WTSDisconnected,
        WTSIdle,
        WTSListen,
        WTSReset,
        WTSDown,
        WTSInit
    }

    public class Win32Exception : System.ComponentModel.Win32Exception
    {
        private string _msg;

        public Win32Exception(string message) : this(Marshal.GetLastWin32Error(), message) { }
        public Win32Exception(int errorCode, string message) : base(errorCode)
        {
            _msg = String.Format("{0} ({1}, Win32ErrorCode {2} - 0x{2:X8})", message, base.Message, errorCode);
        }

        public override string Message { get { return _msg; } }
        public static explicit operator Win32Exception(string message) { return new Win32Exception(message); }
    }

    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        #endregion

        // Gets the user token from the currently active session
        private static SafeNativeHandle GetSessionUserToken()
        {
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            // Get a handle to the user access token for the current active session.
            if (NativeMethods.WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount))
            {
                try
                {
                    var arrayElementSize = Marshal.SizeOf(typeof(NativeHelpers.WTS_SESSION_INFO));
                    var current = pSessionInfo;

                    for (var i = 0; i < sessionCount; i++)
                    {
                        var si = (NativeHelpers.WTS_SESSION_INFO)Marshal.PtrToStructure(
                            current, typeof(NativeHelpers.WTS_SESSION_INFO));
                        current = IntPtr.Add(current, arrayElementSize);

                        if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                        {
                            activeSessionId = si.SessionID;
                            break;
                        }
                    }
                }
                finally
                {
                    NativeMethods.WTSFreeMemory(pSessionInfo);
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = NativeMethods.WTSGetActiveConsoleSessionId();
            }

            SafeNativeHandle hImpersonationToken;
            if (!NativeMethods.WTSQueryUserToken(activeSessionId, out hImpersonationToken))
            {
                throw new Win32Exception("WTSQueryUserToken failed to get access token.");
            }

            using (hImpersonationToken)
            {
                // First see if the token is the full token or not. If it is a limited token we need to get the
                // linked (full/elevated token) and use that for the CreateProcess task. If it is already the full or
                // default token then we already have the best token possible.
                TokenElevationType elevationType = GetTokenElevationType(hImpersonationToken);

                if (elevationType == TokenElevationType.TokenElevationTypeLimited)
                {
                    using (var linkedToken = GetTokenLinkedToken(hImpersonationToken))
                        return DuplicateTokenAsPrimary(linkedToken);
                }
                else
                {
                    return DuplicateTokenAsPrimary(hImpersonationToken);
                }
            }
        }

        public static int StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true,int wait = -1)
        {
            using (var hUserToken = GetSessionUserToken())
            {
                var startInfo = new NativeHelpers.STARTUPINFO();
                startInfo.cb = Marshal.SizeOf(startInfo);

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                //startInfo.lpDesktop = "winsta0\\default";

                IntPtr pEnv = IntPtr.Zero;
                if (!NativeMethods.CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Win32Exception("CreateEnvironmentBlock failed.");
                }
                try
                {
                    StringBuilder commandLine = new StringBuilder(cmdLine);
                    var procInfo = new NativeHelpers.PROCESS_INFORMATION();

                    if (!NativeMethods.CreateProcessAsUserW(hUserToken,
                        appPath, // Application Name
                        commandLine, // Command Line
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        dwCreationFlags,
                        pEnv,
                        workDir, // Working directory
                        ref startInfo,
                        out procInfo))
                    {
                        throw new Win32Exception("CreateProcessAsUser failed.");
                    }

                    try
                    {
                        NativeMethods.WaitForSingleObject( procInfo.hProcess, wait);
                        return procInfo.dwProcessId;
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(procInfo.hThread);
                        NativeMethods.CloseHandle(procInfo.hProcess);
                    }
                }
                finally
                {
                    NativeMethods.DestroyEnvironmentBlock(pEnv);
                }
            }
        }

        private static SafeNativeHandle DuplicateTokenAsPrimary(SafeHandle hToken)
        {
            SafeNativeHandle pDupToken;
            if (!NativeMethods.DuplicateTokenEx(hToken, 0, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenPrimary, out pDupToken))
            {
                throw new Win32Exception("DuplicateTokenEx failed.");
            }

            return pDupToken;
        }

        private static TokenElevationType GetTokenElevationType(SafeHandle hToken)
        {
            using (SafeMemoryBuffer tokenInfo = GetTokenInformation(hToken, 18))
            {
                return (TokenElevationType)Marshal.ReadInt32(tokenInfo.DangerousGetHandle());
            }
        }

        private static SafeNativeHandle GetTokenLinkedToken(SafeHandle hToken)
        {
            using (SafeMemoryBuffer tokenInfo = GetTokenInformation(hToken, 19))
            {
                return new SafeNativeHandle(Marshal.ReadIntPtr(tokenInfo.DangerousGetHandle()));
            }
        }

        private static SafeMemoryBuffer GetTokenInformation(SafeHandle hToken, uint infoClass)
        {
            int returnLength;
            bool res = NativeMethods.GetTokenInformation(hToken, infoClass, new SafeMemoryBuffer(IntPtr.Zero), 0,
                out returnLength);
            int errCode = Marshal.GetLastWin32Error();
            if (!res && errCode != 24 && errCode != 122)  // ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH
            {
                throw new Win32Exception(errCode, String.Format("GetTokenInformation({0}) failed to get buffer length", infoClass));
            }

            SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer(returnLength);
            if (!NativeMethods.GetTokenInformation(hToken, infoClass, tokenInfo, returnLength, out returnLength))
                throw new Win32Exception(String.Format("GetTokenInformation({0}) failed", infoClass));

            return tokenInfo;
        }
    }
}
"@
#endregion

#region function
function Invoke-AsCurrentUser
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[scriptblock]$ScriptBlock,
		[Parameter(Mandatory = $false)]
		[switch]$NoWait,
		[Parameter(Mandatory = $false)]
		[switch]$UseWindowsPowerShell
	)
	if (!("RunAsUser.ProcessExtensions" -as [type]))
	{
		Add-Type -TypeDefinition $script:source -Language CSharp
	}
	$encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
	$privs = whoami /priv /fo csv | ConvertFrom-Csv | Where-Object { $_.'Privilege Name' -eq 'SeDelegateSessionUserImpersonatePrivilege' }
	if ($privs.State -eq "Disabled")
	{
		Write-Error -Message "Not running with correct privilege. You must run this script as system or have the SeDelegateSessionUserImpersonatePrivilege token."
		return
	}
	else
	{
		try
		{
			# Use the same PowerShell executable as the one that invoked the function, Unless -UseWindowsPowerShell is defined
			
			if (!$UseWindowsPowerShell) { $pwshPath = (Get-Process -Id $pid).Path }
			else { $pwshPath = "$($ENV:windir)\system32\WindowsPowerShell\v1.0\powershell.exe" }
			if ($NoWait) { $ProcWaitTime = 1 }
			else { $ProcWaitTime = -1 }
			[RunAsUser.ProcessExtensions]::StartProcessAsCurrentUser(
				$pwshPath, "`"$pwshPath`" -ExecutionPolicy Bypass -Window Normal -EncodedCommand $($encodedcommand)",
				(Split-Path $pwshPath -Parent), $false, $ProcWaitTime)
		}
		catch
		{
			Write-Error -Message "Could not execute as currently logged on user: $($_.Exception.Message)" -Exception $_.Exception
			return
		}
	}
}
#endregion

#region script block to run
$sb = {
	function Show-ToastNotification
	{
		[cmdletbinding()]
		param (
			[parameter(Mandatory = $true)]
			[string]$App,
			[parameter(Mandatory = $true, ValueFromPipeline)]
			[xml]$Toast
		)
		[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
		[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
		# Load the notification into the required format
		$ToastXML = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
		$ToastXML.LoadXml($Toast.OuterXml)
		
		# Display the toast notification
		try
		{
			[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($App).Show($ToastXml)
		}
		catch
		{
			Write-Output -Message 'Something went wrong when displaying the toast notification' -Level Warn
			Write-Output -Message 'Make sure the script is running as the logged on user' -Level Warn
		}
	}
	
	#Setting App variables
	$AppName = "Linux Subsystem"
	$Action = "Enable"
	
	# Setting image variables
	$LogoImageUri = "https://globalautopilot.blob.core.windows.net/localadminadministration/NTT_Stacked_White-48x48.png?sp=r&st=2020-08-25T13:55:00Z&se=2022-08-25T21:55:00Z&spr=https&sv=2019-12-12&sr=b&sig=0xkMh9d79lFKnBD8ucjbUcWAUBzcqCTtFb%2B6gsqwc68%3D"
	$HeroImageUri = "https://globalautopilot.blob.core.windows.net/localadminadministration/local_admin_4.png?sp=r&st=2020-08-14T22:59:13Z&se=2021-08-15T06:59:13Z&spr=https&sv=2019-12-12&sr=b&sig=MhYeS34UTaA4EVnL70hGSB38Op6jzfWoMvH9W5%2Bhtsc%3D"
	$LogoImage = "$env:TEMP\ToastLogoImage.png"
	$HeroImage = "$env:TEMP\ToastHeroImage.png"
	#$Uptime = get-computerinfo | Select-Object OSUptime
	
	#Fetching images from uri
	Invoke-WebRequest -Uri $LogoImageUri -OutFile $LogoImage
	Invoke-WebRequest -Uri $HeroImageUri -OutFile $HeroImage
	
	#Defining the Toast notification settings
	#ToastNotification Settings
	$Scenario = 'reminder' # <!-- Possible values are: reminder | short | long -->
	
	#Greeting Name
	$RegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
	$DisplayName = $DisplayName = (Get-ItemProperty -Path $RegKey).LastLoggedOnDisplayName
	$GivenName = $DisplayName.Split()[0].Trim()
	
	#Greeting Time
	$GreetMorningText = "Good morning"
	$GreetAfternoonText = "Good afternoon"
	$GreetEveningText = "Good evening"
	$Hour = (Get-Date).TimeOfDay.Hours
	switch ($Hour)
	{
		{ ($Hour -ge 0) -and ($Hour -lt 12) } {
			$Greeting = $GreetMorningText
			continue
		}
		{ ($Hour -ge 12) -and ($Hour -lt 16) } {
			$Greeting = $GreetAfternoonText
			continue
		}
		{ ($Hour -ge 16) -and ($Hour -lt 23) } {
			$Greeting = $GreetEveningText
			continue
		}
		default {
			$Greeting = "Hello"
		}
	}
	#$HeaderText = "$Greeting $GivenName"
	
	# Load Toast Notification text
	$AttributionText = "NTT"
	$HeaderText = "Windows Feature"
	$TitleText = "$Action $AppName"
	$BodyText1 = "$Greeting $GivenName. The $Appname Windows feature has been $($Action.ToLower())d on your device."
	$BodyText2 = "Please reboot your device in order to activate it."
	
	# Check for required entries in registry for when using Powershell as application for the toast
	# Register the AppID in the registry for use with the Action Center, if required
	$RegPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'
	$App = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
	
	# Creating registry entries if they don't exists
	if (-NOT (Test-Path -Path "$RegPath\$App"))
	{
		New-Item -Path "$RegPath\$App" -Force
		New-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD'
	}
	
	# Make sure the app used with the action center is enabled
	if ((Get-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -ErrorAction SilentlyContinue).ShowInActionCenter -ne '1')
	{
		New-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD' -Force
	}
	
	
	# Formatting the toast notification XML
	[xml]$Toast = @"
<toast scenario="$Scenario">
    <visual>
    <binding template="ToastGeneric">
        <image id="1" placement="appLogoOverride" src="$LogoImage"/>
        <text placement="attribution">$AttributionText</text>
        <text>$HeaderText</text>
        <group>
            <subgroup>
                <text hint-style="title" hint-wrap="true" >$TitleText</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style="body" hint-wrap="true" >$BodyText1</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style="body" hint-wrap="true" >$BodyText2</text>
            </subgroup>
        </group>
    </binding>
    </visual>
    <actions>
        <action activationType="system" arguments="dismiss" content="$DismissButtonContent" />
    </actions>
</toast>
"@
	
	#Send the notification
	Show-ToastNotification -App $App -Toast $Toast
}

#endregion

Write-LogEntry -Message "*** Starting $Purpose script for `"$AppName`"" @LogParams
Write-LogEntry -Message "$((Get-Culture).TextInfo.ToTitleCase($Purpose.ToLower())) script version $ScriptVersion" @LogParams

If ($Action -ne 'Enable' -and $Action -ne 'Disable')
{
	Write-LogEntry -Message "Invalid action parameter set: `"$Action`"" @LogParams
	Write-LogEntry -Message "Result of script for $Purpose`: NOT Compliant" -Severity 2 @LogParams
	Write-Warning "Not Compliant"
	Exit 1
}

Try
{
	$State = (Get-WindowsOptionalFeature -online -FeatureName $FeatureName).State
	If ($State -eq $null)
	{
		Write-LogEntry -Message "Could not find Windows feature `"$FeatureName`"" @LogParams
		Write-LogEntry -Message "Result of script for $Purpose`: NOT Compliant" -Severity 2 @LogParams
		Write-Warning "Not Compliant"
		Exit 1
	}
	ElseIf ($State -like "$Action*")
	{
		Write-LogEntry -Message "Windows feature `"$FeatureName`" is set to $State" @LogParams
		Write-LogEntry -Message "Result of script for $Purpose`: Compliant" @LogParams
		Write-Output "Compliant"
		Exit 0
	}
	else
	{
		If ($Remediate -eq $true -and $Action -eq "Enable")
		{
			Try
			{
				Write-LogEntry -Message "Performing install of Windows feature `"$FeatureName`" using Powershell" @LogParams
				Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart
				$State = (Get-WindowsOptionalFeature -online -FeatureName $FeatureName).State
				if ($State -eq "Enabled")
				{
					Write-LogEntry -Message "Windows feature `"$FeatureName`" has been successfully installed" @LogParams
					Write-LogEntry -Message "Result of script for $Purpose`: Compliant" @LogParams
					Invoke-AsCurrentUser -ScriptBlock $sb
					Write-Output "Compliant"
					Exit 0
				}
				else
				{
					Write-LogEntry -Message "Failed to install Windows feature `"$FeatureName`" using Powershell" @LogParams
					Write-LogEntry -Message "Performing install of Windows feature `"$FeatureName`" using DISM" @LogParams
					dism.exe /online /enable-feature /featurename:$FeatureName /all /norestart
					$State = (Get-WindowsOptionalFeature -online -FeatureName $FeatureName).State
					if ($State -eq "Enabled")
					{
						Write-LogEntry -Message "Windows feature `"$FeatureName`" has been successfully installed" @LogParams
						Write-LogEntry -Message "Result of script for $Purpose`: Compliant" @LogParams
						Invoke-AsCurrentUser -ScriptBlock $sb
						Write-Output "Compliant"
						Exit 0
					}
					else
					{
						Write-LogEntry -Message "Failed to install Windows feature `"$FeatureName`" using DISM" @LogParams
						Write-LogEntry -Message "Result of script for $Purpose`: NOT Compliant" -Severity 2 @LogParams
						Write-Warning "Not Compliant"
						Exit 1
					}
				}
			}
			Catch
			{
				Write-LogEntry -Message "$Error[0]" -Severity 3 @LogParams
				Write-Warning $_
				Exit 1
			}
		}
		ElseIf ($Remediate -eq $true -and $Action -eq "Disable")
		{
			Try
			{
				Write-LogEntry -Message "Performing removal of Windows feature `"$FeatureName`" using Powershell" @LogParams
				Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart
				$State = (Get-WindowsOptionalFeature -online -FeatureName $FeatureName).State
				if ($State -eq "Disabled")
				{
					Write-LogEntry -Message "Windows feature `"$FeatureName`" has been successfully removed" @LogParams
					Write-LogEntry -Message "Result of script for $Purpose`: Compliant" @LogParams
					Write-Output "Compliant"
					Exit 0
				}
				else
				{
					Write-LogEntry -Message "Failed to remove Windows feature `"$FeatureName`" using Powershell" @LogParams
					Write-LogEntry -Message "Performing removal of Windows feature `"$FeatureName`" using DISM" @LogParams
					dism.exe /online /disable-feature /featurename:$FeatureName /all /norestart
					$State = (Get-WindowsOptionalFeature -online -FeatureName $FeatureName).State
					if ($State -eq "Disabled")
					{
						Write-LogEntry -Message "Windows feature `"$FeatureName`" has been successfully removed" @LogParams
						Write-LogEntry -Message "Result of script for $Purpose`: Compliant" @LogParams
						Write-Output "Compliant"
						Exit 0
					}
					else
					{
						Write-LogEntry -Message "Failed to remove Windows feature `"$FeatureName`" using DISM" @LogParams
						Write-LogEntry -Message "Result of script for $Purpose`: NOT Compliant" -Severity 2 @LogParams
						Write-Warning "Not Compliant"
						Exit 1
					}
				}	
			}
			Catch
			{
				Write-LogEntry -Message "$Error[0]" -Severity 3 @LogParams
				Write-Warning $_
				Exit 1
			}
		}		
		else
		{
			Write-LogEntry -Message "Windows feature `"$FeatureName`" is set to $State" @LogParams
			Write-LogEntry -Message "Result of script for $Purpose`: NOT Compliant" -Severity 2 @LogParams
			Write-Warning "Not Compliant"
			Exit 1
		}
	}
}
Catch
{
	Write-LogEntry -Message "$Error[0]" -Severity 3 @LogParams
	Write-Warning $_
	Exit 1
}
# SIG # Begin signature block
# MIIQ/AYJKoZIhvcNAQcCoIIQ7TCCEOkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAflPvczfTef/Qx
# IruVRFaV8PF93Hn9kfta8urFcYRY96CCC+0wggMGMIIB7qADAgECAhBKC4fZio4F
# pUJD6NVxKl4vMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMMEE5UVCBDb2RlIFNp
# Z25pbmcwHhcNMjAwODA2MTQyNjIwWhcNMjUwODA3MTQyNjIwWjAbMRkwFwYDVQQD
# DBBOVFQgQ29kZSBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEAqYFMvUXiaaIbIy5X+Tq6CyzgJq9rqkCchJtABtzaurpolJx9m0gfWvAyHQSC
# e2oMU1Qptig/B98QcQXgIwIND4VpeZqHm3iXPnB8Pl99b12S1Hi7FM/T+ilyrpYL
# NifnTOb9q6YLMTMAHxu2cpGNLeBNkaBnN/ECNELAF36wIKj0miTXngQs7y2bQRPm
# sIaluzF+Ao7wTc9aVkOVrzLU/Z+SnGGWp7adV8l7IqekDychbebffDuGakF2ULo4
# CrFgUyQnz+1kKFVDndafnWqqof4l9Hr29h14uEdJ+dirnTM1IoULPjopjmh1FMgj
# 5lfaFIoWLF0xixnjYvqUb1DTHQIDAQABo0YwRDATBgNVHSUEDDAKBggrBgEFBQcD
# AzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFJJjRB1GueIsKk7HtaswZQx4Yc3m
# MA0GCSqGSIb3DQEBBQUAA4IBAQCH8zlKO+ZQsH4QXXOmfTuXNSaK1bAfWqJFpj7p
# yUj9UUl/zTaup9X8CDbkoTZcRMWnT7iJihMshAroWdlU07nLcHISag7sXEcfgVDR
# k3cSHBEsxRl+D9HNxe1MildUAyrToi5b0KF/GeM5rpYWddehq3tlB0KFvO1zH9Xa
# P0PMGRQzDGtmrtT2023Dc+wQRmGuRNKcHbnK6PlU7Li2/6n66cSyuG8BFE5lbrFM
# 2A6bhS/e6CUKH5zPoIQqjH5RMuXYmRtFIf6Mu4yO9JHFagVk1jce6T/6jaRZV9Qf
# Man2drYB4ijaiKmCXj4bTYw4WJZWtxIRhel82edG9ZqtJDOvMIIEFTCCAv2gAwIB
# AgILBAAAAAABMYnGUAQwDQYJKoZIhvcNAQELBQAwTDEgMB4GA1UECxMXR2xvYmFs
# U2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMT
# Ckdsb2JhbFNpZ24wHhcNMTEwODAyMTAwMDAwWhcNMjkwMzI5MTAwMDAwWjBbMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMo
# R2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEyNTYgLSBHMjCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKqbjsOrEVElAbaWlOJP2MEI9kYj2UXF
# lZdbqxq/0mxXyTMGH6APxjx+U0h6v52Hnq/uw4xH4ULs4+OhSmwMF8SmwbnNW/Ee
# RImO/gveIVgT7k3IxWcLHLKz8TR2kaLLB203xaBHJgIVpJCRqXme1+tXnSt8ItgU
# 1/EHHngiNmt3ea+v+X+OTuG1CDH96u1LcWKMI/EDOY9EebZ2A1eerS8IRtzSjLz0
# jnTOyGhpUXYRiw9dJFsZVD0mzECNgicbWSB9WfaTgI74Kjj9a6BAZR9XdsxbjgRP
# LKjbhFATT8bci7n43WlMiOucezAm/HpYu1m8FHKSgVe3dsnYgAqAbgkCAwEAAaOB
# 6DCB5TAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUkiGnSpVdZLCbtB7mADdH5p1BK0wwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYI
# KwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkv
# MDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvcm9v
# dC1yMy5jcmwwHwYDVR0jBBgwFoAUj/BLf6guRSSuTVD6Y5qL3uLdG7wwDQYJKoZI
# hvcNAQELBQADggEBAARWgkp80M7JvzZm0b41npNsl+gGzjEYWflsQV+ALsBCJbgY
# x/zUsTfEaKDPKGoDdEtjl4V3YTvXL+P1vTOikn0RH56KbO8ssPRijTZz0RY28bxe
# 7LSAmHj80nZ56OEhlOAfxKLhqmfbs5xz5UAizznO2+Z3lae7ssv2GYadn8jUmAWy
# cW9Oda7xPWRqO15ORqYqXQiS8aPzHXS/Yg0jjFwqOJXSwNXNz4jaHyi1uoFpZCq1
# pqLVc6/cRtsErpHXbsWYutRHxFZ0gEd4WIy+7yv97Gy/0ZT3v1Dge+CQ/SAYeBgi
# XQgujBygl/MdmX2jnZHTBkROBG56HCDjNvC2ULkwggTGMIIDrqADAgECAgwkVLh/
# HhRTrTf6oXgwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMjU2IC0gRzIwHhcNMTgwMjE5MDAwMDAwWhcNMjkwMzE4MTAw
# MDAwWjA7MTkwNwYDVQQDDDBHbG9iYWxTaWduIFRTQSBmb3IgTVMgQXV0aGVudGlj
# b2RlIGFkdmFuY2VkIC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDZeGGhlq4S/6P/J/ZEYHtqVi1n41+fMZIqSO35BYQObU4iVsrYmZeOacqfew8I
# yCoraNEoYSuf5Cbuurj3sOxeahviWLW0vR0J7c3oPdRm/74iIm02Js8ReJfpVQAo
# w+k3Tr0Z5ReESLIcIa3sc9LzqKfpX+g1zoUTpyKbrILp/vFfxBJasfcMQObSoOBN
# aNDtDAwQHY8FX2RV+bsoRwYM2AY/N8MmNiWMew8niFw4MaUB9l5k3oPAFFzg59Je
# zI3qI4AZKrNiLmDHqmfWs0DuUn9WDO/ZBdeVIF2FFUDPXpGVUZ5GGheRvsHAB3Wy
# S/c2usVUbF+KG/sNKGHIifAVAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4Aw
# TAYDVR0gBEUwQzBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93
# d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCQYDVR0TBAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDBGBgNVHR8EPzA9MDugOaA3hjVodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzL2dzdGltZXN0YW1waW5nc2hhMmcyLmNybDCBmAYIKwYB
# BQUHAQEEgYswgYgwSAYIKwYBBQUHMAKGPGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2ln
# bi5jb20vY2FjZXJ0L2dzdGltZXN0YW1waW5nc2hhMmcyLmNydDA8BggrBgEFBQcw
# AYYwaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL2dzdGltZXN0YW1waW5nc2hh
# MmcyMB0GA1UdDgQWBBTUh7iN5uVAPJ1aBmPGRYTZ3bscwzAfBgNVHSMEGDAWgBSS
# IadKlV1ksJu0HuYAN0fmnUErTDANBgkqhkiG9w0BAQsFAAOCAQEAJHJQpQy8QAmm
# wfTVgmpOQV/Ox4g50+R8+SJsOHi49Lr3a+Ek6518zUisi+y1dkyP3IJpCJbnuuFn
# tvCmvxgIQuHrzRlYOaURYSPWGdcA6bvS+V9B+wQ+/oogYAzRTyNaGRoY79jG3tZf
# VKF6k+G2d4XA+7FGxAmuL1P7lZyOJuJK5MTmPDXvusbZucXNzQebY7s9D2G8VXwj
# ELWMiqPSaEWxQLqg3TwbFUC4SXhv5ZTAbVZLPPYSKtSF80gTBeG7MEUKQbd8km6+
# TpJggspbZOZV09IH3p1fm6EB7Zvww127GfAYDJqgHOlqCAs96WaXp3UeD78o1wkj
# DeIW+rrzNDGCBGUwggRhAgEBMC8wGzEZMBcGA1UEAwwQTlRUIENvZGUgU2lnbmlu
# ZwIQSguH2YqOBaVCQ+jVcSpeLzANBglghkgBZQMEAgEFAKBMMBkGCSqGSIb3DQEJ
# AzEMBgorBgEEAYI3AgEEMC8GCSqGSIb3DQEJBDEiBCBSph0z6V+Q0SPStjC0VUSR
# hD5UkHFaw3T6qFISWSbL5TANBgkqhkiG9w0BAQEFAASCAQBP3c3WkWPFCcoKUA7c
# tG7N/PplxkY4uhHFz0RpK5S6RTdmL3r1Dt6oPCjMMj9S1AFih4i3ujubzVCko2pf
# r1/ZqjUXLFmwJHCBdtgOGro2onVWMTTO/D36c1MNtZhGzn6GD1uKdyDwTPOA9YEB
# x4fer0X2ePCKqmppsTZHvMfJ5RMBcsgzbD9AMn966wDCiXinzWrZakUlLpvNF55B
# O/mlLp10a4vG2QFSRCEQwBXZRafjBlsYbV6Tx/0IHVMlh04fV3uZXFv8EdzRFFIe
# SkwKFjBUJxWZmuGViqxPlV29yLkx5N9aDYIFoKy98/+SmSFggSBz1/RmbCQvXTDJ
# WF29oYICuTCCArUGCSqGSIb3DQEJBjGCAqYwggKiAgEBMGswWzELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gU0hBMjU2IC0gRzICDCRUuH8eFFOtN/qheDAN
# BglghkgBZQMEAgEFAKCCAQwwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq
# hkiG9w0BCQUxDxcNMjEwMjE2MDcxODA0WjAvBgkqhkiG9w0BCQQxIgQgOFrybVlp
# ttaHW6UIXy0uqo+OwT7DgIHoTQJ/llDBWSswgaAGCyqGSIb3DQEJEAIMMYGQMIGN
# MIGKMIGHBBQ+x2bV1NRy4hsfIUNSHDG3kNlLaDBvMF+kXTBbMQswCQYDVQQGEwJC
# RTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2ln
# biBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEyNTYgLSBHMgIMJFS4fx4UU603+qF4MA0G
# CSqGSIb3DQEBAQUABIIBABxGgu/sczrVirLOBFfyGqqBe8FpsYLSIvAAbfzDvmZs
# MSvclKQvJqh7ArMVPdkfzqwUlabUJcTPDCpacT4GbiGt87VhQ2TwJd2VRC96H+PY
# Ik1MyUD9Z7Yhpe+FI0puPVyxFAN8gFPf7G/40Rb5wwbHJ19byF8pdOd74ryy2jx/
# Uu1eqe4pXKIAJnhCqpu0K9ggB1rdvgk72Lw9VljpJuLOMoMDNZh81Hfi57PgXvfU
# 9vB+RSyXqwuZw7R5lHLwRbZBCzjCAo+4a78qSiDW/Eet5tvQoDZjUTlVme2eBeBn
# Rmw7i094eylTIHaiwjGemw1MuB8GDVtcsamd2DnDoDc=
# SIG # End signature block
