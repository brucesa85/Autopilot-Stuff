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
function Invoke-AsCurrentUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock,
        [Parameter(Mandatory = $false)]
        [switch]$NoWait,
        [Parameter(Mandatory = $false)]
        [switch]$UseWindowsPowerShell
    )
    if (!("RunAsUser.ProcessExtensions" -as [type])) {
        Add-Type -TypeDefinition $script:source -Language CSharp
    }
    $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
    $privs = whoami /priv /fo csv | ConvertFrom-Csv | Where-Object { $_.'Privilege Name' -eq 'SeDelegateSessionUserImpersonatePrivilege' }
    if ($privs.State -eq "Disabled") {
        Write-Error -Message "Not running with correct privilege. You must run this script as system or have the SeDelegateSessionUserImpersonatePrivilege token."
        return
    }
    else {
        try {
            # Use the same PowerShell executable as the one that invoked the function, Unless -UseWindowsPowerShell is defined
           
            if (!$UseWindowsPowerShell) { $pwshPath = (Get-Process -Id $pid).Path } else { $pwshPath = "$($ENV:windir)\system32\WindowsPowerShell\v1.0\powershell.exe" }
            if ($NoWait) { $ProcWaitTime = 1 } else { $ProcWaitTime = -1 }
            [RunAsUser.ProcessExtensions]::StartProcessAsCurrentUser(
                $pwshPath, "`"$pwshPath`" -ExecutionPolicy Bypass -Window Normal -EncodedCommand $($encodedcommand)",
                (Split-Path $pwshPath -Parent), $false, $ProcWaitTime)
        }
        catch {
            Write-Error -Message "Could not execute as currently logged on user: $($_.Exception.Message)" -Exception $_.Exception
            return
        }
    }
}
#endregion
#region script block to run
$sb = {
    function Show-ToastNotification {
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
        try {
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($App).Show($ToastXml)
        }
        catch {
            Write-Output -Message 'Something went wrong when displaying the toast notification' -Level Warn
            Write-Output -Message 'Make sure the script is running as the logged on user' -Level Warn
        }
    }

    # Setting image variables
    $LogoImageUri = "BLOB"
    $HeroImageUri = "BLOB"
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
    switch ($Hour) {
        {($Hour -ge 0) -and ($Hour -lt 12)} {
            $Greeting = $GreetMorningText
            continue
        }
        {($Hour -ge 12) -and ($Hour -lt 16)} {
            $Greeting = $GreetAfternoonText
            continue
        }
        {($Hour -ge 16) -and ($Hour -lt 23)} {
            $Greeting = $GreetEveningText
            continue
        }
        default {
            $Greeting = "Hello"
        }
    }
    #$HeaderText = "$Greeting $GivenName"

    # Load Toast Notification text
    $AttributionText = "JOE COMMUNICATIONS INC"
    $HeaderText = "Local administrator assignment"
    $TitleText = "Local Admin Granted"
    $BodyText1 = "$Greeting $GivenName. You have been granted Local Administrator priviledges to your computer. Please save all your work and reboot your computer."
    $BodyText2 = "Please contact IT if you need assistence."


    # Check for required entries in registry for when using Powershell as application for the toast
    # Register the AppID in the registry for use with the Action Center, if required
    $RegPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'
    $App = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'

    # Creating registry entries if they don't exists
    if (-NOT (Test-Path -Path "$RegPath\$App")) {
        New-Item -Path "$RegPath\$App" -Force
        New-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD'
    }

    # Make sure the app used with the action center is enabled
    if ((Get-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -ErrorAction SilentlyContinue).ShowInActionCenter -ne '1') {
        New-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD' -Force
    }


    # Formatting the toast notification XML
    [xml]$Toast = @"
<toast scenario="$Scenario">
    <visual>
    <binding template="ToastGeneric">
        <image placement="hero" src="$HeroImage"/>
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

Invoke-AsCurrentUser -ScriptBlock $sb