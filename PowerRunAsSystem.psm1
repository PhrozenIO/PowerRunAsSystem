<#-------------------------------------------------------------------------------

    .Developer
        Jean-Pierre LESUEUR (@DarkCoderSc)
        https://www.twitter.com/darkcodersc
        https://github.com/DarkCoderSc
        www.phrozen.io
        jplesueur@phrozen.io
        PHROZEN
    .License
        Apache License
        Version 2.0, January 2004
        http://www.apache.org/licenses/
    .Disclaimer
        We are doing our best to prepare the content of this app. However, PHROZEN SASU and / or
        Jean-Pierre LESUEUR cannot warranty the expressions and suggestions of the contents,
        as well as its accuracy. In addition, to the extent permitted by the law, 
        PHROZEN SASU and / or Jean-Pierre LESUEUR shall not be responsible for any losses
        and/or damages due to the usage of the information on our app.
        By using our app, you hereby consent to our disclaimer and agree to its terms.
        Any links contained in our app may lead to external sites are provided for
        convenience only. Any information or statements that appeared in these sites
        or app are not sponsored, endorsed, or otherwise approved by PHROZEN SASU and / or
        Jean-Pierre LESUEUR. For these external sites, PHROZEN SASU and / or Jean-Pierre LESUEUR
        cannot be held liable for the availability of, or the content located on or through it.
        Plus, any losses or damages occurred from using these contents or the internet
        generally.
        
-------------------------------------------------------------------------------#>

Add-Type @"
    using System;    
    using System.Security;
    using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct WTS_SESSION_INFO
    {
        public UInt32 SessionID;          
        public string pWinStationName;
        public byte State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public static class WTSAPI32 
    {    
        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            UInt32 Reserved,
            UInt32 Version,
            ref IntPtr ppSessionInfo,
            ref UInt32 pCount
        );

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(IntPtr pMemory);
    }    

    public static class ADVAPI32
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            IntPtr lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            ref IntPtr lpProcessInformation
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            ref IntPtr TokenHandle
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            byte ImpersonationLevel,
            byte TokenType,
            ref IntPtr phNewToken
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetTokenInformation(
            IntPtr TokenHandle,
            byte TokenInformationClass,
            ref UInt32 TokenInformation,
            UInt32 TokenInformationLength
        );
    }

    public static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);
    }
"@

function Invoke-InteractiveSystemProcess
{
    <#
        .SYNOPSIS
            Run system process in active Windows session.

        .PARAMETER Execute
            The program to execute in active session.
    #>
    param(
        [string] $Execute = "powershell.exe"
    )    

    if (-not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
    {
        throw "You must be system user to run an interactive system process."
    }

    # Get Active Session Id

    [IntPtr] $pSessionArray = [IntPtr]::Zero
    [UInt32] $sessionCount = 0

    try
    {
        if (-not [WTSAPI32]::WTSEnumerateSessions([IntPtr]::Zero, 0, 1, [ref]$pSessionArray, [ref]$sessionCount))
        {
            throw "WTSEnumerateSessions"
        }
        try
        {
            $sessionInfoSize = [Runtime.InteropServices.Marshal]::SizeOf([System.Type][WTS_SESSION_INFO])
            $activeSession = -1

            for ($i; $i -lt $sessionCount; $i++)
            {
                [IntPtr] $pOffset = [IntPtr]([Int64]$pSessionArray + ($i * $sessionInfoSize))

                $sessionInfo = [WTS_SESSION_INFO][Runtime.InteropServices.Marshal]::PtrToStructure($pOffset, [System.Type][WTS_SESSION_INFO])    

                if ($sessionInfo.State -eq 0 <# Active #>)
                {
                    $activeSession = $sessionInfo.SessionID

                    break
                }
            }
        }
        finally
        {
            if ($pSessionArray -ne [IntPtr]::Zero)
            {
                [WTSAPI32]::WTSFreeMemory($pSessionArray)
            }
        }

        if ($activeSession -eq -1)
        {
            throw "Could not found active session"
        }

        # Create new system process in Active Session

        $token = [IntPtr]::Zero
        $ALL_ACCESS = 0xF01FF

        if (-not [ADVAPI32]::OpenProcessToken([Kernel32]::GetCurrentProcess(), $ALL_ACCESS, [ref]$token))
        {
            throw "OpenProcessToken"
        }

        $newToken = [IntPtr]::Zero

        $MAXIMUM_ALLOWED = 0x02000000
        $SecurityIdentification = 0x2
        $TokenPrimary = 0x1

        if (-not [ADVAPI32]::DuplicateTokenEx($token, $MAXIMUM_ALLOWED, [IntPtr]::Zero, $SecurityIdentification, $TokenPrimary, [ref]$newToken))
        {
            throw "DuplicateTokenEx"
        }    

        $TokenSessionId = 0xc

        if (-not [ADVAPI32]::SetTokenInformation($newToken, $TokenSessionId, [ref]$activeSession, [UInt32][Runtime.InteropServices.Marshal]::SizeOf($activeSession)))
        {
            throw "SetTokenInformation"
        }

        $STARTF_USESHOWWINDOW = 0x1
        $SW_SHOW = 0x5

        $startupInfo = [STARTUPINFO]::New()
        $startupInfo.cb = [Runtime.InteropServices.Marshal]::SizeOf($startupInfo)
        $startupInfo.dwFlags = $STARTF_USESHOWWINDOW
        $startupInfo.wShowWindow = $SW_SHOW

        $processInfo = [IntPtr]::Zero

        if (-not [ADVAPI32]::CreateProcessAsUser(
            $newToken,
            "cmd.exe",
            "/c ""start powershell.exe""",
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            $false,
            0x10,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [ref]$startupInfo,
            [ref]$processInfo
        ))
        {
            throw "CreateProcessAsUser"
        }
    }
    catch
    {
        ([string]::Format("$_ LastError:{0}", [Runtime.InteropServices.Marshal]::GetLastWin32Error().ToString())) | Out-File "c:\temp\error.log"
    } 
    finally
    {
        if ($token -ne [IntPtr]::Zero)
        {
            [Kernel32]::CloseHandle($token)
        }

        if ($newToken -ne [IntPtr]::Zero)
        {
            [Kernel32]::CloseHandle($newToken)
        }
    }       
}

function Test-Administrator
{
    <#
        .SYNOPSIS
            Check if current user is administrator.
    #>
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    
    return $windowsPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )    
}

function Invoke-SystemCommand
{
    <#
        .SYNOPSIS
            Execute program as NT AUTHORITY/SYSTEM with optional arguments.        

        .PARAMETER Execute
            Program to execute as System.

        .PARAMETER Argument
            Optional argument(s) to pass to program to execute. 
    #>
    param(
        [string] $Execute = "powershell.exe",
        [string] $Argument = "-Command ""whoami | Out-File C:\result.txt"""
    )

    if (-not (Test-Administrator))
    {
        throw "You must be Administrator to run system commands."
    }

    $charList = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    $taskName = -join ((1..15) | ForEach-Object { Get-Random -Input $charList.ToCharArray() })
    
    if ($Argument)
    {
        $action = New-ScheduledTaskAction -Execute $Execute -Argument $Argument
    }
    else
    {
        $action = New-ScheduledTaskAction -Execute $Execute
    }

    if ($null -eq (Register-ScheduledTask -Force -Action $action -TaskName $taskName -User "NT AUTHORITY\SYSTEM"))
    {
        throw ""
    }
    try
    {
        Start-ScheduledTask $taskName
    }
    finally
    {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}

try {  
    Export-ModuleMember -Function Invoke-SystemCommand
    Export-ModuleMember -Function Invoke-InteractiveSystemProcess
} catch {}
