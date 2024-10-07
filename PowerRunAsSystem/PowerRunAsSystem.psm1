# ----------------------------------------------------------------------------------- #
#                                                                                     #
#    .Developer                                                                       #
#        Jean-Pierre LESUEUR (@DarkCoderSc)                                           #
#        https://www.twitter.com/darkcodersc                                          #
#        https://github.com/PhrozenIO                                                 #
#        https://github.com/DarkCoderSc                                               #
#        www.phrozen.io                                                               #
#        jplesueur@phrozen.io                                                         #
#        PHROZEN                                                                      #
#    .License                                                                         #
#        Apache License                                                               #
#        Version 2.0, January 2004                                                    #
#        http://www.apache.org/licenses/                                              #
#    .Disclaimer                                                                      #
#        This script is provided "as is", without warranty of any kind, express or    #
#        implied, including but not limited to the warranties of merchantability,     #
#        fitness for a particular purpose and noninfringement. In no event shall the  #
#        authors or copyright holders be liable for any claim, damages or other       #
#        liability, whether in an action of contract, tort or otherwise, arising      #
#        from, out of or in connection with the software or the use or other dealings #
#        in the software.                                                             #
#                                                                                     #
# ----------------------------------------------------------------------------------- #

# ----------------------------------------------------------------------------------- #
#                           - STRUCTURES MEMORY MAPS -                                #
# ----------------------------------------------------------------------------------- #
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#
# ----------------------------------------------------------------------------------- #
# Field               | Type       | Size x32 | Offset x32 | Size x64 | Offset x64    #
# ----------------------------------------------------------------------------------- #
# PROCESS_INFORMATION                                                                 #
# ----------------------------------------------------------------------------------- #
# hProcess            | HANDLE     | 0x4      | 0x0        | 0x8      | 0x0           #
# hThread             | HANDLE     | 0x4      | 0x4        | 0x8      | 0x8           #
# dwProcessId         | DWORD      | 0x4      | 0x8        | 0x4      | 0x10          #
# dwThreadId          | DWORD      | 0x4      | 0xC        | 0x4      | 0x14          #
# ----------------------------------------------------------------------------------- #
# Total Size x32: 0x10 (16 Bytes)      |     Total Size x64: 0x18 (24 Bytes)          #
# ----------------------------------------------------------------------------------- #
# STARTUPINFOW                                                                        #
# ----------------------------------------------------------------------------------- #
# cb                  | DWORD      | 0x4      | 0x0        | 0x4      | 0x0           #
# lpReserved          | LPWSTR     | 0x4      | 0x4        | 0x8      | 0x8           #
# lpDesktop           | LPWSTR     | 0x4      | 0x8        | 0x8      | 0x10          #
# lpTitle             | LPWSTR     | 0x4      | 0xC        | 0x8      | 0x18          #
# dwX                 | DWORD      | 0x4      | 0x10       | 0x4      | 0x20          #
# dwY                 | DWORD      | 0x4      | 0x14       | 0x4      | 0x24          #
# dwXSize             | DWORD      | 0x4      | 0x18       | 0x4      | 0x28          #
# dwYSize             | DWORD      | 0x4      | 0x1C       | 0x4      | 0x2C          #
# dwXCountChars       | DWORD      | 0x4      | 0x20       | 0x4      | 0x30          #
# dwYCountChars       | DWORD      | 0x4      | 0x24       | 0x4      | 0x34          #
# dwFillAttribute     | DWORD      | 0x4      | 0x28       | 0x4      | 0x38          #
# dwFlags             | DWORD      | 0x4      | 0x2C       | 0x4      | 0x3C          #
# wShowWindow         | WORD       | 0x2      | 0x30       | 0x2      | 0x40          #
# cbReserved2         | WORD       | 0x2      | 0x32       | 0x2      | 0x42          #
# lpReserved2         | LPBYTE     | 0x4      | 0x34       | 0x8      | 0x48          #
# hStdInput           | HANDLE     | 0x4      | 0x38       | 0x8      | 0x50          #
# hStdOutput          | HANDLE     | 0x4      | 0x3C       | 0x8      | 0x58          #
# hStdError           | HANDLE     | 0x4      | 0x40       | 0x8      | 0x60          #
# ----------------------------------------------------------------------------------- #
# Total Size x32: 0x44 (68 Bytes)      |     Total Size x64: 0x68 (104 Bytes)         #
# ----------------------------------------------------------------------------------- #
# WTS_SESSION_INFOW                                                                   #
# ----------------------------------------------------------------------------------- #
# SessionId           | DWORD       | 0x4      | 0x0        | 0x4      | 0x0          #
# pWinStationName     | LPSTR       | 0x4      | 0x4        | 0x8      | 0x8          #
# State               | WTS_C_STATE | 0x1      | 0x8        | 0x1      | 0x10         #
# ----------------------------------------------------------------------------------- #
# Total Size x32: 0xC (12 Bytes)       |    Total Size x64: 0x18 (24 Bytes)           #
# ----------------------------------------------------------------------------------- #
# TokenPrivilege Structure                                                            #
# ----------------------------------------------------------------------------------- #
# PrivilegeCount     | UInt32       | 0x4      | 0x0        | 0x4      | 0x0          #
# Luid               | Int64 (long) | 0x8      | 0x4        | 0x8      | 0x8          #
# Attributes         | UInt32       | 0x4      | 0xC        | 0x4      | 0x10         #
# ----------------------------------------------------------------------------------- #
# Total Size x32: 0x10 (16 Bytes)       | Total Size x64: 0x18 (24 Bytes)             #
# ----------------------------------------------------------------------------------- #


# ----------------------------------------------------------------------------------- #
#                                                                                     #
#                                                                                     #
#                                                                                     #
#  Windows API Definitions                                                            #
#                                                                                     #
#                                                                                     #
#                                                                                     #
# ----------------------------------------------------------------------------------- #

Add-Type @"
    using System;
    using System.Security;
    using System.Runtime.InteropServices;

    public static class ADVAPI32
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(
            IntPtr lpSystemName,
            string lpName,
            ref long lpLuid
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            IntPtr NewState,
            UInt32 BufferLengthInBytes,
            IntPtr PreviousState,
            IntPtr ReturnLengthInBytes
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImpersonateNamedPipeClient(
            IntPtr hNamedPipe
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RevertToSelf();
    }

    public static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
"@

# ----------------------------------------------------------------------------------- #
#                                                                                     #
#                                                                                     #
#                                                                                     #
#  Spawn Interactive System Process Script Block                                      #
#  (Stager)                                                                           #
#                                                                                     #
#                                                                                     #
# ----------------------------------------------------------------------------------- #

$InvokeInteractiveProcess_ScriptBlock = {
    Add-Type @"
        using System;
        using System.Security;
        using System.Runtime.InteropServices;

        public static class ADVAPI32
        {
            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CreateProcessAsUser(
                IntPtr hToken,
                IntPtr lpApplicationName,
                string lpCommandLine,
                IntPtr lpProcessAttributes,
                IntPtr lpThreadAttributes,
                bool bInheritHandles,
                uint dwCreationFlags,
                IntPtr lpEnvironment,
                IntPtr lpCurrentDirectory,
                IntPtr lpStartupInfo,
                IntPtr lpProcessInformation
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool DuplicateTokenEx(
                IntPtr hExistingToken,
                uint dwDesiredAccess,
                IntPtr lpTokenAttributes,
                byte ImpersonationLevel,
                byte TokenType,
                ref IntPtr phNewToken
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
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
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseHandle(IntPtr handle);
        }

        public static class WTSAPI32
        {
            [DllImport("wtsapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
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
"@

    function Get-ActiveDesktopSessionId
    {
        $activeSessionId = 0xFFFFFFFF

        $pSessionArray = [IntPtr]::Zero
        $sessionCount = 0

        if (-not [WTSAPI32]::WTSEnumerateSessions([IntPtr]::Zero, 0, 1, [ref]$pSessionArray, [ref]$sessionCount))
        {
            throw [WinAPIException]::New("WTSEnumerateSessions")
        }
        try
        {
            if ([Environment]::Is64BitProcess)
            {
                $structSize = 0x18
                $structOffset_State = 0x10
            }
            else
            {
                $structSize = 0xc
                $structOffset_State = 0x8
            }

            for ($i = 0; $i -lt $sessionCount; $i++)
            {
                $pOffset = [IntPtr]([Int64]$pSessionArray + ($i * $structSize))

                $curSessionId = [System.Runtime.InteropServices.Marshal]::ReadInt32($pOffset, 0x0)
                $curSessionState = [System.Runtime.InteropServices.Marshal]::ReadInt32($pOffset, $structOffset_State)

                $WTS_CONNECTSTATE_CLASS_WTSActive = 0
                if ($curSessionState -eq $WTS_CONNECTSTATE_CLASS_WTSActive)
                {
                    $activeSessionId = $curSessionId

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

        return $activeSessionId
    }

    function Invoke-InteractiveSystemProcess
    {
        param(
            [string] $CommandLine = "powershell.exe",

            [switch] $Hide
        )

        if (-not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
        {
            return
        }

        $newToken = [IntPtr]::Zero
        try
        {
            $token = [Security.Principal.WindowsIdentity]::GetCurrent().Token

            $MAXIMUM_ALLOWED = 0x02000000
            $SECURITY_IMPERSONATION_LEVEL_SecurityImpersonation = 0x2
            $TOKEN_TYPE_TokenPrimary = 0x1

            if (-not [ADVAPI32]::DuplicateTokenEx(
                $token,
                $MAXIMUM_ALLOWED,
                [IntPtr]::Zero,
                $SECURITY_IMPERSONATION_LEVEL_SecurityImpersonation,
                $TOKEN_TYPE_TokenPrimary,
                [ref]$newToken)
            )
            {
                throw [WinAPIException]::New("DuplicateTokenEx")
            }

            $activeSessionId = Get-ActiveDesktopSessionId

            $TOKEN_INFORMATION_CLASS_TokenSessionId = 0xc

            if (-not [ADVAPI32]::SetTokenInformation(
                $newToken,
                $TOKEN_INFORMATION_CLASS_TokenSessionId,
                [ref]$activeSessionId,
                [Runtime.InteropServices.Marshal]::SizeOf($activeSessionId))
            )
            {
                throw [WinAPIException]::New("SetTokenInformation")
            }

            $STARTF_USESHOWWINDOW = 0x1
            $SW_SHOW = 0x5
            $SW_HIDE = 0x0

            if ([Environment]::Is64BitProcess)
            {
                # STARTUP_INFO x64
                $STARTUPINFO_structSize = 0x68
                $STARTUPINFO_dwFlags = 0x3c
                $STARTUPINFO_wShowWindow = 0x40

                # PROCESS_INFORMATION x64
                $PROCESS_INFORMATION_structSize = 0x18
                $PROCESS_INFORMATION_dwProcessId = 0x10
                $PROCESS_INFORMATION_hThread = 0x8
            }
            else
            {
                # STARTUP_INFO x32
                $STARTUPINFO_structSize = 0x44
                $STARTUPINFO_dwFlags = 0x2c
                $STARTUPINFO_wShowWindow = 0x30

                # PROCESS_INFORMATION x32
                $PROCESS_INFORMATION_structSize = 0x10
                $PROCESS_INFORMATION_dwProcessId = 0x8
                $PROCESS_INFORMATION_hThread = 0x4
            }

            $pSTARTUPINFO = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($STARTUPINFO_structSize)
            $pPROCESS_INFORMATION = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PROCESS_INFORMATION_structSize)
            try
            {
                Invoke-ZeroMemory -MemoryOffset $pSTARTUPINFO -Size $STARTUPINFO_structSize
                Invoke-ZeroMemory -MemoryOffset $pPROCESS_INFORMATION -Size $PROCESS_INFORMATION_structSize

                # STARTUPINFO Structure Initialization
                [System.Runtime.InteropServices.Marshal]::WriteInt32(
                    $pSTARTUPINFO,
                    0x0,
                    $STARTUPINFO_structSize
                )

                [System.Runtime.InteropServices.Marshal]::WriteInt32(
                    $pSTARTUPINFO,
                    $STARTUPINFO_dwFlags,
                    $STARTF_USESHOWWINDOW -bor $STARTF_USESTDHANDLES
                )

                [System.Runtime.InteropServices.Marshal]::WriteInt16(
                    $pSTARTUPINFO,
                    $STARTUPINFO_wShowWindow,
                    $(if ($Hide) {$SW_HIDE} else {$SW_SHOW})
                )

                # Start new process as SYSTEM (Interactive Session)
                $CREATE_NEW_CONSOLE = 0x10

                if (-not [ADVAPI32]::CreateProcessAsUser(
                    $newToken,
                    [IntPtr]::Zero,
                    $CommandLine,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero,
                    $false,
                    $CREATE_NEW_CONSOLE,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero,
                    $pSTARTUPINFO,
                    $pPROCESS_INFORMATION
                ))
                {
                    throw [WinAPIException]::New("CreateProcessAsUser")
                }

                # Read Process Information
                $processId = [System.Runtime.InteropServices.Marshal]::ReadInt32(
                    $pPROCESS_INFORMATION,
                    $PROCESS_INFORMATION_dwProcessId
                )

                $hProcess = [System.Runtime.InteropServices.Marshal]::ReadIntPtr(
                    $pPROCESS_INFORMATION,
                    0x0
                )

                $hThread = [System.Runtime.InteropServices.Marshal]::ReadIntPtr(
                    $pPROCESS_INFORMATION,
                    $PROCESS_INFORMATION_hThread
                )

                # Close returned handles, it is recommended by Microsoft documentation
                $null = [Kernel32]::CloseHandle($hThread)
                $null = [Kernel32]::CloseHandle($hProcess)

                return [string]::Format("Success: New process launched with process id: '{0}'", $processId)
            }
            finally
            {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pSTARTUPINFO)
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pPROCESS_INFORMATION)
            }
        }
        catch
        {
            return "Error: " + $_.Exception.Message
        }
        finally
        {
            if ($newToken -ne [IntPtr]::Zero)
            {
                $null = [Kernel32]::CloseHandle($newToken)
            }
        }
    }
}

# ----------------------------------------------------------------------------------- #
#                                                                                     #
#                                                                                     #
#                                                                                     #
#  Classes                                                                            #
#                                                                                     #
#                                                                                     #
#                                                                                     #
# ----------------------------------------------------------------------------------- #

$WinAPIException_ScriptBlock = {
    class WinAPIException: System.Exception {
        WinAPIException([string] $ApiName) : base (
            [string]::Format(
                "WinApi Exception -> {0}, LastError: {1}",
                $ApiName,
                [System.Runtime.InteropServices.Marshal]::GetLastWin32Error().ToString()
            )
        )
        {}
    }
}
. $WinAPIException_ScriptBlock

# ----------------------------------------------------------------------------------- #
#                                                                                     #
#                                                                                     #
#                                                                                     #
#  Internal Functions                                                                 #
#                                                                                     #
#                                                                                     #
#                                                                                     #
# ----------------------------------------------------------------------------------- #

$InvokeZeroMemory_ScriptBlock = {
    function Invoke-ZeroMemory
    {
        param(
            [IntPtr] $MemoryOffset,
            [int] $Size
        )

        for ($i = 0; $i -lt $Size; $i++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryOffset, $i, 0x0)
        }
    }
}
. $InvokeZeroMemory_ScriptBlock

function Test-SystemImpersonation
{
    <#
        .SYNOPSIS
            Check if current user is correctly impersonating SYSTEM user.
                - ImpersonationLevel: Impersonate
                - IsSystem: True
    #>
    $isSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
    $impersonationLevel = [System.Security.Principal.WindowsIdentity]::GetCurrent().ImpersonationLevel

    return ($impersonationLevel -eq [System.Management.ImpersonationLevel]::Impersonate) -and $isSystem
}

function Test-Administrator
{
    <#
        .SYNOPSIS
            Check if current user has administrator privilege. This privilege is required to register a
            SYSTEM user scheduled task.
    #>
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )

    return $windowsPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Test-AdministratorOrRaise
{
    <#
        .SYNOPSIS
            Call `Test-Administrator` and raise an exception if the user is not an administrator.
    #>
    if (-not (Test-Administrator))
    {
        throw "Insufficient Privilege: You must have administrator privilege to perform this action."
    }
}

function Get-RandomString
{
    <#
        .SYNOPSIS
            Return a random string composed of a-Z and 0-9
    #>
    $charList = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    return -join ((1..15) | ForEach-Object { Get-Random -Input $charList.ToCharArray() })
}

function Set-CurrentProcessPrivilege
{
    <#
        .SYNOPSIS
            Adjust current process privilege.
    #>
    param(
        [Parameter(Mandatory=$True)]
        $PrivilegeName,

        [bool] $Enable = $true
    )

    $luid = 0

    $result = [ADVAPI32]::LookupPrivilegeValue(
        [IntPtr]::Zero,
        $PrivilegeName,
        [ref] $luid
    )
    if (-not $result)
    {
        throw [WinAPIException]::New("LookupPrivilegeValue")
    }

    $SE_PRIVILEGE_ENABLED = 0x2

    if ($Enable)
    {
        $attr = $SE_PRIVILEGE_ENABLED
    }
    else
    {
        $attr = 0x0
    }

    if ([Environment]::Is64BitProcess)
    {
        # TokenPrivilege Structure x64
        $tokenPrivilege_structSize = 0x18
        $tokenPrivilege_LuidOffset = 0x8
        $tokenPrivilege_AttributesOffset = 0x10
    }
    else
    {
        # TokenPrivilege Structure x32
        $tokenPrivilege_structSize = 0x10
        $tokenPrivilege_LuidOffset = 0x4
        $tokenPrivilege_AttributesOffset = 0xC
    }

    $tokenPrivilege = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tokenPrivilege_structSize)
    try
    {
        Invoke-ZeroMemory -MemoryOffset $tokenPrivilege -Size $tokenPrivilege_structSize

        [System.Runtime.InteropServices.Marshal]::WriteInt32(
            $tokenPrivilege,
            0,
            1
        )

        [System.Runtime.InteropServices.Marshal]::WriteInt64(
            $tokenPrivilege,
            $tokenPrivilege_LuidOffset,
            $luid
        )

        [System.Runtime.InteropServices.Marshal]::WriteInt32(
            $tokenPrivilege,
            $tokenPrivilege_AttributesOffset,
            $attr
        )

        $result = [ADVAPI32]::AdjustTokenPrivileges(
            [Security.Principal.WindowsIdentity]::GetCurrent().Token,
            $false,
            $tokenPrivilege,
            0,
            [IntPtr]::Zero,
            [IntPtr]::Zero
        )
        if (-not $result)
        {
            throw [WinAPIException]::New("AdjustTokenPrivileges")
        }
    }
    finally
    {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($tokenPrivilege)
    }

    return ([System.Runtime.InteropServices.Marshal]::GetLastWin32Error() -eq 0)
}

function Write-CurrentUser
{
    <#
        .SYNOPSIS
            Write the current user information to the console.

        .DESCRIPTION
            This function will write the current user name and token to the console.
            If the current user is the result of an impersonation, it will display "Impersonated" next to the user name.
    #>
    Write-Host "Current User: " -NoNewLine
    Write-Host ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -ForegroundColor Green -NoNewLine
    Write-Host " (" -NoNewLine
    Write-Host ([Security.Principal.WindowsIdentity]::GetCurrent().Token) -NoNewLine -ForegroundColor Cyan


    if (Test-SystemImpersonation)
    {
        Write-Host " - Impersonated" -NoNewLine
    }

    Write-Host ")"
}

# ----------------------------------------------------------------------------------- #
#                                                                                     #
#                                                                                     #
#                                                                                     #
#  Exported Functions                                                                 #
#                                                                                     #
#                                                                                     #
#                                                                                     #
# ----------------------------------------------------------------------------------- #

function Invoke-SystemCommand
{
    <#
        .SYNOPSIS
            Execute an application as SYSTEM user with the specified argument(s).

        .DESCRIPTION
            Impersonation is not required for this function. It exclusively relies on Task Scheduler to execute action.

            It is important to note that executed application will run in the background and will not be visible to the user.
            (Non-interactive)

        .PARAMETER Application
            Program to execute as System.

        .PARAMETER Argument
            Optional argument(s) to pass to program to execute.
    #>
    param(
        [string] $Application = "powershell.exe",
        [string] $Argument = "-Command ""whoami | Out-File C:\result.txt"""
    )

    Test-AdministratorOrRaise

    $taskName = Get-RandomString

    if ($Argument)
    {
        $action = New-ScheduledTaskAction -Execute $Application -Argument $Argument
    }
    else
    {
        $action = New-ScheduledTaskAction -Execute $Application
    }

    $null = Register-ScheduledTask -Force -Action $action -TaskName $taskName -User "NT AUTHORITY\SYSTEM"
    try
    {
        Start-ScheduledTask $taskName
    }
    finally
    {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}

function Invoke-InteractiveSystemProcess
{
    <#
        .SYNOPSIS
            Spawn a SYSTEM process in Active Microsoft Windows Session.
    #>
    param (
        [string] $CommandLine = "powershell.exe",
        [switch] $Hide
    )

    $stager_ScriptBlock = {
        try
        {
            $pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream(".", "PIPENAME", [System.IO.Pipes.PipeDirection]::InOut)

            $pipeClient.Connect(5 * 1000)

            $reader = New-Object System.IO.StreamReader($pipeClient)

            $writer = New-Object System.IO.StreamWriter($pipeClient)
            $writer.AutoFlush = $true

            $nextStage = $reader.ReadLine()

            $result = Invoke-Expression([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($nextStage)))

            $writer.WriteLine($result)
        }
        finally
        {
            if ($pipeClient)
            {
                $pipeClient.Dispose()
            }
        }
    }

    $pipeName = Get-RandomString

    $encodedBlock =  [Convert]::ToBase64String(
        [System.Text.Encoding]::ASCII.GetBytes(
            ($stager_ScriptBlock.ToString()).replace('PIPENAME', $pipeName)
        )
    )

    $command = [string]::Format(
        "Invoke-Expression([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{0}')))",
        $encodedBlock
    )

    Invoke-SystemCommand -Argument $command

    try
    {
        $pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::InOut)

        $pipeServer.WaitForConnection()

        $writer = New-Object System.IO.StreamWriter($pipeServer)
        $writer.AutoFlush = $true

        $reader = New-Object System.IO.StreamReader($pipeServer)

        # Create our final payload that will be executed in the context of the SYSTEM user
        $payload = $InvokeInteractiveProcess_ScriptBlock.ToString() +
        $WinAPIException_ScriptBlock.ToString() +
        $InvokeZeroMemory_ScriptBlock.ToString() +
        [string]::Format(
            "Invoke-InteractiveSystemProcess -CommandLine ""{0}"" {1}",
            $CommandLine,
            $(if ($Hide) {"-Hide"} else {""})
        )

        $encoded_payload = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($payload))

        $writer.WriteLine($encoded_payload)

        # Display remote process task(s) output
        Write-Host ($reader.ReadLine())
    }
    finally
    {
        if ($pipeServer)
        {
            $pipeServer.Dispose()
        }
    }
}

function Invoke-ImpersonateSystem
{
    <#
        .SYNOPSIS
            Impersonate SYSTEM User using NamedPipes. After calling this command,
            current thread will impersonate the SYSTEM User. You will be able to spawn a new
            process as SYSTEM using the impersonated token.

        .DESCRIPTION
            Use the Invoke-RevertToSelf to stop impersonation.
    #>
    Test-AdministratorOrRaise

    if (Test-SystemImpersonation)
    {
        throw "You are already impersonating SYSTEM user. Use `Invoke-RevertToSelf` to stop impersonation."
    }

    $stager_ScriptBlock = {
        try
        {
            $pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream(".", "PIPENAME", [System.IO.Pipes.PipeDirection]::Out)

            $pipeClient.Connect(10 * 1000)

            $writer = New-Object System.IO.StreamWriter($pipeClient)
            $writer.AutoFlush = $true

            $writer.Write("A")
        }
        finally
        {
            if ($writer)
            {
                $writer.Close()
            }

            if ($pipeClient)
            {
                $pipeClient.Dispose()
            }
        }
    }

    try
    {
        $null = Set-CurrentProcessPrivilege -PrivilegeName "SeImpersonatePrivilege"
    }
    catch
    {}

    try
    {
        Write-CurrentUser

        $pipeName = Get-RandomString

        $pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::In)

        $encodedBlock =  [Convert]::ToBase64String(
            [System.Text.Encoding]::ASCII.GetBytes(
                ([string]$stager_ScriptBlock).replace('PIPENAME', $pipeName)
            )
        )

        $command = [string]::Format(
            "Invoke-Expression([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{0}')))",
            $encodedBlock
        )

        Invoke-SystemCommand -Argument $command

        $pipeServer.WaitForConnection()

        $reader = New-Object System.IO.StreamReader($pipeServer)

        $null = $reader.Read()

        $pipeHandle = $pipeServer.SafePipeHandle.DangerousGetHandle()

        if (-not [ADVAPI32]::ImpersonateNamedPipeClient($pipeHandle))
        {
            throw [WinAPIException]::New("ImpersonateNamedPipeClient")
        }

        if (-not (Test-SystemImpersonation))
        {
            throw "Failed to impersonate SYSTEM user."
        }

        Write-Host "SYSTEM User Impersonation Successful."

        Write-CurrentUser
    }
    finally
    {
        if ($reader)
        {
            $reader.Close()
        }

        if ($pipeServer)
        {
            $pipeServer.Dispose()
        }
    }
}

function Invoke-RevertToSelf
{
    <#
        .SYNOPSIS
            Stop impersonating user.
    #>

    if (-not (Test-SystemImpersonation))
    {
        throw "You are not impersonating SYSTEM user."
    }

    Write-Host "Stop impersonating user..."

    if (-not [ADVAPI32]::RevertToSelf())
    {
        throw [WinAPIException]::New("RevertToSelf")
    }

    Write-Host "Impersonation Stopped."
    Write-CurrentUser
}

try {
    Export-ModuleMember -Function Invoke-SystemCommand
    Export-ModuleMember -Function Invoke-InteractiveSystemProcess
    Export-ModuleMember -Function Invoke-ImpersonateSystem
    Export-ModuleMember -Function Invoke-RevertToSelf
} catch {}