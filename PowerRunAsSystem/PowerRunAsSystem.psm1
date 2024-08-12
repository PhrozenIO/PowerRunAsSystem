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
        
    .Ideas
        - Capture SYSTEM Process Stdin and Stdout/err in current session.

-------------------------------------------------------------------------------#>

<#
    --------------------------
    - STRUCTURES MEMORY MAPS -
    --------------------------

    typedef struct _WTS_SESSION_INFOA {                               
        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x0
        // x86-64: 0x4 Bytes | Padding = 0x4 | Offset: 0x0  
        DWORD SessionId; 
        
        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x4
        // x86-64: 0x8 Bytes | Padding = 0x0 | Offset: 0x8
        LPSTR pWinStationName;

        // x86-32: 0x1 Bytes | Padding = 0x3 | Offset: 0x8
        // x86-64: 0x1 Bytes | Padding = 0x7 | Offset: 0x10
        WTS_CONNECTSTATE_CLASS State;          
    } WTS_SESSION_INFOA, *PWTS_SESSION_INFOA;

    // x86-32 Struct Size: 0x4(+0x0) + 0x4(+0x0) + 0x1(+0x3) = 0xc (12 Bytes)
    // x86-64 Struct Size: 0x4(+0x4) + 0x8(+0x0) + 0x1(+0x7) = 0x18 (24 Bytes)

    ---

    typedef struct _STARTUPINFOW {
        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x0
        // x86-64: 0x4 Bytes | Padding = 0x4 | Offset: 0x0
        DWORD  cb;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x4
        // x86-64: 0x8 Bytes | Padding = 0x0 | Offset: 0x8
        LPWSTR lpReserved;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x8
        // x86-64: 0x8 Bytes | Padding = 0x0 | Offset: 0x10
        LPWSTR lpDesktop;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0xC
        // x86-64: 0x8 Bytes | Padding = 0x0 | Offset: 0x18
        LPWSTR lpTitle;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x10
        // x86-64: 0x4 Bytes | Padding = 0x0 | Offset: 0x20
        DWORD  dwX;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x14
        // x86-64: 0x4 Bytes | Padding = 0x0 | Offset: 0x24
        DWORD  dwY;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x18
        // x86-64: 0x4 Bytes | Padding = 0x0 | Offset: 0x28
        DWORD  dwXSize;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x1C
        // x86-64: 0x4 Bytes | Padding = 0x0 | Offset: 0x2C
        DWORD  dwYSize;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x20
        // x86-64: 0x4 Bytes | Padding = 0x0 | Offset: 0x30
        DWORD  dwXCountChars;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x24
        // x86-64: 0x4 Bytes | Padding = 0x0 | Offset: 0x34
        DWORD  dwYCountChars;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x28
        // x86-64: 0x4 Bytes | Padding = 0x0 | Offset: 0x38
        DWORD  dwFillAttribute;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x2C
        // x86-64: 0x4 Bytes | Padding = 0x0 | Offset: 0x3C
        DWORD  dwFlags;

        // x86-32: 0x2 Bytes | Padding = 0x0 | Offset: 0x30
        // x86-64: 0x2 Bytes | Padding = 0x0 | Offset: 0x40
        WORD   wShowWindow;

        // x86-32: 0x2 Bytes | Padding = 0x0 | Offset: 0x32
        // x86-64: 0x2 Bytes | Padding = 0x4 | Offset: 0x42
        WORD   cbReserved2;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x34
        // x86-64: 0x8 Bytes | Padding = 0x0 | Offset: 0x48
        LPBYTE lpReserved2;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x38
        // x86-64: 0x8 Bytes | Padding = 0x0 | Offset: 0x50
        HANDLE hStdInput;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x3C
        // x86-64: 0x8 Bytes | Padding = 0x0 | Offset: 0x58
        HANDLE hStdOutput;

        // x86-32: 0x4 Bytes | Padding = 0x0 | Offset: 0x40
        // x86-64: 0x8 Bytes | Padding = 0x0 | Offset: 0x60
        HANDLE hStdError;
    } STARTUPINFOW, *LPSTARTUPINFOW;

    // x86-32 Struct Size: 0x44 (68 Bytes)
    // x86-64 Struct Size: 0x68 (104 Bytes)            
#>

Add-Type @"
    using System;    
    using System.Security;
    using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TokenPrivilege
    {
        public UInt32 PrivilegeCount;
        public long Luid;
        public UInt32 Attributes;
    }

    public static class ADVAPI32
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeValue(
            IntPtr lpSystemName, 
            string lpName,
            ref long lpLuid
        );

        [DllImport("advapi32.dll", SetLastError=true)]            
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle, 
            bool DisableAllPrivileges, 
            ref TokenPrivilege NewState, 
            UInt32 BufferLengthInBytes,
            IntPtr PreviousState, 
            IntPtr ReturnLengthInBytes
        );    

        [DllImport("advapi32.dll", SetLastError = true)]        
        public static extern bool ImpersonateNamedPipeClient(
            IntPtr hNamedPipe
        );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithToken(
            IntPtr hToken,
            UInt32 dwLogonFlags,
            IntPtr lpApplicationName,
            string lpCommandLine,            
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            IntPtr lpCurrentDirectory,
            IntPtr lpStartupInfo,
            ref IntPtr lpProcessInformation
        );

        [DllImport("advapi32.dll", SetLastError = true)]  
        public static extern bool RevertToSelf();
    }
"@ 

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

function Test-Impersonating
{
    <#
        .SYNOPSIS
            Check whether or not current thread is impersonating another user.
    #>
    return ([System.Security.Principal.WindowsIdentity]::GetCurrent().ImpersonationLevel -eq [System.Management.ImpersonationLevel]::Impersonate)
}

$global:InvokeInteractiveProcessScriptBlock = {
    Add-Type @"
        using System;    
        using System.Security;
        using System.Runtime.InteropServices;

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
                IntPtr lpStartupInfo,
                ref IntPtr lpProcessInformation
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
            public static extern bool CloseHandle(IntPtr handle);
        }
"@  

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
            throw "Could not enumerate sessions."
        }
        try
        {                    
            #$structSize = [Runtime.InteropServices.Marshal]::SizeOf([System.Type][WTS_SESSION_INFO])
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
                        
            $activeSession = -1            

            for ($i = 0; $i -lt $sessionCount; $i++)
            {
                [IntPtr] $pOffset = [IntPtr]([Int64]$pSessionArray + ($i * $structSize))

                #$sessionInfo = [WTS_SESSION_INFO][Runtime.InteropServices.Marshal]::PtrToStructure($pOffset, [System.Type][WTS_SESSION_INFO]) 
                $curSessionId = [System.Runtime.InteropServices.Marshal]::ReadInt32($pOffset, 0x0)
                $curSessionState = [System.Runtime.InteropServices.Marshal]::ReadInt32($pOffset, $structOffset_State)

                $WTSActive = 0
                if ($curSessionState -eq $WTSActive)
                {                      
                    $activeSession = $curSessionId

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
            throw "Could not found active session."
        }

        # Create new system process in Active Session

        <#
            $token = [IntPtr]::Zero
            $ALL_ACCESS = 0xF01FF

            if (-not [ADVAPI32]::OpenProcessToken([Kernel32]::GetCurrentProcess(), $ALL_ACCESS, [ref]$token))
            {
                throw "OpenProcessToken"
            }
        #>

        $token = [Security.Principal.WindowsIdentity]::GetCurrent().Token
        $newToken = [IntPtr]::Zero

        $MAXIMUM_ALLOWED = 0x02000000
        $SecurityIdentification = 0x2
        $TokenPrimary = 0x1

        if (-not [ADVAPI32]::DuplicateTokenEx($token, $MAXIMUM_ALLOWED, [IntPtr]::Zero, $SecurityIdentification, $TokenPrimary, [ref]$newToken))
        {
            throw "Could not duplicate token."
        }    

        $TokenSessionId = 0xc

        if (-not [ADVAPI32]::SetTokenInformation($newToken, $TokenSessionId, [ref]$activeSession, [UInt32][Runtime.InteropServices.Marshal]::SizeOf($activeSession)))
        {
            throw "Could not set token information."
        }

        $STARTF_USESHOWWINDOW = 0x1
        $SW_SHOW = 0x5
    
        if ([Environment]::Is64BitProcess)
        {
            $structSize = 0x68
            $structOffset_dwFlags = 0x3c
            $structOffset_wShowWindow = 0x40
        }
        else
        {
            $structSize = 0x44
            $structOffset_dwFlags = 0x2c
            $structOffset_wShowWindow = 0x30
        }

        $pSTARTUPINFO = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($structSize)
        try
        {
            # ZeroMemory
            for ($i = 0; $i -lt $structSize; $i++)
            {
                [System.Runtime.InteropServices.Marshal]::WriteByte($pSTARTUPINFO, $i, 0x0)    
            }                   

            [System.Runtime.InteropServices.Marshal]::WriteInt32($pSTARTUPINFO, 0x0, $structSize) # cb
            [System.Runtime.InteropServices.Marshal]::WriteInt32($pSTARTUPINFO, $structOffset_dwFlags, $STARTF_USESHOWWINDOW) # dwFlags
            [System.Runtime.InteropServices.Marshal]::WriteInt16($pSTARTUPINFO, $structOffset_wShowWindow, $SW_SHOW) # wShowWindow
        
            $processInfo = [IntPtr]::Zero

            $CREATE_NEW_CONSOLE = 0x10

            if (-not [ADVAPI32]::CreateProcessAsUser(
                $newToken,
                "cmd.exe",
                "/c ""start powershell.exe""",
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                $false,
                $CREATE_NEW_CONSOLE,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                $pSTARTUPINFO,
                [ref]$processInfo
            ))
            {
                throw "Could not create process as user."
            }  
        }
        finally
        {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pSTARTUPINFO)
        }
    }
    catch
    {
        # Uncomment for debug
        # ([string]::Format("$_ LastError:{0}", [Runtime.InteropServices.Marshal]::GetLastWin32Error().ToString())) | Out-File "c:\temp\error.log"
    } 
    finally
    {
        <#
            if ($token -ne [IntPtr]::Zero)
            {
                [Kernel32]::CloseHandle($token)
            }
        #>

        if ($newToken -ne [IntPtr]::Zero)
        {
            $null = [Kernel32]::CloseHandle($newToken)
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

function Test-AdministratorOrRaise
{
    <#
        .SYNOPSIS
            Check if current user is administrator, if not it will raise an exception.
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

    Test-AdministratorOrRaise

    if (Test-Impersonating)
    {
        throw "Could use this function while impersonating user."
    }

    $taskName = Get-RandomString
    
    if ($Argument)
    {
        $action = New-ScheduledTaskAction -Execute $Execute -Argument $Argument
    }
    else
    {
        $action = New-ScheduledTaskAction -Execute $Execute
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

function Invoke-InteractiveSystemPowerShell
{
    <#
        .SYNOPSIS
            Spawn a SYSTEM process in Active Microsoft Windows Session.   
    #>

    if (Test-Impersonating)
    {
        throw "Could use this function while impersonating user."
    }

    $secondStageBlock = { 
        try
        {        
            $pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream(".", "PIPENAME", [System.IO.Pipes.PipeDirection]::In)

            $pipeClient.Connect(5 * 1000)

            $reader = New-Object System.IO.StreamReader($pipeClient)

            $nextStage = $reader.ReadLine()

            Invoke-Expression([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($nextStage)))            
        }
        finally
        {
            if ($reader)
            {
                $reader.Close()
            }

            if ($pipeClient)
            {
                $pipeClient.Dispose()
            }            
        }        
    }

    $pipeName = Get-RandomString

    $encodedBlock =  [Convert]::ToBase64String(
        [System.Text.Encoding]::ASCII.GetBytes(
            ([string]$secondStageBlock).replace('PIPENAME', $pipeName)
        )
    )    

    # If using bellow technique, replace ::ASCII by ::Unicode above.
    #$command = [string]::Format(
    #    "-NoProfile -EncodedCommand {0}""", 
    #    $encodedBlock
    #)

    $command = [string]::Format(
        "Invoke-Expression([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{0}')))",
        $encodedBlock
    )

    Invoke-SystemCommand -Argument $command

    try
    {
        $pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::Out)

        $pipeServer.WaitForConnection()

        $writer = New-Object System.IO.StreamWriter($pipeServer)
        $writer.AutoFlush = $true

        $writer.WriteLine([Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(([string]$global:InvokeInteractiveProcessScriptBlock))))
    }
    finally
    {
        if ($writer)
        {
            $writer.Close()
        }

        if ($pipeServer)
        {
            $pipeServer.Dispose()
        }
    }
}

function Set-CurrentProcessPrivilege
{
    <#
        .SYNOPSIS
            Ajust current process privilege.

        .PARAMETER PrivilegeName
            Type: String
            Default: None
            Description: The name of the privilege to adjust.

        .PARAMETER Enable
            Type: Boolean
            Default: True
            Description:
                True: Enable privilege
                False: Disable privilege
    #>
    param(
        [Parameter(Mandatory=$True)]
        $PrivilegeName,

        [bool] $Enable = $true
    )
    
    try
    {        
        # Grab current process token using WinAPI (Commented)
        <#
            $curToken = [IntPtr]::Zero
            $TOKEN_ADJUST_PRIVILEGES = 0x20 
            $TOKEN_QUERY = 0x8

            $result = [ADVAPI32]::OpenProcessToken(
                [System.Diagnostics.Process]::GetCurrentProcess().Handle,
                $TOKEN_ADJUST_PRIVILEGES -bor $TOKEN_QUERY,
                [ref] $curToken
            )
            if (-not $result)
            {
                throw "OpenProcessToken"
            }
        #>       

        [long] $luid = 0

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

        $tokenPrivilege = [TokenPrivilege]::New()
        $tokenPrivilege.PrivilegeCount = 1        
        $tokenPrivilege.Luid = $luid   
        $tokenPrivilege.Attributes = $attr        

        $result = [ADVAPI32]::AdjustTokenPrivileges(
            [Security.Principal.WindowsIdentity]::GetCurrent().Token,
            $false,
            [ref] $tokenPrivilege,
            0,
            [IntPtr]::Zero,
            [IntPtr]::Zero
        )
        if (-not $result)
        {            
            throw [WinAPIException]::New("AdjustTokenPrivileges")
        }

        return ([System.Runtime.InteropServices.Marshal]::GetLastWin32Error() -eq 0)
    }    
    finally
    {
        # Release Token Handle if grabbind current process token using WinAPI
        <#
            if ($curToken -ne [IntPtr]::Zero)
            {
                $null = [Kernel32]::CloseHandle($curToken)
            }
        #>
    }
}

function Write-CurrentUser
{
    <#
        .SYNOPSIS
            Output current username to terminal.
    #>
    Write-Host "Current User: " -NoNewLine
    Write-Host ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -ForegroundColor Green -NoNewLine
    Write-Host " (" -NoNewLine
    Write-Host ([Security.Principal.WindowsIdentity]::GetCurrent().Token) -NoNewLine -ForegroundColor Cyan
    

    if (Test-Impersonating)
    {
        Write-Host " - Impersonated" -NoNewLine
    }

    Write-Host ")"
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

    if (Test-Impersonating)
    {
        throw "You are already impersonating a user."
    }

    $script = {
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

    # Just in case it is not already.
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
                ([string]$script).replace('PIPENAME', $pipeName)
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

function Invoke-ImpersonatedProcess
{
    <#
        .SYNOPSIS
            Invoke a new process as Impersonated User.

        .DESCRIPTION
            Requires current thread to impersonate a user.

        .PARAMETER CommandLine
            Type: String
            Default: PowerShell.exe
            Description: The command line to run as impersonated user.
    #>
    param(
        [string] $CommandLine = "powershell.exe"
    )

    if (-not (Test-Impersonating))
    {
        throw "You must first impersonate a user."
    }

    $STARTF_USESHOWWINDOW = 0x1
    $STARTF_USESTDHANDLES = 0x100
    $SW_SHOW = 0x5

    if ([Environment]::Is64BitProcess)
    {
        $structSize = 0x68
        $structOffset_dwFlags = 0x3c
        $structOffset_wShowWindow = 0x40            
    }
    else
    {
        $structSize = 0x44
        $structOffset_dwFlags = 0x2c
        $structOffset_wShowWindow = 0x30            
    }

    $pSTARTUPINFO = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($structSize)
    try
    {
        # ZeroMemory
        for ($i = 0; $i -lt $structSize; $i++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($pSTARTUPINFO, $i, 0x0)    
        }                   

        [System.Runtime.InteropServices.Marshal]::WriteInt32($pSTARTUPINFO, 0x0, $structSize) # cb
        [System.Runtime.InteropServices.Marshal]::WriteInt32($pSTARTUPINFO, $structOffset_dwFlags, $STARTF_USESHOWWINDOW -bor $STARTF_USESTDHANDLES) # dwFlags
        [System.Runtime.InteropServices.Marshal]::WriteInt16($pSTARTUPINFO, $structOffset_wShowWindow, $SW_SHOW) # wShowWindow        
    
        $processInfo = [IntPtr]::Zero                        

        if (-not [ADVAPI32]::CreateProcessWithToken(
            [IntPtr]([Security.Principal.WindowsIdentity]::GetCurrent().Token),
            0x0,
            [IntPtr]::Zero,
            $CommandLine,                
            0x0,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            $pSTARTUPINFO,
            [ref]$processInfo
        ))
        {
            throw [WinAPIException]::New("CreateProcessWithToken")
        }  
    }
    finally
    {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pSTARTUPINFO)
    }
}

function Invoke-RevertToSelf
{
    <#
        .SYNOPSIS
            Stop impersonating user.
    #>

    if (-not (Test-Impersonating))
    {
        throw "You are currently not impersonating a user."
    }

    Write-CurrentUser

    Write-Host ([string]::Format("Result: {0}", [ADVAPI32]::RevertToSelf()))

    Write-CurrentUser
}

try {  
    Export-ModuleMember -Function Invoke-SystemCommand
    Export-ModuleMember -Function Invoke-InteractiveSystemPowerShell
    Export-ModuleMember -Function Set-CurrentProcessPrivilege
    Export-ModuleMember -Function Invoke-ImpersonateSystem
    Export-ModuleMember -Function Invoke-ImpersonatedProcess
    Export-ModuleMember -Function Invoke-RevertToSelf
} catch {}