# PowerRunAsSystem

Run application as system with interactive system process support (active Windows session)

This technique doesn't rely on any external tools and doesn't require a Microsoft Service.

It spawns an `NT Authority/System` process using the Microsoft Windows Task Scheduler then upgrade to Interactive System Process using cool WinApi's (Run in Active Windows Session)

![demo](https://user-images.githubusercontent.com/2520298/155295069-3c916877-e5c9-4e8d-a6dd-f13cb3d15f52.png)

---

## Install

You can install this module very easily using PowerShell Gallery:

```powershell
Install-Module -Name PowerRunAsSystem
```

You might need to execute bellow command to allow unsigned script to be executed:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
```

If you don't want to use PowerShell Gallery, you can install and import this module manually and/or use it as script.

## Usage

⚠️ Both commands requires **Administrator Privilege**. 

### Invoke-SystemCommand

```PowerShell
Invoke-SystemCommand -Execute "powershell.exe" -Argument "whoami \| Out-File C:\result.txt"
```

Create a new process (default: `powershell.exe`) running under the context of `NT AUTHORITY/SYSTEM` in Microsoft Windows session id `0`

⚠️ Notice: Session id `0` is not directly accessible through your active desktop, any process running under another session than the active one wont be visible. If you want to spawn a new SYSTEM process under active session, use `Invoke-InteractiveSystemPowerShell` command instead.

##### ⚙️ Supported Options:

| Parameter               | Type             | Default                                        | Description  |
|-------------------------|------------------|------------------------------------------------|--------------|
| Execute                 | String           | powershell.exe                                 | Program to execute as SYSTEM (Session `0`)  |
| Argument                | String           | -Command "whoami \| Out-File C:\result.txt"    | Optional argument to run with program |

---

### Invoke-InteractiveSystemPowerShell

```PowerShell
Invoke-InteractiveSystemPowerShell
```

Create a new **PowerShell** instance running under the context of `NT AUTHORITY/SYSTEM` and visible on your desktop (active session)

## Future Ideas

- Redirect Stdin and Stdout/Stderr to caller (Administrator <--> System).
