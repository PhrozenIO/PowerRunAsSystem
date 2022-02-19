# PowerRunAsSystem

Run application as system with interactive system process support (active Windows session)

This technique doesn't rely on any external tools and doesn't require a Microsoft Service.

It spawns an `NT Authority/System` process using the Microsoft Windows Task Scheduler then upgrade to Interactive System Process using cool WinApi's (Run in Active Windows Session)

## Example (Spawn a new Interactive PowerShell)

```PowerShell
IEX(Get-Content PowerRunAsSystem.psm1 -Raw)

Invoke-SystemCommand -Argument "IEX(Get-Content C:\Temp\PowerRunAsSystem.psm1 -Raw); Invoke-InteractiveSystemProcess"
```

https://user-images.githubusercontent.com/2520298/154730781-a2c6d7e2-ac9a-40a6-a17d-b8e91fd59fb9.mp4

## Available Functions

### `Invoke-SystemCommand` (Requires to be Administrator User)

Spawn a new SYSTEM Process running in Microsoft Windows Session Id `0` which is not visible on current Desktop.

This function is expected to be used in addition of `Invoke-InteractiveSystemProcess` to spawn a SYSTEM Process in active Windows Session (Active Desktop)

##### ⚙️ Supported Options:

| Parameter               | Type             | Default                                        | Description  |
|-------------------------|------------------|------------------------------------------------|--------------|
| Execute                 | String           | powershell.exe                                 | Program to execute as SYSTEM (Session `0`)  |
| Argument                | String           | -Command "whoami \| Out-File C:\result.txt"    | Optional argument to run with program |

### `Invoke-InteractiveSystemProcess` (Requires to be SYSTEM User)

##### ⚙️ Supported Options:

| Parameter               | Type             | Default                                        | Description  |
|-------------------------|------------------|------------------------------------------------|--------------|
| Execute                 | String           | powershell.exe                                 | Program to execute as SYSTEM (Active Session)  |
