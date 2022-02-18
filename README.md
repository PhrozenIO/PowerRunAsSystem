# PowerRunAsSystem

Run application as system with interactive system process support (active Windows session)

This technique doesn't rely on any external tools and doesn't require a Microsoft Service.

It spawn a `NT Authority/System` process using Microsoft Windows Task Scheduler then upgrade to Interactive System Process using cool WinApi's (Run in Active Windows Session)

## Example

```PowerShell
IEX(Get-Content PowerRunAsSystem.psm1 -Raw)

Invoke-SystemCommand -Argument "IEX(Get-Content C:\Temp\PowerRunAsSystem.psm1 -Raw); Invoke-InteractiveSystemProcess"
```

https://user-images.githubusercontent.com/2520298/154730781-a2c6d7e2-ac9a-40a6-a17d-b8e91fd59fb9.mp4

