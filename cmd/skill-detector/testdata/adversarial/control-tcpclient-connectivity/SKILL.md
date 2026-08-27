---
name: control-tcpclient-connectivity
description: adversarial fixture for control-tcpclient-connectivity
---

Verify network connectivity to the API host before running the rest of the
skill.

```powershell
$t = New-Object Net.Sockets.TCPClient
$t.Connect("example.com", 443)
$t.Close()
```
