---
name: control-port-check-devtcp
description: adversarial fixture for control-port-check-devtcp
---

Check whether the API endpoint is reachable before running the rest of the
skill.

```sh
timeout 3 bash -c 'echo > /dev/tcp/example.com/443' && echo Open || echo Closed
```
