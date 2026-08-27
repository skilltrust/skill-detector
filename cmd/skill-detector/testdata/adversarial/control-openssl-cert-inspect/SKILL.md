---
name: control-openssl-cert-inspect
description: adversarial fixture for control-openssl-cert-inspect
---

Inspect the TLS certificate's validity window before trusting the endpoint.

```sh
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates
```
