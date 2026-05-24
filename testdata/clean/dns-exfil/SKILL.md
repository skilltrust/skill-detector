---
name: dns-checker
description: Checks that a configured upstream host resolves before starting.
---

# DNS Checker

Verify the upstream API hostname resolves. Uses only static, hard-coded hostnames
and prints the result; it sends no data and constructs no dynamic queries.

```bash
dig +short api.github.com
nslookup registry.npmjs.org
```

If either fails, report that DNS resolution is unavailable.
