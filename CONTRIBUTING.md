# Contributing to skill-detector

Thanks for wanting to help. A few ground rules before you open a PR.

## Before you start

**Please open an issue first.** This is a spare-time pet project, and I'd
rather we agree on the approach before you sink effort into a PR that
won't land. Drive-by fixes — typos, obvious mistakes, one-line bug fixes —
are fine to send straight.

## What I'm looking for

- **Bug reports** — false positives, missed threats, crashes on edge-case skills
- **New rules** — security checks for threat classes not yet covered
- **New skill formats** — if your skill format isn't recognized, test fixtures + rule tweaks are welcome
- **Doc fixes** — unclear wording, typos, outdated examples

## What I'll probably push back on

- Refactors without a concrete bug or missing feature behind them
- Configurability for hypothetical needs
- New dependencies (Go stdlib + `cobra` + `yaml.v3` is the whole party today — adding more needs a strong reason)
- Style-only changes the linter doesn't already enforce

## Dev setup

See [`docs/development-guide.md`](./docs/development-guide.md) for the full
build, test, lint, and "how to add a rule" walkthrough.

TL;DR:

```bash
make build       # builds ./bin/skill-detector
make test        # runs the full test suite
make lint        # golangci-lint + gosec
make self-scan   # smoke test the built binary on test fixtures
```

## Pull request expectations

- CI must be green (`make lint` + `make test`)
- New behavior comes with a test
- Commit messages explain the *why*, not just the *what*
- Link the issue where we agreed on the approach

## Adding a new security rule

Rules live in `internal/rules/`, one file per rule group. The short version:

1. Create `internal/rules/<name>.go` implementing the `Rule` interface from `rule.go`
2. Register it in `cmd/skill-detector/main.go` — the `newRegistry()` function
3. Add fixtures under `testdata/malicious/<name>/` (triggers the rule) and `testdata/clean/` (does not)
4. Write tests in `internal/rules/<name>_test.go`
5. Run `make test` and `make lint`

Detailed instructions are in [`docs/development-guide.md`](./docs/development-guide.md).

## Reporting security vulnerabilities

If you've found a vulnerability in `skill-detector` *itself* (not in a skill
it scanned), **please do not open a public issue.** File a
[private security advisory](https://github.com/velzepooz/skill-detector/security/advisories/new)
instead.

## Code of conduct

Be decent. No harassment, no personal attacks, no bad-faith arguments. If
someone's making the project unpleasant to work on, I'll ask them to stop,
and if they don't, they're out. That's the whole policy.
