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
- **A suppression comes with a fixture that abuses it.** If your change stops the scanner
  flagging something — an exemption, a demotion, a narrowed regex — add an adversarial fixture
  that tries to launder a real payload through it, plus a benign twin. See
  [Adversarial Fixtures](./docs/development-guide.md#adversarial-fixtures). A unit test of the
  regex does not substitute: the assertion has to be on the grade a user sees.
- Commit messages explain the *why*, not just the *what*
- Link the issue where we agreed on the approach
- Every commit is signed off (`git commit -s`) — see [Licensing of contributions](#licensing-of-contributions)

## Adding a new security rule

1. Create `pkg/rules/<name>.go` implementing the `Rule` interface from `rule.go`
2. Register it in `pkg/rules/registry.go` — the `DefaultRegistry()` function
3. Add fixtures under `testdata/malicious/<name>/` (triggers the rule) and `testdata/clean/` (does not)
4. Write tests in `pkg/rules/<name>_test.go`
5. Run `make test` and `make lint`

Detailed instructions are in [`docs/development-guide.md`](./docs/development-guide.md).

## Licensing of contributions

`skill-detector` is [MIT licensed](./LICENSE). Contributions are accepted on
those terms, plus one extra grant that keeps the project's licensing options
open.

### Sign off every commit

Add a `Signed-off-by` line to each commit:

```bash
git commit -s -m "your message"
```

That line certifies the [Developer Certificate of Origin
1.1](https://developercertificate.org/) — in short: you wrote the change, or
you have the right to submit it under the project's license.

### Grant to the maintainer

By signing off, you additionally agree that:

> You retain copyright in your contribution. You grant the project maintainer
> a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to
> use, reproduce, modify, publicly display, sublicense, and distribute your
> contribution — including the right to distribute it, and derivative works of
> it, under any license terms the maintainer chooses, including proprietary or
> commercial terms.
>
> You confirm you are legally entitled to grant this. If your employer has
> rights to work you create, you confirm you have permission to contribute on
> their behalf, or that they have waived those rights.

**Why this exists.** The maintainer also runs a commercial service built on
this engine. Without this grant, relicensing the project — or shipping it as
part of a closed product — would require chasing down every past contributor
for permission. Nothing here restricts your own use of your contribution: you
keep copyright and may reuse it however you like.

If you can't agree to this, open an issue and we'll talk before you write code.

## Reporting security vulnerabilities

If you've found a vulnerability in `skill-detector` *itself* (not in a skill
it scanned), **please do not open a public issue.** File a
[private security advisory](https://github.com/velzepooz/skill-detector/security/advisories/new)
instead.

## Code of conduct

Be decent. No harassment, no personal attacks, no bad-faith arguments. If
someone's making the project unpleasant to work on, I'll ask them to stop,
and if they don't, they're out. That's the whole policy.
