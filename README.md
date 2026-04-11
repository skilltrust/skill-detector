# skill-detector

[![CI](https://img.shields.io/github/actions/workflow/status/velzepooz/skill-detector/ci.yml?branch=main&label=ci)](https://github.com/velzepooz/skill-detector/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/velzepooz/skill-detector)](https://github.com/velzepooz/skill-detector/releases/latest)
[![License](https://img.shields.io/github/license/velzepooz/skill-detector)](./LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/velzepooz/skill-detector)](./go.mod)

> CLI to spot risky AI skill packages before you install them.

Scans AI skill folders (Anthropic Claude Skills, Codex skills, and similar
file-based formats) for security threats so you can vet third-party skills —
e.g. from [skills.sh](https://skills.sh) — without reading every line by hand.

> ⚠️ **Status:** Early-stage (v0.x). Usable, but rules and flags may change before 1.0.

## Why

Installing a skill from a third-party source means running someone else's code
and prompts inside your AI assistant. A malicious skill can exfiltrate
credentials, inject prompts, run shell commands, or quietly tamper with files.
`skill-detector` runs security checks over a skill folder and flags anything
suspicious, so you get a second opinion before dropping it into your skills
directory.

## What it checks

Six rule categories, purpose-built for AI skill packages:

| Category             | Catches                                                 |
| -------------------- | ------------------------------------------------------- |
| **Injection**        | Shell / command injection, prompt injection             |
| **Supply chain**     | Suspicious deps, unpinned installs, typosquats          |
| **Exfiltration**     | Outbound HTTP to unknown hosts, clipboard / env reads   |
| **Misconfiguration** | Over-broad permissions, unsafe defaults                 |
| **Integrity**        | Tampered or unsigned files                              |
| **Access control**   | Permission-declaration vs. actual-behavior mismatches   |

It also parses the skill manifest YAML, so findings can be weighed against
what the skill *claims* it needs.

## Install

```bash
# Homebrew (macOS / Linux)
brew install velzepooz/tap/skill-detector

# Go
go install github.com/velzepooz/skill-detector/cmd/skill-detector@latest
```

Or grab a prebuilt binary from
[Releases](https://github.com/velzepooz/skill-detector/releases)
(linux / darwin / windows × amd64 / arm64).

## Usage

```bash
# Scan a single skill folder
skill-detector scan ./path/to/some-skill

# Scan a whole skills directory
skill-detector scan ~/.claude/skills

# CI mode: fail on HIGH+ findings
skill-detector scan ./my-skill --fail-on high

# JSON output (for piping into other tools)
skill-detector scan ./my-skill --format json

# Quiet mode — exit code only
skill-detector scan ./my-skill --quiet
```

### Exit codes

| Code | Meaning                                        |
| ---- | ---------------------------------------------- |
| `0`  | No findings                                    |
| `1`  | Findings, all below your `--fail-on` threshold |
| `2`  | Finding at or above threshold                  |

### Configuration

Drop a `.skill-detector.yml` next to the skill (or pass `--config`) to toggle
rules and allowlist known-safe patterns. Defaults are sensible; most users
will only need config to suppress false positives.

## How it compares

Plenty of great security scanners already exist — why another one?

| Tool         | Why not just use it for skills?                                                                              |
| ------------ | ------------------------------------------------------------------------------------------------------------ |
| **semgrep**  | Generic pattern engine — powerful, but *you* write the rules. `skill-detector` ships with skill-aware rules. |
| **gitleaks** | Narrower — only secrets. Doesn't cover prompt injection, permission mismatches, exfiltration.                |
| **trivy**    | CVEs in containers / OS packages — a different problem from skill semantics.                                 |
| **gosec**    | Scans Go source. Skills are YAML + Markdown + shell, not Go.                                                 |

Short version: use `skill-detector` when the thing you're scanning is an
AI skill package and you want rules that understand skill-manifest semantics
out of the box.

## Contributing

Issues are very welcome — bug reports, false positives, rule ideas, new skill
formats I haven't covered.

**For pull requests, please open an issue first** so we can agree on the
approach. This is a spare-time pet project; I'd rather not have anyone sink
effort into a PR that won't land.

Build / test / lint instructions: [`docs/development-guide.md`](./docs/development-guide.md).

## Reporting security issues

If you've found a vulnerability in `skill-detector` itself (not in a skill it
scanned), please file a
[private security advisory](https://github.com/velzepooz/skill-detector/security/advisories/new)
rather than a public issue.

## License

[MIT](./LICENSE) — do whatever, no warranty.
