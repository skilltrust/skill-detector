# skill-detector

[![CI](https://img.shields.io/github/actions/workflow/status/velzepooz/skill-detector/ci.yml?branch=main&label=ci)](https://github.com/velzepooz/skill-detector/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/velzepooz/skill-detector)](https://github.com/velzepooz/skill-detector/releases/latest)
[![License](https://img.shields.io/github/license/velzepooz/skill-detector)](./LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/velzepooz/skill-detector)](./go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/velzepooz/skill-detector)](https://goreportcard.com/report/github.com/velzepooz/skill-detector)

> CLI to spot risky AI skill packages before you install them.

Scans AI skill folders (Anthropic Claude Skills, Codex skills, and similar
file-based formats) for security threats so you can vet third-party skills —
e.g. from [skills.sh](https://skills.sh) — without reading every line by hand.

> ⚠️ **Status:** Early-stage (v0.x). Usable, but rules and flags may change before 1.0.

## What's new in v0.2.0 (SP-1: Multi-Axis Engine)

Every scan now produces a 4-axis A–F **Trust Score** alongside the
familiar findings list:

```
Trust Score
  Security             D   High-severity issue: …
  Permission hygiene   A   no findings on this axis
  Transparency         A   no findings on this axis
  Quality              A   no findings on this axis
```

Seven new rules target `.claude/CLAUDE.md`, `.claude/settings.json`,
hooks, and MCP server configs — the configuration surface where
several named 2026 CVEs lived. New CLI flags:

- `--fail-on-axis <axis>=<grade>` — fail CI on an axis-grade
  threshold (e.g. `--fail-on-axis security=B`).
- `--strict-mcp` — treat external MCP server URLs as High severity.
- `--axes-only` — emit just the Trust Score block on stdout
  (findings go to stderr). Pipeable.

**Scope (also new in v0.2.0):** the scanner now defaults to inspecting only
AI-agent configuration files (`SKILL.md`, `CLAUDE.md`, `.claude/settings.json`,
`.mcp.json`) plus arbitrary files inside `.claude/`, `.codex/`, `.opencode/`
directories. It honors `.gitignore` and skips `node_modules`, `vendor`, `dist`,
`build`, `target`, `.next`, `.git`. Pass `--scan-all` to bypass this and walk
every scannable file (v0.1.x behavior).

See [CHANGELOG.md](CHANGELOG.md) for the full v0.2.0 entry.

## Why

Installing a skill from a third-party source means running someone else's code
and prompts inside your AI assistant. A malicious skill can exfiltrate
credentials, inject prompts, run shell commands, or quietly tamper with files.
`skill-detector` runs security checks over a skill folder and flags anything
suspicious, so you get a second opinion before dropping it into your skills
directory.

## What it checks

Ten rule categories (21 rules total), purpose-built for AI agent skill packages
and the surrounding configuration files:

| Category             | Catches                                                 |
| -------------------- | ------------------------------------------------------- |
| **Injection**        | Shell / command injection, prompt injection             |
| **Supply chain**     | Suspicious deps, unpinned installs, typosquats          |
| **Exfiltration**     | Outbound HTTP to unknown hosts, clipboard / env reads   |
| **Misconfiguration** | Over-broad permissions, unsafe defaults                 |
| **Integrity**        | Tampered or unsigned files                              |
| **Access control**   | Permission-declaration vs. actual-behavior mismatches   |
| **CLAUDE.md** *(new in v0.2)* | SQL-injection-by-instruction, Comment-and-Control patterns |
| **settings.json** *(new)*     | `Bash(curl *)` wildcards, deny-bypass-via-broader-allow, unsanctioned hooks |
| **Hooks** *(new)*             | Shell metacharacter interpolation in hook command strings |
| **MCP** *(new)*               | External-domain reach by MCP servers (raise to High with `--strict-mcp`) |

Every finding is tagged with one of four **trust axes** —
Security, Permission hygiene, Transparency, Quality — and the scanner
emits an A–F grade per axis on every scan.

It also parses the skill manifest YAML, so findings can be weighed against
what the skill *claims* it needs.

### What it does NOT check (by default)

- Source code files (`.ts`, `.py`, `.go`, etc.) — that's Snyk / Semgrep's lane.
- `node_modules/`, `vendor/`, `dist/`, lock files — always skipped.
- Files matched by your repo's `.gitignore`.

If you want the v0.1.x behavior of scanning every file with a known extension,
pass `--scan-all`.

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
# Scan a single skill folder (or a whole repo — only agent files inspected)
skill-detector scan ./path/to/some-skill
skill-detector scan ~/.claude/skills

# CI: fail on HIGH+ severity
skill-detector scan ./my-skill --fail-on high

# CI: fail on an axis-grade threshold (new in v0.2)
skill-detector scan ./my-skill --fail-on-axis security=B
# repeatable — combines with --fail-on (worst wins)
skill-detector scan . --fail-on-axis security=B --fail-on-axis permission_hygiene=C

# JSON output (for piping into other tools)
skill-detector scan ./my-skill --format json

# Just the 4-axis Trust Score on stdout (text format only; findings go to stderr)
skill-detector scan ./my-skill --axes-only

# Treat external MCP server URLs as High severity (default: Medium)
skill-detector scan ./my-skill --strict-mcp

# Quiet mode — exit code only
skill-detector scan ./my-skill --quiet

# Bypass scope tightening + .gitignore filtering (walks every scannable file)
skill-detector scan . --scan-all
```

### Exit codes

| Code | Meaning                                                         |
| ---- | --------------------------------------------------------------- |
| `0`  | No findings                                                     |
| `1`  | Findings, all below your `--fail-on` / `--fail-on-axis` threshold |
| `2`  | Finding at or above threshold (worst of severity OR axis-grade) |

### Configuration

Drop a `.skill-detector.yml` next to the skill (or pass `--config`) to toggle
rules and allowlist known-safe patterns. Defaults are sensible; most users
will only need config to suppress false positives.

### Trust Score (sample output)

```
Trust Score
  Security             D   High-severity issue: outbound network reference detected
  Permission hygiene   D   High-severity issue: broad shell permission granted: Bash(curl *)
  Transparency         A   no findings on this axis
  Quality              A   no findings on this axis
```

Per-axis grade is set by the **worst finding on that axis** (worst-finding-wins).
Each grade ships with a one-line human-readable rationale plus the rule IDs
that drove it — so disagreements become rule-tuning conversations, not
credibility hits.

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
