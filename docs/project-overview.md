# skill-detector — Project Overview

## Purpose

**skill-detector** is a security-focused CLI tool that analyzes AI agent configuration files for trust + governance issues. It scans `SKILL.md`, `CLAUDE.md`, `.claude/settings.json`, `.mcp.json`, and surrounding hook scripts for malicious patterns and emits a four-axis A–F Trust Score (Security, Permission hygiene, Transparency, Quality) alongside the findings list. Detects shell injection, credential theft, data exfiltration, supply-chain attacks, prompt injection, persistence mechanisms, misconfigurations, integrity violations, access control issues, plus AI-agent-specific issues like CLAUDE.md SQL-injection-by-instruction, Comment-and-Control patterns, `Bash(curl *)` wildcards, subcommand-bypass shapes, shell-metacharacter interpolation in hooks, and external MCP server reach.

## Executive Summary

| Attribute          | Value                                              |
| ------------------ | -------------------------------------------------- |
| **Project Name**   | skill-detector                                     |
| **Language**       | Go 1.26                                            |
| **Type**           | CLI Tool                                           |
| **Framework**      | Cobra (CLI)                                        |
| **Repository**     | Monolith                                           |
| **Architecture**   | Pipeline (scan → path-gated rules → axis aggregation → report) |
| **License**        | Not specified                                      |
| **Maintainer**     | velzepooz                                          |

## Tech Stack Summary

| Category        | Technology            | Version  | Purpose                                    |
| --------------- | --------------------- | -------- | ------------------------------------------ |
| Language        | Go                    | 1.26     | Core language                              |
| CLI Framework   | spf13/cobra           | 1.10.2   | Command-line interface & argument parsing  |
| YAML Parsing    | gopkg.in/yaml.v3      | 3.0.1    | Configuration and skill manifest parsing   |
| Linting         | golangci-lint + gosec | v2.11.4  | Code quality and security linting          |
| Release         | GoReleaser            | v2       | Cross-platform binary builds & publishing  |
| CI/CD           | GitHub Actions        | —        | Automated lint, test, build, self-scan     |
| Distribution    | Homebrew tap          | —        | macOS/Linux package distribution           |

## Architecture Overview

The tool follows a **pipeline architecture**:

1. **Scanner** (`pkg/scanner/`) — Discovers files (honoring `.gitignore` + hardcoded skip-dirs), classifies them, runs rules, populates `ScanResult.Axes`
2. **Rules** (`pkg/rules/`) — A registry of security rule checkers (10 rule files, 21 rules total). Every rule path-gates by file class before evaluating its pattern.
3. **Path Predicates** (`pkg/rules/fileclass.go`) — `IsAgentFile`, `IsSkillManifest`, `IsClaudeMD`, `IsClaudeSettings`, `IsMCPConfig`, `isInClaudeOrCodexDir`
4. **Axes + Grade** (`pkg/axes/`, `pkg/grade/`) — 4-axis enum + worst-finding-wins aggregator with per-axis caps and rationale templates
5. **Permission Extractor** (`pkg/permission/`) — Extracts permission declarations from skill manifests
6. **Scorer** (`pkg/scorer/`) — Legacy flat-score (kept for backward compat); per-axis grades are the primary scoring surface now
7. **Reporter** (`pkg/reporter/`) — Formats output (text with Trust Score block, JSON with `axes` map, quiet modes)
8. **Config** (`pkg/config/`) — Loads YAML configuration with defaults, rule toggles, and allowlists

## Repository Structure

- **Single-part monolith** — All code lives in one cohesive Go module
- **Standard Go layout** — `cmd/` for entry points, `pkg/` for public/library packages (importable by downstream consumers like `skillmoss-go`)
- **Test fixtures** — `testdata/` contains clean, malicious (agent-file-shaped), CVE reproducer, and edge-case samples
- **Cross-platform** — Builds for linux/darwin/windows on amd64/arm64

## Key Metrics (as of v0.2.0)

- **Public packages:** 9 (scanner, rules, reporter, model, config, permission, scorer, axes, grade)
- **Source files:** ~30 `.go` files (excluding tests)
- **Test files:** 326+ test functions across 10 packages
- **Security rules:** 10 categories, 21 rules total
- **Trust axes:** 4 (Security, Permission hygiene, Transparency, Quality)
- **Output formats:** 3 (text with Trust Score block, JSON with axes map, quiet)
- **CLI flags (v0.2.0 additions):** `--fail-on-axis`, `--strict-mcp`, `--axes-only`, `--scan-all`

## Links

- [Architecture](./architecture.md)
- [Source Tree Analysis](./source-tree-analysis.md)
- [Development Guide](./development-guide.md)
