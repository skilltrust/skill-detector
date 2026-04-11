# skill-detector — Project Overview

## Purpose

**skill-detector** is a security-focused CLI tool that analyzes AI skill packages for potential threats. It scans skill package directories for malicious patterns including shell injection, credential theft, data exfiltration, supply-chain attacks, prompt injection, persistence mechanisms, misconfigurations, integrity violations, and access control issues.

## Executive Summary

| Attribute          | Value                                              |
| ------------------ | -------------------------------------------------- |
| **Project Name**   | skill-detector                                     |
| **Language**       | Go 1.26                                            |
| **Type**           | CLI Tool                                           |
| **Framework**      | Cobra (CLI)                                        |
| **Repository**     | Monolith                                           |
| **Architecture**   | Pipeline (scan → rules → score → report)           |
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

1. **Scanner** (`internal/scanner/`) — Discovers files in a skill package directory, classifies them, and applies allowlists
2. **Rules** (`internal/rules/`) — A registry of security rule checkers (injection, supply chain, exfiltration, misconfiguration, integrity, access control)
3. **Permission Extractor** (`internal/permission/`) — Extracts permission declarations from skill manifests
4. **Scorer** (`internal/scorer/`) — Computes a risk score from findings
5. **Reporter** (`internal/reporter/`) — Formats output (text, JSON, quiet modes)
6. **Config** (`internal/config/`) — Loads YAML configuration with defaults, rule toggles, and allowlists

## Repository Structure

- **Single-part monolith** — All code lives in one cohesive Go module
- **Standard Go layout** — `cmd/` for entry points, `internal/` for private packages
- **Test fixtures** — `testdata/` contains clean, malicious, and edge-case skill samples
- **Cross-platform** — Builds for linux/darwin/windows on amd64/arm64

## Key Metrics (Quick Scan)

- **Internal packages:** 7 (scanner, rules, reporter, model, config, permission, scorer)
- **Source files:** ~20 `.go` files (excluding tests)
- **Test files:** 18 `_test.go` files with 219 test functions
- **Security rules:** 6 categories (injection, supply chain, exfiltration, misconfiguration, integrity, access control)
- **Output formats:** 3 (text, JSON, quiet)

## Links

- [Architecture](./architecture.md)
- [Source Tree Analysis](./source-tree-analysis.md)
- [Development Guide](./development-guide.md)
