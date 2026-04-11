# skill-detector — Architecture

## Executive Summary

skill-detector is a Go CLI tool that scans AI skill package directories for security threats. It follows a pipeline architecture: discover files → apply security rules → score risk → report results. The tool is designed for extensibility (new rules can be added via a registry pattern) and supports multiple output formats.

## Architecture Pattern

**Pipeline / Chain of Responsibility**

The tool processes skill packages through a linear pipeline:

```
Input (directory path)
  → File Discovery (scanner/discover.go)
    → Rule Application (rules/registry.go → individual rules)
      → Allowlist Filtering (scanner/allowlist.go)
        → Risk Scoring (scorer/scorer.go)
          → Output Formatting (reporter/*.go)
            → Exit Code
```

## Package Architecture

### Dependency Graph

```
cmd/skill-detector (main)
  ├── internal/config      ← Configuration loading
  ├── internal/scanner     ← Orchestration
  │     ├── internal/model       ← Shared types
  │     ├── internal/rules       ← Security checks
  │     ├── internal/permission  ← Manifest parsing
  │     └── internal/config      ← Allowlists
  ├── internal/scorer      ← Risk computation
  │     └── internal/model
  └── internal/reporter    ← Output formatting
        └── internal/model
```

### Package Responsibilities

#### `internal/model`
- Core domain types shared across all packages
- `Finding` — A single security issue detected
- `Result` — Complete scan output (findings, score, metadata)
- Severity levels and categorization

#### `internal/config`
- Loads YAML configuration (`.skill-detector.yml`)
- Provides sensible defaults via `defaults.go`
- Supports per-rule enable/disable toggles
- Allowlist configuration for finding suppression

#### `internal/scanner`
- **`discover.go`** — Walks the target directory, classifies files by extension and content, detects binary files
- **`scanner.go`** — Orchestrates the scan: discovers files, runs enabled rules, applies allowlists, collects findings
- **`allowlist.go`** — Filters findings based on configured domain/pattern allowlists

#### `internal/rules`
- **`rule.go`** — Defines the Rule interface that all checkers implement
- **`registry.go`** — Collects and manages available rules; controls which rules are active
- Six security rule implementations:
  - **`injection.go`** — Detects shell/command injection patterns
  - **`supply_chain.go`** — Detects supply chain attack indicators
  - **`exfiltration.go`** — Detects data exfiltration attempts
  - **`misconfiguration.go`** — Detects security misconfigurations
  - **`integrity.go`** — Detects integrity violations
  - **`access_control.go`** — Detects access control issues

#### `internal/permission`
- Extracts permission declarations from skill manifest YAML files
- Identifies what permissions a skill claims to need

#### `internal/scorer`
- Computes an aggregate risk score from scan findings
- Considers severity, count, and category of findings

#### `internal/reporter`
- **`reporter.go`** — Reporter interface definition
- **`text.go`** — Human-readable colored terminal output
- **`json.go`** — Machine-readable JSON output
- **`quiet.go`** — Minimal output (relies on exit code)
- **`theme.go`** — Terminal color and styling constants

## Design Decisions

### Standard Go Layout
Uses `cmd/` for entry points and `internal/` for private packages, preventing external imports of internal APIs.

### Rule Registry Pattern
Rules are registered centrally, allowing new rules to be added by:
1. Creating a new file in `internal/rules/`
2. Implementing the Rule interface
3. Registering in the registry

### Allowlist-Based Suppression
Findings can be suppressed via configuration, allowing users to whitelist known-safe patterns without disabling entire rule categories.

### Multiple Output Formats
Supports text (human), JSON (machine), and quiet (CI) output, making it suitable for both interactive use and CI/CD pipelines.

### Self-Scan CI Step
The CI pipeline runs `make self-scan` which scans the tool's own test fixtures, serving as both a smoke test and a dogfooding mechanism.

## Testing Strategy

- **Unit tests** — Each package has co-located `_test.go` files (219 test functions total)
- **E2E tests** — `cmd/skill-detector/e2e_test.go` tests the full CLI flow
- **Test fixtures** — `testdata/` provides realistic samples:
  - `clean/` — Non-malicious skills (should produce no findings)
  - `malicious/` — Known-bad skills (should trigger specific rules)
  - `edge-cases/` — Boundary conditions (empty dirs, binary files, malformed YAML, hidden dirs)
- **CI validation** — GitHub Actions runs lint → test → build → self-scan on every push/PR

## Cross-Platform Distribution

- **GoReleaser** builds binaries for linux/darwin/windows × amd64/arm64
- **Homebrew tap** (`velzepooz/homebrew-tap`) for macOS/Linux installation
- **GitHub Releases** triggered by version tags (`v*`)
