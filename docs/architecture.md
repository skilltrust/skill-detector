# skill-detector — Architecture

## Executive Summary

skill-detector is a Go CLI tool that scans AI skill package directories for security threats. It follows a pipeline architecture: discover files → apply security rules → score risk → report results. The tool is designed for extensibility (new rules can be added via a registry pattern) and supports multiple output formats.

## Architecture Pattern

**Pipeline / Chain of Responsibility** (with per-rule path gating and per-axis aggregation as of v0.2.0)

The tool processes scan targets through a linear pipeline:

```
Input (directory path)
  → File Discovery (scanner/discover.go + gitignore.go)
      • Hardcoded skip-dirs (node_modules, .git, etc.)
      • Honors .gitignore unless --scan-all
      • Restricts to scannable file extensions
    → Rule Application (rules/registry.go → individual rules)
      • Each rule's Match() gates by path (IsAgentFile / isInClaudeOrCodexDir)
      • Rule sets Finding.Axis via baseRule.newFinding
    → Allowlist Filtering (scanner/allowlist.go)
      → Risk Scoring (scorer/scorer.go — legacy flat score, kept for compat)
        → Per-axis aggregation (grade.Grade per axis → ScanResult.Axes)
          → Output Formatting (reporter/*.go — Trust Score block + findings)
            → Exit Code (worst of --fail-on severity OR --fail-on-axis grade)
```

## Package Architecture

### Dependency Graph

```
cmd/skill-detector (main)
  ├── pkg/axes        ← Axis + Grade enums (wire-stable)
  ├── pkg/config      ← Configuration loading
  ├── pkg/scanner     ← Orchestration + walker
  │     ├── pkg/model       ← Shared types (incl. Axis, AxisResult)
  │     ├── pkg/rules       ← Security checks (incl. fileclass predicates)
  │     ├── pkg/grade       ← Per-axis aggregator (uses pkg/axes + pkg/model)
  │     ├── pkg/permission  ← Manifest parsing
  │     └── pkg/config      ← Allowlists
  ├── pkg/scorer      ← Flat-score (legacy, kept for backward compat)
  │     └── pkg/model
  └── pkg/reporter    ← Output formatting (text + JSON, Trust Score block)
        ├── pkg/model
        └── pkg/axes
```

### Package Responsibilities

#### `pkg/axes`
- Wire-stable enums: `Axis` ("security" / "permission_hygiene" / "transparency" / "quality") and `Grade` ("A" .. "F")
- `Order` — canonical iteration order for the four axes
- Strings appear in JSON output, badge URLs, downstream DB columns — changing requires a major version bump

#### `pkg/grade`
- Pure aggregator: `Grade(axis, findings) → AxisResult` using worst-finding-wins with per-axis caps
- `caps` table: per-(axis, severity) grade ceiling (Security/Permission stricter; Transparency/Quality softer)
- `rationaleTemplate` — deterministic per-grade rationale strings
- `CanonicalMetadata()` — stable string form fed to `registry.Checksum()` for tamper detection

#### `pkg/model`
- Core domain types shared across all packages
- `Finding` — A single security issue detected. Includes `Axis axes.Axis` field.
- `ScanResult` — Complete scan output. Includes `Axes map[axes.Axis]AxisResult` populated by the scanner.
- `AxisResult`, `DrivingFinding` — per-axis grade output

#### `pkg/config`
- Loads YAML configuration (`.skill-detector.yml`)
- Provides sensible defaults via `defaults.go`
- Supports per-rule enable/disable toggles
- Allowlist configuration for finding suppression

#### `pkg/scanner`
- **`discover.go`** — Walks the target directory; respects hardcoded skip-dirs (node_modules, vendor, dist, build, target, .next, .git) and `.gitignore`; classifies files by extension; detects binary files
- **`gitignore.go`** — Best-effort wrapper over `github.com/sabhiram/go-gitignore` for root `.gitignore` loading
- **`scanner.go`** — Orchestrates the scan: discovers files, runs enabled rules, applies allowlists, collects findings, populates `ScanResult.Axes` via `grade.Grade`
- **`allowlist.go`** — Filters findings based on configured domain/pattern allowlists
- `DiscoverOptions` / `DiscoverWithOptions` — option-aware walker (`ScanAll bool` bypasses `.gitignore`)

#### `pkg/rules`
- **`rule.go`** — Defines the Rule interface (including the `Axis()` method) that all checkers implement
- **`registry.go`** — Collects and manages available rules; `Checksum()` covers axis + grade metadata for tamper detection
- **`fileclass.go`** — Path predicates: `IsSkillManifest`, `IsClaudeMD`, `IsClaudeSettings`, `IsMCPConfig`, `IsAgentFile`, `isInClaudeOrCodexDir`. Every rule's `Match()` gates on one of these.
- 10 rule files, 21 rules total:
  - Pre-SP-1 (path-gated in v0.2.0):
    - **`injection.go`** — SD-001 shell injection, SD-002 prompt injection
    - **`supply_chain.go`** — SD-009 curl-pipe-bash, SD-010 runtime download, SD-011 vulnerable deps
    - **`exfiltration.go`** — SD-007 outbound network, SD-008 base64 obfuscation
    - **`misconfiguration.go`** — SD-005 misconfig, SD-006 hardcoded secret
    - **`integrity.go`** — SD-012 post-install hook, SD-013 persistence, SD-014 git-hook modification
    - **`access_control.go`** — SD-003 path traversal, SD-004 credential access
  - SP-1 additions:
    - **`claude_md.go`** — SD-015 SQL-injection-by-instruction, SD-016 Comment-and-Control
    - **`settings_json.go`** — SD-017 Bash wildcard, SD-018 subcommand-limit-bypass, SD-019 unsanctioned hook
    - **`hooks.go`** — SD-020 shell metacharacter interpolation
    - **`mcp.go`** — SD-021 external domain reach

#### `pkg/permission`
- Extracts permission declarations from skill manifest YAML files
- Identifies what permissions a skill claims to need

#### `pkg/scorer`
- Computes an aggregate flat-score (0–100) from scan findings — legacy field, kept for backward compatibility
- New consumers should read `ScanResult.Axes` per-axis grades instead

#### `pkg/reporter`
- **`reporter.go`** — Reporter interface definition
- **`text.go`** — Human-readable terminal output. Prepends a 4-axis **Trust Score block** above the findings list. `OmitTrustScore` toggles for `--axes-only` mode.
- **`json.go`** — Machine-readable JSON output. Includes `axes` map (per-axis Grade + Rationale + DrivingFindings) and per-finding `axis` tag (additive — old consumers parse unchanged).
- **`quiet.go`** — Minimal output (relies on exit code)
- **`theme.go`** — Terminal color and styling constants

## Design Decisions

### Standard Go Layout with Exported `pkg/`
Uses `cmd/` for entry points and `pkg/` for public/library packages, allowing external consumers (e.g., `skillmoss-go`) to import the scanner, rules, and grade-aggregator as a library.

### Rule Registry Pattern with Path-Gating
Rules are registered centrally. New rules are added by:
1. Creating a new file in `pkg/rules/`
2. Implementing the Rule interface (including `Axis()` method)
3. **Gating `Match()` by file class** as the first statement — typically `if !IsAgentFile(ctx.Path) { return nil }`
4. Registering in `DefaultRegistry()` AND in `cmd/skill-detector/main.go::newRegistry()`

Path-gating is mandatory — without it the rule would fire on every file with a matching extension, ballooning false-positive noise on real-world repos (per the SP-1.1 dogfood lessons).

### Default Scope Tightening (v0.2.0)
The scanner inspects only AI-agent files by default (SKILL.md, CLAUDE.md, .claude/settings.json, .mcp.json, plus arbitrary files in .claude/.codex/.opencode dirs). Hardcoded skip-dirs and `.gitignore` filtering keep noise out. `--scan-all` flag bypasses for migration scenarios.

### Multi-Axis Trust Score
Every scan produces an A–F grade on four independent axes (Security, Permission hygiene, Transparency, Quality) via the worst-finding-wins aggregator. Per-axis caps in `pkg/grade/templates.go` define the (axis, severity) → grade mapping. Rationale strings are deterministic templates — no LLM in the loop. `registry.Checksum()` covers axis assignments + cap-table + templates so any tampering invalidates pinned-checksum builds.

### Allowlist-Based Suppression
Findings can be suppressed via configuration, allowing users to whitelist known-safe patterns without disabling entire rule categories.

### Multiple Output Formats
Supports text (human-readable with Trust Score block), JSON (machine-readable with `axes` map), and quiet (CI) output. The `--axes-only` flag emits only the Trust Score block on stdout (text format).

### Self-Scan CI Step
The CI pipeline runs `make self-scan` which scans the tool's own test fixtures, serving as both a smoke test and a dogfooding mechanism.

## Testing Strategy

- **Unit tests** — Each package has co-located `_test.go` files (326+ test functions total as of v0.2.0)
- **CVE reproducer tests** — `cmd/skill-detector/cve_repro_test.go` runs both Go-API and binary E2E paths against `testdata/cve/<incident>/` fixtures, one per named 2026 incident
- **Scope regression tests** — `cmd/skill-detector/scope_test.go` and `scope_real_repo_test.go` assert the default scope only walks/fires on agent files, and that the total finding count on a real-world-shape fixture stays under a sanity threshold
- **Path-gate tests** — Every rule has a `TestSDxxx_GatesNonAgentFile` test asserting it does NOT fire on `node_modules/.../*.md` and similar non-agent paths
- **Integrity tests** — `pkg/rules/registry_test.go` asserts `Checksum()` changes when a rule's axis is flipped
- **E2E tests** — `cmd/skill-detector/e2e_test.go` tests the full CLI flow
- **Test fixtures** — `testdata/` provides realistic samples:
  - `clean/` — Non-malicious skills (should produce no findings)
  - `malicious/<rule>/<agent-path>` — Known-bad fixtures at agent-file shape (SKILL.md / CLAUDE.md / .claude/...)
  - `cve/<incident>/` — Minimal CVE reproducer repos
  - `edge-cases/` — Boundary conditions (empty dirs, binary files, malformed YAML, hidden dirs)
- **CI validation** — GitHub Actions runs lint → test → build → self-scan on every push/PR

## Cross-Platform Distribution

- **GoReleaser** builds binaries for linux/darwin/windows × amd64/arm64
- **Homebrew tap** (`velzepooz/homebrew-tap`) for macOS/Linux installation
- **GitHub Releases** triggered by version tags (`v*`)
