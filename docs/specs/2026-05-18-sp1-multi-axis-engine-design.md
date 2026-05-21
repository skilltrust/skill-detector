# SP-1 — Multi-Axis Scoring + Extended Rule Packs in `skill-detector`

**Date:** 2026-05-18
**Author:** Glib
**Status:** Draft for review
**Parent PRD:** `_bmad-output/planning-artifacts/prd.md` (SkillTrust MVP)
**Sub-project of:** SkillTrust MVP Wk 0–8

## Purpose

Refactor the `skill-detector` Go module to emit a 4-axis A–F trust score on every scan, alongside its existing flat-score output, and ship 7 new rules covering `CLAUDE.md`, `.claude/settings.json`, hooks, and MCP server configs. This unblocks SP-2 (hosted scanner UI), SP-3 (badge), SP-4 (PR-comment bot), and SP-5 (GitHub Action) — all of which consume the new axis-tagged shape.

## Scope

**In scope:**
- New `pkg/axes/` (axis enum + grade constants).
- New `pkg/grade/` (pure aggregator + rationale templates).
- `pkg/model.Finding` gains `Axis` field (existing `Category`, `Confidence`, `Remediation`, `RuleName`, `EffSeverity` preserved).
- `pkg/model.ScanResult` gains `Axes` map; all existing fields preserved.
- `pkg/rules.Rule` interface gains `Axis()` method; all existing methods preserved.
- 7 new rule files: `claude_md.go`, `settings_json.go`, `hooks.go`, `mcp.go`.
- Scanner walker extended to classify 4 new file classes.
- `pkg/reporter/text.go` and `pkg/reporter/json.go` additively emit axis output.
- New CLI flags: `--fail-on-axis`, `--strict-mcp`, `--axes-only`.
- Existing 6 rule groups receive axis assignments (no behavior change).
- `registry.Checksum()` extended to cover axis assignments + threshold table + rationale templates.
- Test fixtures for all 7 new rules + CVE reproducers under `testdata/cve/`.

**Out of scope (named, explicit):**
- Per-workspace configurable threshold tables → SP-2/SP-4.
- Axis-grade suppression workflow (existing severity allowlist still works) → P2.
- Hot-reload of rule packs without rebuild → SP-2/SP-4 (NFR34).
- LLM-semantic rationale generation → forbidden (deterministic templates only).
- Cross-tool SKILL.md dialect handling (Codex/Cursor/Kiro/Gemini variants) → data-driven, defer.
- DB migrations in `skillmoss-go` → SP-2.
- Suppression-with-reason structured workflow → P2.
- Quality / Transparency rules → out of SP-1 (axes ship as A-by-default until later sub-projects).

## Design Decisions (locked)

| Decision | Choice | Why |
|---|---|---|
| Rule → axis mapping | **Single axis per rule** | Simple, no UI ambiguity, deterministic grade contribution. Same evidence-text duplication across rules is acceptable. |
| Grade aggregator | **Worst-finding-wins with per-axis caps** | Easy to explain; one Critical = F is the buyer-facing mental model. Volume-insensitive by design (separate "X findings" stat lives alongside the grade). |
| New-rule scope | **Demo-rules-only (7 rules)** | Each named 2026 CVE has at least one detecting rule. Fits 2-week timebox. Avoids rule-count-parity trap with Snyk/Cisco. |
| CLI compat | **Additive V1** | No breaking change for existing Homebrew users. JSON schema gains fields; old fields preserved. |
| LLM in rationale | **Forbidden** | Aligns with PRD anti-pattern "Mock/black-box LLM scoring with no deterministic explanation". |

## Architecture

### Module layout

```
skill-detector/
├── pkg/
│   ├── axes/           NEW — Axis enum, Grade enum, display order
│   ├── grade/          NEW — pure aggregator + rationale templates
│   ├── model/          MUTATED — Finding.Axis, ScanResult.Axes
│   ├── rules/
│   │   ├── rule.go         MUTATED — Rule.Axis() method
│   │   ├── registry.go     MUTATED — Checksum() input extended
│   │   ├── injection.go         existing, axis=security
│   │   ├── supply_chain.go      existing, axis=security
│   │   ├── exfiltration.go      existing, axis=security
│   │   ├── integrity.go         existing, axis=security
│   │   ├── misconfiguration.go  existing, axis=permission_hygiene
│   │   ├── access_control.go    existing, axis=permission_hygiene
│   │   ├── claude_md.go         NEW — 2 rules
│   │   ├── settings_json.go     NEW — 3 rules
│   │   ├── hooks.go             NEW — 1 rule
│   │   └── mcp.go               NEW — 1 rule
│   ├── scanner/        MUTATED — discover.go classifies new file classes
│   ├── scorer/         existing — kept (flat score), no behavior change
│   └── reporter/       MUTATED — text.go + json.go additive output
├── cmd/skill-detector/main.go   MUTATED — newRegistry() registers new packs
└── testdata/
    ├── clean/                   existing
    ├── malicious/<rule_id>/     NEW dirs for 7 new rules
    └── cve/                     NEW — one dir per named 2026 CVE
```

### Axis enum (wire-stable)

```go
package axes

type Axis string

const (
    Security          Axis = "security"
    PermissionHygiene Axis = "permission_hygiene"
    Transparency      Axis = "transparency"
    Quality           Axis = "quality"
)

var Order = []Axis{Security, PermissionHygiene, Transparency, Quality}

type Grade string  // "A" | "B" | "C" | "D" | "F"
```

String IDs are wire-stable. Change requires major version bump because they appear in JSON, badge URLs, PR-comment markdown, and (downstream) DB columns.

### Mutated types

`pkg/model.Finding` (existing) gains one field:

```go
// pkg/model/finding.go — existing fields preserved
type Finding struct {
    RuleID      string
    RuleName    string
    Severity    Severity
    EffSeverity Severity
    Category    string             // existing — "injection", "supply_chain", etc. KEPT.
    Description string
    FilePath    string
    Line        int
    Confidence  Confidence         // existing
    Remediation string
    Axis        axes.Axis          // NEW — non-empty for every finding from v0.2.0
}
```

**Note on `Category` vs `Axis`**: these coexist intentionally. `Category` is the per-rule-group taxonomy already used by reporters and JSON consumers (`injection`, `supply_chain`, `exfiltration`, `misconfiguration`, `integrity`, `access_control`, plus `claude_md`, `settings_json`, `hooks`, `mcp` for new packs). `Axis` is the coarser 4-bucket trust dimension. The mapping is many-to-one (multiple categories → one axis), defined at the rule level.

**Note on `Confidence`**: existing `model.Confidence` field on `Finding` is **ignored by the SP-1 grade aggregator** — worst-finding-wins treats all findings of a given severity uniformly regardless of confidence. PRD's "confidence-graded findings" pattern stays available for UI tooltips and future P2 features, but does not influence axis grade in SP-1. Documented to avoid future "why is a low-confidence Critical still giving us an F" confusion.

`pkg/model.ScanResult` (existing) gains `Axes`; existing fields preserved:

```go
type ScanResult struct {
    // ... all existing fields kept (Findings, Score, etc.)
    Axes map[axes.Axis]AxisResult  // NEW
}

type AxisResult struct {
    Grade           axes.Grade
    Rationale       string
    DrivingFindings []DrivingFinding
}

type DrivingFinding struct {
    RuleID string
    Count  int
}
```

### Mutated Rule interface

`pkg/rules.Rule` (existing) gains one method:

```go
// pkg/rules/rule.go — existing methods preserved
type Rule interface {
    ID() string
    Name() string
    Severity() model.Severity
    Category() string
    FileTypes() []string
    Match(content []byte, ctx model.FileContext) []model.Finding
    Axis() axes.Axis                       // NEW
}
```

`baseRule` (existing helper) gains a corresponding `axis` field and `Axis()` method; the existing `newFinding` helper additionally stamps `Finding.Axis = b.axis` so rule implementations don't have to remember.

**Invariant**: rule code does not set `Finding.Axis` directly — `baseRule.newFinding` is the chokepoint, and any rule not using `baseRule` (none exist today) would have a registry-side stamper as defense in depth.

## File-class detection

`pkg/scanner/discover.go` walker classifies each visited path into 0+ `FileClass` values; rules subscribe by class.

| FileClass | Path pattern | Notes |
|---|---|---|
| `skill_md` | `**/SKILL.md`, `**/skill.yaml` | Existing — unchanged. |
| `claude_md` | `CLAUDE.md`, `.claude/CLAUDE.md`, `**/CLAUDE.md` (excluding `node_modules`, `.git`, common vendor dirs) | 4-level hierarchy treated as separate sources. Each found file gets a `Hierarchy` tag (`managed`/`policy`/`project`/`local`) inferred from path. |
| `claude_settings` | `.claude/settings.json`, `.claude/settings.local.json` | Parsed once; passed to rules as decoded struct, not raw bytes. |
| `hooks` | Synthesized — emitted per hook entry inside `.claude/settings.json` | Not a real path; rules receive `(hook command string, source settings.json path, key path inside JSON)`. |
| `mcp_config` | `.mcp.json`, `.claude/mcp.json`, MCP blocks inside `settings.json` | Same synthesis pattern as hooks. |

**Hierarchy deduplication**: NOT performed in SP-1. A rule firing on the same pattern in managed-level CLAUDE.md and project-level CLAUDE.md produces two separate findings (different blast radius, different remediation). SP-2 UI may choose to group them.

## Rule catalog

### Existing rule groups — axis assignments

| RuleID prefix | Axis | Behavior change |
|---|---|---|
| `injection.*` | security | none |
| `supply_chain.*` | security | none |
| `exfiltration.*` | security | none |
| `integrity.*` | security | none |
| `misconfiguration.*` | permission_hygiene | none |
| `access_control.*` | permission_hygiene | none |

### New rules (7)

| RuleID | Axis | FileClass | Severity floor | Detection summary | CVE / source |
|---|---|---|---|---|---|
| `claude_md.sql_injection_by_instruction` | security | claude_md | High | Phrase-list + regex for instructions directing AI to construct raw SQL from untrusted input without parameterization | LayerX, Mar 2026 |
| `claude_md.comment_and_control` | security | claude_md | Critical | Patterns instructing the AI to read PR comments / issues / external URLs as authoritative directives | Comment-and-Control 2026 |
| `settings_json.bash_curl_wildcard` | permission_hygiene | claude_settings | High | `allowed-tools` entry matches `Bash(curl *)`, `Bash(wget *)`, `Bash(*)`, or other broad-shell patterns | Maya's headline pattern |
| `settings_json.subcommand_limit_bypass` | permission_hygiene | claude_settings | High | Tool grant uses bypass shape (e.g. `Bash(*)` after a specific deny, or `Bash(git *)` followed by `Bash(git; <anything>)` via separators) | Apr 2026 CVE |
| `settings_json.unsanctioned_hook` | permission_hygiene | claude_settings | Medium | Hook references binary outside repo + outside a configurable allowlist | General |
| `hooks.shell_metacharacter_interpolation` | security | hooks | Critical | Hook command embeds `${VAR}` or `$VAR` unquoted inside shell metacharacter context. Detection via Go shellwords parser. | CVE-2025-59536 family |
| `mcp.external_domain_reach` | permission_hygiene | mcp_config | Medium (High with `--strict-mcp`) | MCP server `url`/`endpoint` resolves outside the configured allowlist | General + Trend Micro 2026 |

Each rule ships with:
- Deterministic detector (no LLM).
- One-line `Description()`.
- Longer `Diagnosis(f)` interpolated with finding context.
- Paired fixture: `testdata/malicious/<rule_id>/` (must trigger) + `testdata/clean/<rule_id>/` (must not trigger).

## Grade aggregator

`pkg/grade/grade.go` — pure function, no I/O, no rule deps:

```go
func Grade(axis axes.Axis, findings []model.Finding) model.AxisResult
```

**Algorithm:**

1. Filter `findings` to those with `Axis == axis`.
2. If empty → `Grade=A`, `Rationale="no findings on this axis"`, `DrivingFindings=nil`.
3. Find max severity among filtered findings.
4. Map `(axis, maxSeverity)` → grade via the per-axis cap table.
5. Rationale = `template[axis][severity]` interpolated with `len(maxFindings)` and top rule ID.
6. `DrivingFindings` = stable-sorted `[]DrivingFinding{RuleID, Count}` for all max-severity findings.

### Per-axis cap table

| Axis | Critical | High | Medium | Low |
|---|---|---|---|---|
| `security` | F | D | C | B |
| `permission_hygiene` | F | D | C | B |
| `transparency` | D | C | B | B |
| `quality` | C | B | B | A |

Security and permission_hygiene are load-bearing for the wedge — harshest caps. Transparency and quality cap softer because false positives in those axes would be noisier and they have no rules in SP-1 anyway.

### Rationale templates

Source: `pkg/grade/templates.go`, a map keyed on `(axis, severity)`:

```go
var templates = map[axes.Axis]map[model.Severity]string{
    axes.Security: {
        model.Critical: "Critical security issue: %s",
        model.High:     "High security risk: %s",
        // ...
    },
    // ...
}
```

`%s` interpolates the top rule's `Description()`. No LLM, no per-customer text variation, no localization in SP-1.

## Integrity — extended `registry.Checksum()`

Current: hashes sorted list of registered `RuleID`s, compared against `expectedChecksum` ldflag, halts on mismatch.

SP-1 extends checksum input to a canonicalized JSON of:
1. Sorted `(RuleID, Axis)` pairs.
2. Per-axis cap table.
3. Per-(axis, severity) rationale templates.

Same `expectedChecksum` ldflag mechanism, same halt-on-mismatch behavior. Dev builds (empty ldflag) skip the check (existing behavior).

**Test cases (must fail checksum verification):**
- Rule added or removed.
- Rule's axis assignment flipped.
- Cap-table cell changed.
- Rationale template string changed.

## Reporter output

### Text reporter — additive

```
Trust Score
  Security            D    1 critical finding: claude_md.comment_and_control
  Permission hygiene  D    1 high finding:     settings_json.bash_curl_wildcard
  Transparency        A    (no rules fired on this axis)
  Quality             A    (no rules fired on this axis)

Findings (2)
  [CRITICAL] claude_md.comment_and_control
    .claude/CLAUDE.md:14
    ...
```

- Trust Score block prepended above existing findings list.
- Colors via existing `theme.go`: A/B green, C yellow, D/F red.
- Existing findings list unchanged.

### JSON reporter — additive

```json
{
  "version": "1.2.0",
  "score": 70,
  "axes": {
    "security": {
      "grade": "D",
      "rationale": "...",
      "driving_findings": [{"rule_id": "claude_md.comment_and_control", "count": 1}]
    },
    "permission_hygiene": { "grade": "D", "rationale": "...", "driving_findings": [...] },
    "transparency":       { "grade": "A", "rationale": "no findings on this axis", "driving_findings": [] },
    "quality":            { "grade": "A", "rationale": "no findings on this axis", "driving_findings": [] }
  },
  "findings": [
    {
      "rule_id": "claude_md.comment_and_control",
      "severity": "critical",
      "axis": "security",
      "path": ".claude/CLAUDE.md",
      "line": 14,
      "description": "...",
      "diagnosis": "..."
    }
  ]
}
```

Schema versioning:
- `version` field tracks JSON output schema, not the binary version.
- Minor bump on additive change. Major bump on breaking change.

### Quiet reporter

No change.

## CLI flags

| Flag | Status | Behavior |
|---|---|---|
| `--fail-on <severity>` | existing | Exit 2 if any finding ≥ severity. Unchanged. |
| `--fail-on-axis <axis>=<grade>` | NEW, repeatable | Exit 2 if axis grade worse than threshold. Example: `--fail-on-axis security=B --fail-on-axis permission_hygiene=C`. |
| `--strict-mcp` | NEW, opt-in | Flags any MCP external domain when no allowlist configured. Default off. |
| `--axes-only` | NEW, opt-in | Print only the 4-axis grid to stdout. Findings emitted to stderr. For shell pipelines and PR-comment renderer. |

**Exit-code precedence**: `--fail-on` and `--fail-on-axis` evaluated together, worst wins. Existing semantics preserved (0 clean / 1 below / 2 at-or-above).

## Testing strategy

Five layers, all checked-in fixtures, deterministic:

1. **Rule unit tests** — `pkg/rules/<rule>_test.go` per new rule. Paired `testdata/malicious/<rule_id>/` (must trigger) + `testdata/clean/<rule_id>/` (must not trigger). Mirrors existing pattern.
2. **Grade aggregator tests** — `pkg/grade/grade_test.go`, table-driven per `(axis, severity-set) → expected grade`. Covers empty, single per-severity, multiple same-severity, mixed severities. ~30 cases.
3. **CVE reproducer fixtures** — `testdata/cve/<cve-id>/` per named 2026 CVE. Asserts expected rule fires + expected axis grade. Becomes the benchmark dataset for SP-6's HN-launch comparative write-up.
4. **Integrity checksum tests** — verifies `Checksum()` changes when a rule is added/removed, axis flips, cap-table cell changes, rationale template string changes.
5. **JSON schema snapshot test** — golden-file snapshot of `pkg/reporter/json.go` output against a known fixture. Snapshot update requires manual approval; catches accidental schema drift.

No file-system mocking — all tests work off real `testdata/` directories. Matches existing skill-detector convention. `gosec G101` already excluded for `_test.go` (allows hardcoded fixture credentials).

## Compat invariants

- Running `skill-detector .` on a SKILL.md-only repo continues to emit identical Findings + Severity + flat Score as before, plus a new "Trust Score" block above. No flag flip required.
- JSON reporter consumers parsing existing fields continue to work unchanged.
- `--fail-on <severity>` exit-code behavior unchanged.
- Homebrew tap distribution unchanged. GoReleaser flow unchanged.

## Migration story (informational — SP-2 consumes this)

`skillmoss-go` migration after SP-1 ships (lives in SP-2 spec, summarized here so SP-1 reviewers see the contract):

- Bump `require github.com/velzepooz/skill-detector` to v0.2.x.
- Add DB migration: `scans.axis_grades JSONB`, `findings.axis TEXT` (NOT NULL with default `'security'` for backfill of existing rows).
- Existing `scan.Runner.Run()` adapted to persist `res.Axes` into `axis_grades`.
- Result page template refactored to render axis grid above existing findings list.
- `repo_identity` entity introduction is SP-2 scope; SP-1 does not require it.

## Schedule

| Day | Milestone |
|---|---|
| Day 1–2 | `pkg/axes/`, `pkg/grade/`, `pkg/model` mutations, `pkg/rules.Rule` interface change, registry invariant enforcement, all existing tests green with axis backfill on 6 existing rule groups |
| Day 3–4 | New rules 1–3 (`claude_md.*`), file-class detection for `claude_md`, paired fixtures |
| Day 5–6 | New rules 4–6 (`settings_json.*` + `hooks.shell_metacharacter_interpolation`), file-class detection for `claude_settings` + hook synthesis, paired fixtures |
| Day 7 | New rule 7 (`mcp.external_domain_reach`), MCP discovery, paired fixtures |
| Day 8 | Reporter additive output (text + json), CLI flag additions, integrity checksum extension |
| Day 9 | CVE reproducer fixtures under `testdata/cve/` for each named 2026 CVE |
| Day 10 | Polish + release v0.2.0 (minor bump from current v0.1.0) via existing GoReleaser flow |

10 working days (= 2 weeks).

## Risks

| Risk | Mitigation |
|---|---|
| Rule detection regex / heuristic false positives discovered during SP-2 dogfooding | Each rule ships with a `Description()` referencing the deterministic pattern that fired; users contest via rule-tuning conversations, not credibility hits. Suppression workflow (P2) covers ongoing operational FP rate. |
| Hierarchy mismatch — 4-level CLAUDE.md hierarchy is harder to detect than expected | Simplification: SP-1 treats any matched CLAUDE.md as a separate source with path-inferred `Hierarchy` tag. Wrong inference is non-fatal (display only). |
| Existing Homebrew users see unexpected new output and complain | "Additive V1" choice means JSON consumers unbroken. Text reporter changes are visible but additive; release notes call out the new block. |
| Checksum extension breaks CI for users with pinned `expectedChecksum` | New ldflag value ships with v1.2 release. Documented in CHANGELOG. Dev-build behavior (empty checksum = skip) unchanged. |
| Snyk Agent Guard GA lands during these 2 weeks | Engineering-side: nothing to do. Positioning-side: SP-6 handles. |

## Open questions (none blocking)

All design decisions resolved. Implementation can begin immediately on approval.

## Approval

- [x] Section 1 — Module layout & Rule interface refactor (approved 2026-05-18)
- [x] Section 2 — Axis taxonomy, file-class detection, rule catalog (approved 2026-05-18)
- [x] Section 3 — Grade aggregator, rationale, integrity (approved 2026-05-18)
- [x] Section 4 — Reporter output, CLI flags, testing (approved 2026-05-18)
- [ ] Final spec review by user
