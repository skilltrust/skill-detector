# skill-detector — Architecture

Single source of truth for the package layout and the contracts between
packages. `AGENTS.md` carries the behavioural contract — scope, how to add a
rule, testdata conventions — and does not repeat the tree below.

`skill-detector` is a Go CLI and library that scans AI-agent configuration
files for security and governance issues. It is a pipeline: discover files,
apply path-gated rules, score, aggregate per-axis grades, report. Extensibility
comes from a rule registry. The same packages are imported as a library by the
hosted scanner and by the GitHub Action — see
[`cross-repo.md`](cross-repo.md).

## Pipeline

```
Input (directory or file path)
  → Discovery                         pkg/scanner/discover.go, gitignore.go
      • prunes the hardcoded skip-dirs
      • honours .gitignore unless --scan-all, counting what it skipped
      • restricts to scannable extensions, flags binaries,
        follows in-tree symlinks through a scoped os.Root
      • records skill roots and stamps FileContext.SkillRoot
  → Rule application                  pkg/rules
      • ConfigurationDiagnostics runs independent bounded analyzers first;
        Codex errors abort the scan, limitations append ScanResult.Warnings
      • every Match() gates by file class first
      • baseRule.newFinding stamps the rule's axis onto each finding
  → Confidence scoring + diagnosis    pkg/scorer.Score
  → Config overrides                  pkg/scorer.ApplyOverrides
      • writes EffSeverity, never Severity
  → Allowlist filtering               pkg/scanner/allowlist.go
      • only when a config was loaded
  → Deterministic sort                file path, then line, then rule ID
  → Triage                            pkg/triage (seam; no-op unless a
                                      Verifier is injected)
  → Per-axis aggregation              pkg/grade → ScanResult.Axes
  → Reporting                         pkg/reporter (text | json | quiet)
  → Warnings and exit code            cmd/skill-detector
```

Stages run in that order — `pkg/scanner/scanner.go` is the one place the order
is expressed — and each consumes the slice the previous one produced. The sort
sits ahead of triage deliberately: it fixes the batch a verifier sees and the
order findings are reported in, so neither depends on walk timing.

Configuration diagnostics are independent of enabled rules. Disabling a
finding must not convert an unparsed configuration into a clean result.
Direct `Rule.Match` consumers must also call
`rules.ConfigurationDiagnostics`: the rule interface has no error/warning
channel. `CodexConfigDiagnostics` remains the bounded Codex analyzer behind
that shared entry point. The scanner handles both.

Claude hook/gateway diagnostics preserve handler type, event and matcher
context, but file presence alone never proves runtime activation. HTTP hook
destinations and event/header/environment exposure are inventory, not an
external-host threat classification. Before a configuration file crosses the
optional verifier boundary, hook/gateway header values and URL credentials are
redacted; configured hosts are never contacted.

## Commands

`cmd/skill-detector` is a Cobra CLI with three sub-commands:

- **`scan <path>`** — the pipeline above. `main.go` builds the ruleset by
  calling `rules.DefaultRegistry()` directly. `--strict-mcp` does not swap the
  registry: `applyStrictMCP` upgrades the SD-021 findings in place after the
  scan returns and re-runs `grade.Grade` over every axis, so the ruleset
  fingerprint stays stable.
- **`delta <base.json> <head.json>`** — diffs two scan results, emitting
  `--format json|markdown`. A thin wrapper over `pkg/delta.Compute`.
- **`version`** — prints the injected version, the rule count and the ruleset
  fingerprint.

Exit codes: `0` clean, `1` findings below the `--fail-on` / `--fail-on-axis`
threshold, `2` a finding at or above the threshold (the worse of the severity
check and the axis-grade check wins), `3` a tool error — bad arguments, an
unreadable path, an internal failure.

## Package tree and dependency direction

```
cmd/skill-detector    main.go, delta.go, input.go — CLI entry points, flags,
                      exit-code decision
  ├── pkg/axes        the four axis names and the A–F grade type; wire-stable
  ├── pkg/model       shared domain types
  ├── pkg/config      loads .skill-detector.yml, applies defaults,
  │                   per-rule toggles and allowlists
  ├── pkg/rules       DefaultRegistry(), built by the CLI and handed to the
  │                   scanner
  ├── pkg/grade       called again by applyStrictMCP to re-grade in place
  ├── pkg/scanner     orchestration and the filesystem walk
  │     ├── pkg/rules       detection rules and file-class predicates
  │     ├── pkg/scorer      per-finding confidence, diagnosis, config overrides
  │     ├── pkg/grade       per-axis aggregator
  │     ├── pkg/triage      pluggable verification seam
  │     ├── pkg/permission  capability extraction
  │     ├── pkg/config
  │     ├── pkg/axes
  │     └── pkg/model
  ├── pkg/delta       scan-to-scan diff
  └── pkg/reporter    output formatting
```

`pkg/scorer` is reached only through `pkg/scanner`; the CLI does not import it.
`pkg/rules` imports `pkg/grade`, because the ruleset fingerprint hashes the
grading metadata alongside the rules. Every package bottoms out at `pkg/model`
and `pkg/axes`, which import nothing from this module beyond each other.

Dependency direction is one-way: nothing under `pkg/` imports `cmd/`.
`pkg/grade`, `pkg/delta`, `pkg/scorer` and `pkg/triage` are pure — no IO, no
global state — which is what makes them safe to embed in another process.
`pkg/rules` is pure too: it reads the `FileContext` it is handed and never
touches the filesystem, so discovery's scoped `os.Root` stays the only thing
that opens a path.

### `pkg/axes`
`Axis` (`security`, `permission_hygiene`, `transparency`, `quality`), `Grade`
(`A`…`F`), and `Order`, the canonical iteration order. These strings appear in
JSON output, badge URLs and downstream databases; changing one is a major
version bump.

### `pkg/model`
Domain types shared by every other package. `Finding` carries `RuleID`,
`Severity`, `EffSeverity`, `Confidence`, `Axis`, `FilePath` and `Line`.
`ScanResult` carries `Findings`, `Permissions`, `ConfigOverrides`, `Axes`,
`Warnings`, `FileCount`, `RuleCount`, `Version`, `Checksum`, `SchemaVersion`
and `NoAgentSurface`. `FileContext` is the per-file metadata handed to rules and
triage; it carries `SkillRoot` and an `AnalysisContext`, and it is not part of
the JSON wire format. Analysis context distinguishes known, candidate, absent,
empty, malformed, unsupported, unavailable and unknown harness/version/source/
trust/session facts. It is internal pipeline metadata: `Scanner.Scan` supplies
unknown runtime facts and there is no JSON, CLI or caller input contract.

`Severity` is an ordered enum — `Critical`, `High`, `Medium`, `Low`, `Info` —
where `Critical` is numerically smallest, so "worst" is a `<` comparison.

### `pkg/config`
Loads `.skill-detector.yml`, cascading from the scan path upwards or from an
explicit path, applies defaults, and supports per-rule enable/disable toggles
plus allowlist entries.

### `pkg/scanner`
- `discover.go` walks the target, prunes the hardcoded skip-dirs
  (`node_modules`, `vendor`, `dist`, `build`, `target`, `.next`, `.git`),
  classifies files, flags binaries and follows in-tree symlinks.
  `DiscoverWithOptions(root, opts)` threads `ScanAll` and returns the files
  plus a `DiscoverStats`, which counts agent-shaped paths that `.gitignore`
  excluded so the caller can warn that the scan may not have seen the primary
  attack surface.

  The walk is two-phase. Directory entries are visited in lexical order, so a
  subdirectory sorting before the manifest beside it is walked before that
  manifest is seen; scope cannot be decided in place during a single pass.
  Phase one records every skill root as the walk finds them, after the skip-dir
  pruning, so a manifest inside a skipped directory creates no root. Phase two,
  once the root set is closed, resolves each file's nearest ancestor root and
  stamps it on `FileContext.SkillRoot`. Reads still go through the scoped
  `os.Root`, and candidates are consumed in walk order.
- `gitignore.go` is a best-effort wrapper over the root `.gitignore` only. A
  missing or malformed file is a no-op.
- `scanner.go` orchestrates, in this order: discover, stamp internal analysis
  context, run configuration diagnostics, run the enabled rules,
  score, apply config overrides, apply allowlists, sort, triage, aggregate
  axes, build warnings. `Options` carries `Config`, `Version`, `Timeout`,
  `ScanAll`, `Verifier` and `TriageTimeout`.
- `allowlist.go` drops findings matching configured domains and patterns.

### `pkg/rules`
- `rule.go` — the `Rule` interface and `baseRule`.
- `registry.go` — `RuleRegistry`, `DefaultRegistry()` and `Checksum()`.
- `fileclass.go` — the path predicates every rule gates on.
- `pathscope.go` — resolves a relative reference against the file's skill root,
  so an in-package reference is distinguished from one that leaves the skill.
- The rule files themselves: `injection.go`, `access_control.go`,
  `misconfiguration.go`, `exfiltration.go`, `supply_chain.go`, `integrity.go`,
  `claude_md.go`, `settings_json.go`, `hooks.go`, `mcp.go`, `dns_exfil.go`,
  `reverse_shell.go`. Rule IDs are `SD-NNN`; `CHANGELOG.md` records what each
  one detects.

`ContentScanTypes`, in `rule.go`, is the shared extension list for
line-oriented content rules: every scannable config and doc extension, the
script languages, the extensionless case for hook scripts inside agent config
directories, and the `.cursorrules` / `.windsurfrules` dotfile forms. Rule
groups that need the standard set register with it rather than hand-rolling
their own, so a new script extension is added once.

### `pkg/grade`
Pure aggregator. `Grade(axis, findings) → AxisResult`.

### `pkg/triage`
The pluggable verification seam. `Verifier.Classify(ctx, file, findings)`
returns a `Verdict` per finding — `real_threat`, `benign_example` or
`uncertain` — matched back to its finding by the verdict's 1-based index when
the verifier stamps one, and otherwise by a `{RuleID, Line}` key. That key is
not unique: a rule can emit several findings on one line. A key claimed by two
findings, or by two verdicts, is therefore resolved to the `unavailable`
fail-safe rather than guessed at. Implementations must be deterministic.

The engine ships `NoopVerifier`, which returns `uncertain` for everything and
is the default when `Options.Verifier` is nil, and `ScriptedVerifier`, a test
double. The CLI wires neither in, which is what keeps it offline,
deterministic and free of network dependencies.

Triage never makes a grade worse than the deterministic one. On a verifier
error or a deadline the affected findings are left alone and stamped
`unavailable`.

### `pkg/permission`
Derives the capabilities a scan implies — network reach, filesystem access,
environment-variable access and so on — and returns them as
`ScanResult.Permissions`. `Extract(findings, files)` works from three inputs:
the rule IDs of the findings, mapped through a rule-to-capability table; an
environment-variable pattern applied to the discovered file contents; and a
baseline filesystem permission, added whenever any file was discovered at all.
It parses
no declared permission and compares nothing against a manifest; it describes
what the scanned files reach for, not what they claim.

Every registered rule must be classified here, either mapped to a capability or
listed as capability-free. A test over `DefaultRegistry().All()` enforces it, so
a new rule fails the suite until it is classified.

### `pkg/scorer`
Does not compute an aggregate score — there is no flat 0–100 number anywhere in
the pipeline. `Score(findings)` adjusts each finding's `Confidence` from
same-file rule co-occurrence and a corroborating-pair table, and generates a
per-rule `Diagnosis` string stating the threat hypothesis against the benign
alternative. `ApplyOverrides` then applies config-file severity and context
overrides, writing to `EffSeverity` and leaving `Severity` alone. Consumers
read `ScanResult.Axes` for the trust-score surface; `Confidence` and
`Diagnosis` are per-finding context.

### `pkg/delta`
Pure scan-to-scan diff. `Compute(base, head) → Delta` returns a per-axis
`GradeDelta`, the added and removed findings, and axis-downgrade explanations;
`GradeArrow` renders the movement. Findings are identified by a content hash —
content addressing, not a cryptographic primitive. Matching runs in two passes:
exact on the full key, then leftovers paired one-for-one on the same key minus
the line number, so an edit above a finding is not reported as one finding
resolved and another appearing. Diff lists follow scan order and are
deterministic.

### `pkg/reporter`
A `Reporter` interface with three implementations: `text` (the Trust Score
block above the findings list; `OmitTrustScore` backs `--axes-only`), `json`
(the `axes` map plus a per-finding `axis` tag), and `quiet` (exit code only).
`theme.go` holds the ANSI styling.

## The `Rule` interface and the registry

Every rule implements:

```go
type Rule interface {
	ID() string
	Name() string
	Severity() model.Severity
	Category() string
	FileTypes() []string
	Match(content []byte, ctx model.FileContext) []model.Finding
	Axis() axes.Axis
}
```

Rules embed `baseRule`, which supplies every accessor from the fields set at
registration. Findings are constructed through `baseRule.newFinding`, which
pre-fills the rule's ID, name, severity, category and axis, so rule code cannot
forget the axis. `newFindingAs` is the same constructor with severity and axis
overridden, for a rule whose pattern means different things in different
contexts and where the difference is decidable at match time; the registered
severity remains the ceiling and remains the thing the fingerprint hashes.

`DefaultRegistry()` composes the rule groups. A rule group exposes one
`RegisterXxxRules(registry)` function, and `DefaultRegistry()` calls them in
turn — that function is the single wiring point, and a new rule group is
registered there and nowhere else. A group is not the same thing as a file:
some files hold a rule that a neighbouring group registers, so there are fewer
register functions than rule files. `RegisterExfiltrationRules` registers
SD-022 from `dns_exfil.go`, and that file exposes no register function of its
own.

`RulesFor(ext)` selects the rules whose `FileTypes()` contain a given
extension, and `All()` returns everything registered. `Count()` is the total
number of registered rules — it is what `version` prints, and it is not the
number a scan reports. `ScanResult.RuleCount`, serialised as `rules_applied`,
counts the rules that actually ran against at least one discovered file, so it
is at most `Count()` and usually less.

`Checksum()` hashes each rule's `(ID, Name, Severity, Category, Axis)`,
sorted, together with `grade.CanonicalMetadata()`, and returns the first 16 hex
characters. Any change to rule registration, axis assignment, cap-table
thresholds or rationale templates moves it. It is a **ruleset fingerprint**,
printed by `version` and carried on every scan result as `ruleset_checksum` so
two scans can be compared for having run the same ruleset. It gates nothing.

## The path-gating contract

**Every rule gates by file class as the first statement of `Match()`.** This is
a requirement on all rules, not a convention: a rule without a gate fires on
every file carrying a matching extension, and the noise floor on a real-world
repository makes the whole result unusable.

The standard gate is:

```go
func InScope(ctx model.FileContext) bool {
	return IsAgentFile(ctx.Path) || isInAgentConfigDir(ctx.Path) || InSkillSubtree(ctx)
}
```

Its three arms:

- `IsAgentFile(path)` — the union of the agent file classes:
  `IsSkillManifest` (`SKILL.md`, `skill.yaml`), `IsInstructionFile` (the
  per-harness instruction files, at any level of the hierarchy),
  `IsClaudeSettings` and `IsMCPConfig`.
- `isInAgentConfigDir(path)` — any file under `.claude/`, `.codex/`,
  `.opencode/`, `.cursor/`, `.gemini/`, `.windsurf/` or `.agents/`. It
  deliberately excludes `.github/` and `.vscode/`: those directories are walked
  so the named predicates can match the specific instruction and MCP files
  inside them, but treating them as agent config directories would run every
  content rule over all of CI.
- `InSkillSubtree(ctx)` — the file lies inside a skill root.

A rule needing a narrower class composes the individual predicates instead;
`IsAgentFile(ctx.Path)` alone is the gate for a rule that must deliberately not
fire inside a skill root.

### The skill-root predicate

A **skill root** is a directory that contains a skill manifest — `SKILL.md` or
`skill.yaml`. Its entire subtree is in scope, wherever that directory sits in
the tree.

Unlike every other predicate in `fileclass.go`, this is not a path-shape test.
Whether some ancestor directory holds a manifest is a filesystem fact and
cannot be decided from the path string, so discovery computes it once per walk
and hands it over on `FileContext.SkillRoot` — the nearest ancestor root
relative to the scan root, or `""`. `InSkillSubtree` reads that field:

```go
func InSkillSubtree(ctx model.FileContext) bool {
	return ctx.SkillRoot != "" && !isExcluded(ctx.Path) && !inSkillRootExcludedDir(ctx.Path)
}
```

Two exclusions sit above the arm. The hardcoded skip-dirs are pruned before
phase one runs, so a manifest inside a vendored or build directory creates no
root at all. And `.github/` and `.vscode/` are excluded from this arm, so a
manifest at a repository root does not pull CI workflows and editor tasks into
scope. The exclusion check is repeated in `pkg/rules` rather than trusted from
discovery, because `pkg/rules` is a published API and a caller may build a
`FileContext` by hand.

## Axis aggregation

Each finding carries exactly one axis, stamped by its rule. `grade.Grade` runs
once per axis, over the whole findings slice, and filters internally.

The algorithm is worst-finding-wins with a per-axis cap:

1. Keep the findings on this axis; set aside any the triage seam marked as
   suppressed, counting them.
2. With nothing left in the pool, the axis is `A`, with a rationale that says
   so — and says how many findings were set aside, when any were. An `A` is the
   absence of a counted finding, not a positive assessment.
3. Otherwise find the worst `Severity` in the pool, collect every finding at
   that severity as the driving findings, aggregate them by rule ID, and sort
   by rule ID so the result is deterministic.
4. The letter comes from `caps[axis][severity]` in `pkg/grade/templates.go` — a
   per-axis mapping, so the same severity does not produce the same letter on
   every axis. Security and permission hygiene cap harder than transparency and
   quality.
5. `rationaleTemplate(axis, severity, topDescription)` produces the rationale
   string deterministically. No model is involved in this path.

The field the cap table is indexed by is `Finding.Severity`, not
`Finding.EffSeverity`. `EffSeverity` is written by `scorer.ApplyOverrides` from
the user's config file and read by the `--fail-on` severity threshold, so a
per-rule severity override in `.skill-detector.yml` moves the exit code and not
the grade.

`CanonicalMetadata()` emits the stable string form of the cap table and the
templates, and is what feeds them into the ruleset fingerprint.

### When no axes are emitted

Discovery is deliberately wider than the rules' path gates — it walks every
scannable extension — so "files were scanned" does not mean the agent surface
was read. When no discovered file satisfies `rules.InScope`, the scan sets
`ScanResult.NoAgentSurface`, leaves `Axes` and `Permissions` empty, and adds a
warning saying that nothing was checked.

This is deliberate and is not a missing default. Grading such a tree `A` would
report "checked and clean" about files no rule ever opened, and that `A`
travels — into CI exit codes, badges and downstream databases. Absent axes is
the shape every consumer already handles: the text reporter omits the Trust
Score block, `axes` is `omitempty` in JSON, and `--fail-on-axis` treats a
missing axis as nothing to compare. A result carrying `no_agent_surface` must
not be stored or displayed as a pass.

## The JSON schema version

`pkg/model.SchemaVersion` is the version of the JSON wire format. `pkg/scanner`
stamps it onto every `ScanResult` as `schema_version`, and downstream consumers
read it to detect a format they do not know.

It is bumped in the same commit as any change to the shape of `ScanResult` or
of anything nested inside it — a field added, renamed, removed or retyped.
Enforcement is `cmd/skill-detector/schema_golden_test.go` against
`cmd/skill-detector/testdata/schema_shapes.json`: the test compares the shape
of the emitted JSON with the golden file, so a shape change without a bump
fails. The procedure is in
[`development-guide.md`](development-guide.md#json-output-schema).

## Testing

- **Unit tests** — co-located `_test.go` in every package.
- **Path-gate tests** — every rule has a test asserting it does not fire on a
  non-agent path.
- **Reproducer fixtures** — `testdata/cve/<incident>/`, each a minimal repo,
  exercised through both the Go API and the compiled binary.
- **Scope regression** — the default scope walks and fires only on agent files,
  and the two installation layouts of the same skill grade identically.
- **Adversarial fixtures** — manifests at several depths each scoping their own
  subtree, with controls proving that a directory which is not a skill root,
  and a manifest inside an excluded directory, stay out of scope.
- **Registry integrity** — the fingerprint changes when a rule's axis is
  flipped.
- **Triage** — the seam is driven with `ScriptedVerifier`, including the
  verifier-error path.
- **End-to-end** — the full CLI, over the fixture trees.
- **CI** — lint, test, build, and a self-scan on every push and pull request.

Fixture conventions are in `AGENTS.md`; commands are in
[`development-guide.md`](development-guide.md).

## Distribution

GoReleaser builds linux, darwin and windows across amd64 and arm64 on every
`v*` tag, publishes a GitHub Release, and updates the Homebrew tap. The version
string is injected at build time with `-ldflags`. Steps are in
[`development-guide.md`](development-guide.md).
