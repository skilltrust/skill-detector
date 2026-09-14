# AGENTS.md

Be extremely concise. Sacrifice grammar for the sake of concision.

This is the coding contract for `skill-detector`. It applies to every agent and
every contributor working in this repo. `CLAUDE.md` is a symlink to this file.

## Git branches

Name branches by purpose. Allowed types: `feat`, `fix`, `hotfix`, `refactor`,
`docs`, `chore`, and `epic`.

For work tracked in Linear, Jira, or another tracker, use
`<type>/<issue-id>-<short-name>`. Copy the issue identifier exactly:

```text
feat/PROJ-123-short-name
fix/PROJ-123-short-name
hotfix/PROJ-123-short-name
refactor/PROJ-123-short-name
docs/PROJ-123-short-name
chore/PROJ-123-short-name
epic/PROJ-100-short-name
```

For untracked work, use `<type>/<short-name>`:

```text
feat/short-name
fix/short-name
hotfix/short-name
refactor/short-name
docs/short-name
chore/short-name
epic/short-name
```

Write the short name in lowercase kebab-case. For a large task or project, create
an `epic/` branch. The developer decides between child pull requests into that
branch and direct work on it. Merge the completed epic branch through one final
pull request.

## Project knowledge

Docs map: [`docs/README.md`](docs/README.md). The committed doc set is:

| Artifact | Location | When to write |
|----------|----------|---------------|
| Docs map | [`docs/README.md`](docs/README.md) | A doc is added or removed. |
| Architecture | [`docs/architecture.md`](docs/architecture.md) | A package is added/removed or a contract between packages changes. |
| Domain term / invariant | [`docs/glossary.md`](docs/glossary.md) | A new concept, rule ID convention, or invariant appears. |
| What this tool is for | [`docs/product-context.md`](docs/product-context.md) | The intended use or audience changes. |
| Downstream consumers | [`docs/cross-repo.md`](docs/cross-repo.md) | The published surface or a consumer contract changes. |
| Build / test / lint / release steps | [`docs/development-guide.md`](docs/development-guide.md) | Those steps change. |
| Released behaviour | `CHANGELOG.md` | Every user-visible change, in the same PR. |

Never document the same thing twice. Package layout lives only in
`docs/architecture.md`; this file carries the behavioral contract.

`docs/` is allow-listed in `.gitignore`: a new file there publishes nothing
until it is named in that list. Not everything the maintainer keeps is in this
repo — when a rule below has no reason attached, that is deliberate. See
"Settled behaviour".

## Architecture

Pipeline CLI: discover → rules (path-gated) → score → aggregate axes → report.
Package layout and dependency graph: **`docs/architecture.md`** (single source
of truth — do not duplicate the tree here).

Key wiring points:
- `pkg/rules/registry.go::DefaultRegistry()` registers all rule groups — **add new rule groups here**. The CLI calls it directly; `--strict-mcp` does not swap the registry, it upgrades SD-021 post-hoc in `cmd/skill-detector/main.go::applyStrictMCP` so the checksum stays stable.
- `pkg/permission/extractor.go` — `ruleCapabilities` / `capabilityFreeRules`. Every registered rule must appear in one of them; a test over `DefaultRegistry().All()` enforces it.
- `pkg/model.SchemaVersion` — the JSON wire version. Shape change → bump in the same commit; `cmd/skill-detector/schema_golden_test.go` + `cmd/skill-detector/testdata/schema_shapes.json` fail otherwise. Procedure: [`docs/development-guide.md#json-output-schema`](docs/development-guide.md#json-output-schema).
- `pkg/scanner.Options.ScanAll` threads `--scan-all` from CLI through to `DiscoverWithOptions`.
- `registry.Checksum()` hashes per-rule `(ID, Name, Severity, Category, Axis)` + `grade.CanonicalMetadata()` — any change to rules, axis assignments, cap-table cells, or rationale templates moves it. It is a **ruleset fingerprint** (printed by `version`), not a gate. `expectedChecksum` is deliberately never pinned. Record the value in `CHANGELOG.md` when it moves; do not add the ldflag.
- Exit codes: `0`=clean, `1`=findings below the `--fail-on`/`--fail-on-axis` threshold, `2`=finding at/above threshold (worst of severity OR axis grade wins), `3`=tool error (bad args, unreadable path, internal failure).
- `scanner.New(registry, scanner.Options{ScanAll: bool, Version: string}).Scan(ctx, input)` returns `model.ScanResult` with `Findings` + `Axes` + `Warnings` (e.g. gitignore-blindness) + `SchemaVersion`.
- `pkg/rules.ContentScanTypes` — shared extension list for line-oriented content rules; new rule groups needing the standard config/doc/script extension set should register with it instead of hand-rolling `types:`.

## Scope

The scanner intentionally walks only AI-agent files by default:
- Skill manifests: `SKILL.md`, `skill.yaml` (`IsSkillManifest`).
- Per-harness instruction files, at any hierarchy level: `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules` — plus `.github/copilot-instructions.md` and any `.mdc` under `.cursor/rules/`, which are matched by directory component, not by basename alone (`instructionFileNames` / `IsInstructionFile`). Content rules run uniformly across all of them; a rule that only handles `CLAUDE.md` is a bug.
- `.claude/settings.json`, `.claude/settings.local.json`, at any depth under a `.claude/` (`IsClaudeSettings`).
- MCP configs (`IsMCPConfig`): `.mcp.json` (leading dot) anywhere; bare `mcp.json` only under `.claude/`, `.cursor/` or `.vscode/`.
- Anything under `.claude/`, `.codex/`, `.opencode/`, `.cursor/`, `.gemini/`, `.windsurf/`, `.agents/` directories (hook scripts, bundled test files, etc.). `.agents/` is the `npx skills add` install path — a skill installed the standard way lands there.
- Anything under a directory containing a skill manifest — `SKILL.md` **or** `skill.yaml` (a *skill root*) — the whole subtree, wherever that directory sits. This is a filesystem fact, not a path-shape fact (`FileContext.SkillRoot`, `InScope(ctx)` in `pkg/rules/fileclass.go`). The hardcoded skip-dirs still sit above this — a manifest inside `node_modules/` etc. creates no root. `.github/` and `.vscode/` are excluded from this arm too.

Hardcoded skip-dirs: `node_modules`, `vendor`, `dist`, `build`, `target`,
`.next`, `.git` — always skipped, even under `--scan-all`.

Honors `.gitignore` at the scan root by default. `--scan-all` stops honoring
`.gitignore` but does NOT lift the hardcoded skip list.

## Adding a rule

1. New file `pkg/rules/<name>.go` implementing `Rule` interface from `rule.go`. The struct embeds `baseRule`, sets `axis` in its registration — `baseRule.newFinding` stamps `Finding.Axis` automatically.
2. **Path gate**: first line of `Match()` MUST gate by file class. `InScope(ctx)` — `IsAgentFile(path) || isInAgentConfigDir(path) || InSkillSubtree(ctx)` — is the default gate; use `IsAgentFile(ctx.Path)` alone only when a rule must deliberately NOT fire inside a skill root. Without a gate, the rule fires on every file with a matching extension and balloons the noise floor.
3. Add `RegisterXxxRules(registry)` call in `pkg/rules/registry.go::DefaultRegistry()` — one place, the CLI builds from it.
3a. Classify the rule in `pkg/permission/extractor.go`: map it in `ruleCapabilities`, or list it in `capabilityFreeRules` if it flags a technique rather than a capability. The exhaustiveness test fails until you do.
4. Fixtures in `testdata/malicious/<name>/...` — paths MUST satisfy `InScope()` or the path gate will block them. Common shapes: `SKILL.md`, `CLAUDE.md`, `.claude/settings.json`, `.claude/scripts/<orig>.sh`, or any file beside a `SKILL.md`/`skill.yaml` in the fixture tree.
5. Tests in `pkg/rules/<name>_test.go`. Each rule needs a paired clean fixture (must NOT trigger) and a `TestSDxxx_GatesNonAgentFile` test (must NOT fire on `node_modules/.../README.md` etc.).

## Adding a new axis

Don't, in v0.x. The four axes (`security`, `permission_hygiene`,
`transparency`, `quality`) are wire-stable strings appearing in JSON, badge
URLs and downstream databases. Changing them requires a major version bump. If
a new dimension seems needed, raise it with the maintainer before writing code.

## Testdata conventions

- `testdata/clean/<rule-or-dir>/` — must produce zero findings.
- `testdata/malicious/<rule>/` — must trigger that rule. **Fixture paths must satisfy `InScope`**: agent-file-shaped (`SKILL.md`/`CLAUDE.md`/`.claude/...`) *or* sitting beside a `SKILL.md`/`skill.yaml` in the fixture tree (a skill root), so the path-gated rules can fire.
- `testdata/cve/<incident>/` — reproducer fixtures for named real-world incidents. Each is a minimal repo. Used by `cmd/skill-detector/cve_repro_test.go` for Go-API + binary E2E tests.
- `testdata/edge-cases/` — `binary-file`, `empty-dir`, `empty-skill`, `hidden-dir`, `malformed-yaml`.
- `gosec G101` excluded in `_test.go` (hardcoded creds in fixtures).
- Fixture `CLAUDE.md` / `AGENTS.md` files track normally — `.gitignore` no longer excludes those names at any depth. Do not use `git add -f` for them; if one appears ignored, the pattern is wrong and the pattern is what to fix.

## Release

Tag `v*` triggers GoReleaser → cross-platform binaries + `velzepooz/homebrew-tap`.
Version injected via `-ldflags "-X main.version=..."`. Steps:
[`docs/development-guide.md`](docs/development-guide.md).

**A release is not done when the binaries exist.** Three pins downstream hold
this engine's version and none of them notices a new tag: the `scan-action`
GitHub Action (`action.yml` → `detector-version`, which needs its own release
to take effect), and two in the hosted scanner (its `go.mod` and its CI fixture
pin). Moving them is part of the release, not follow-up work. An agent working
only in this repo cannot do it — say so in the handoff rather than tagging and
calling it shipped.

Released behaviour, per version: `CHANGELOG.md`. It is public and
authoritative; do not restate it here.

## Settled behaviour — confirm before changing

Some behaviour here looks like an oversight and is not. Do not change any of
the following on inference; ask the maintainer first and get a yes:

- the axis set and the axis strings
- the exit-code contract
- `pkg/model.SchemaVersion` and the JSON wire shape
- `registry.Checksum()` and whether it gates anything
- the default scope list, the skip-dirs, and any rule's path gate
- demotion and suppression thresholds in any rule
- `ScanResult.NoAgentSurface` and the result shape when a scan reads no in-scope file. A scan that checked nothing does not grade: `Axes` stays empty, and the result must not be reported, stored or displayed as a pass. It is not a missing default to fill in.
- the adversarial suite — `cmd/skill-detector/adversarial_test.go`, its tables, and the `testdata/adversarial/` fixtures — **and the fact that it is public**. It records cases the engine does not currently catch, and the tables fail when one of them changes state. That standing signal is the point of the suite and is worth more than the concealment that dropping it would buy. Do not scrub, relax or delete any of it to reduce what this repository discloses: that trade was weighed and settled, and reversing it needs the maintainer.

The reasoning behind each of these is recorded outside this repo. Absence of a
reason in the codebase is not evidence that there isn't one.
