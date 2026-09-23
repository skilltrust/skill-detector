# skill-detector — Glossary

Domain terms and invariants, in the sense this repository uses them. Where a
term names something in the code, the package is given. Terms are alphabetical.

### Agent file

A file that configures an AI coding agent, and therefore one of the file
classes the scanner inspects: a skill manifest, a per-harness instruction file
(`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`,
`.github/copilot-instructions.md`, a `.mdc` under `.cursor/rules/`), a Claude
settings file, or an MCP configuration. `rules.IsAgentFile` is the union
predicate over those classes; `README.md` lists the exact filenames.

### Analysis context

Internal facts that can change whether a declaration applies: harness,
version, provider, declaration origin, trust, session and named activation
conditions. Every value distinguishes known, candidate, absent, empty,
malformed, unsupported, unavailable and unknown. Repository placement can
produce a candidate but cannot authenticate managed provenance, trust or
runtime activation. The context travels to rules on `model.FileContext`; it is
not serialized in `ScanResult` and has no CLI or caller input contract.

### Axis

One of the four dimensions a scan grades: `security`, `permission_hygiene`,
`transparency`, `quality`. Every rule is assigned exactly one, and every
finding carries the axis of the rule that produced it. The strings are
wire-stable — they appear in JSON output, badge URLs and downstream databases —
so changing one is a major version bump. Defined in `pkg/axes`.

### Declaration analysis

Inspection of configuration present in scanned files, not a reconstruction of
the configuration a harness will execute. Trust, selected profiles, omitted
sources, overrides and external enforcement may change activation. A declared
capability finding does not prove that an untrusted repository can activate
it. Warnings carry that distinction; absence of findings does not certify an
effective runtime configuration.

### Delta

The difference between two scan results: per-axis grade movement, findings
added, findings removed, and an explanation for any axis that got worse.
Computed by `pkg/delta.Compute` and exposed by the `delta` sub-command, which
takes two JSON scan results and emits JSON or Markdown.

### Finding

One detection: a rule fired on a file at a line. It carries the rule ID and
name, the severity, the effective severity, the axis, the confidence, the file
path, the line number, a description and a remediation string. Findings are
constructed only through the `baseRule` constructors, which stamp the rule's
metadata so no field can be forgotten. Defined in `pkg/model`.

### Grade

A letter from `A` to `F` summarising one axis. The worst finding on an axis
sets that axis's letter, through a per-axis cap table mapping severity to
grade; an axis with no findings left in its pool is `A`. An `A` means nothing
was counted against that axis — it is the absence of a detection, not a
positive assessment. Computed by `pkg/grade`.

### Path gate

The file-class check every rule performs as the first statement of its
`Match()`. `rules.InScope(ctx)` is the standard gate: an agent file by name,
any file inside an agent config directory, or any file inside a skill root. A
rule needing a narrower class composes the individual predicates instead. A
rule without a gate fires on every file with a matching extension, which is why
the gate is a requirement rather than a convention. See
[`architecture.md`](architecture.md).

### Rule ID

The stable identifier of a detection rule, of the form `SD-NNN` — `SD-001`,
`SD-021`. IDs are assigned in sequence, never reused and never renumbered, so
a finding, an allowlist entry and a config override can all refer to the same
rule across versions. What each rule detects is recorded in `CHANGELOG.md`.

### Ruleset fingerprint

The 16-hex-character value `rules.RuleRegistry.Checksum()` returns, printed by
the `version` sub-command and carried on every scan result as
`ruleset_checksum`. It hashes each registered rule's ID, name, severity,
category and axis, together with the canonical form of the cap table and the
rationale templates, so any change to registration, axis assignment, cap
thresholds or template strings moves it. Its purpose is to let two scans be
compared for having run the same ruleset. It gates nothing and is not a tamper
check.

### Scope

The set of files a scan actually inspects. Discovery is the outer bound: it
walks scannable extensions, prunes the hardcoded skip-dirs (`node_modules`,
`vendor`, `dist`, `build`, `target`, `.next`, `.git`) and honours `.gitignore`
unless `--scan-all` is passed. The rules' path gates are the inner bound, and
they are narrower — a file can be discovered and still be out of scope for
every rule. When nothing discovered passes a gate, the scan reports that it
checked nothing rather than grading the tree.

### Schema version

`pkg/model.SchemaVersion`, emitted on every scan result as `schema_version`.
It identifies the shape of the JSON wire format so a consumer can detect a
format it does not know. It is bumped in the same commit as any change to the
shape of `ScanResult` or of anything nested inside it, and a golden test in
`cmd/skill-detector` fails when a shape change arrives without a bump.

### Severity

How bad one finding is: `Critical`, `High`, `Medium`, `Low` or `Info`. It is
set at rule registration and stamped onto each finding the rule emits. It feeds
two independent decisions — the axis grade, through the cap table, and the exit
code, through `--fail-on`. The exit-code path reads the *effective* severity,
which a user's config file may override; the grade reads the registered one, so
an override in `.skill-detector.yml` moves the exit code and not the grade.

### Skill

A packaged unit of instructions and supporting files that an AI coding agent
loads and acts on — the thing a user installs from a third-party source and the
thing this tool is built to vet. On disk it is a directory with a manifest at
its top and whatever content the manifest brings with it: instructions,
scripts, configuration, assets.

### Skill root

A directory that contains a skill manifest — `SKILL.md` or `skill.yaml`. Its
whole subtree is in scope, wherever that directory sits in the tree. This is
the one file-class fact that is a filesystem fact rather than a path-shape
fact, so discovery computes it once per walk and hands it to the rules on
`FileContext.SkillRoot` rather than each rule resolving it. A manifest inside a
skip-dir creates no root, and `.github/` and `.vscode/` are excluded from the
subtree.
