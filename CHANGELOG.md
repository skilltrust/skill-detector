# Changelog

## v0.4.0 — 2026-05-29

### Added
- **Triage seam (`pkg/triage`).** A pluggable `Verifier` interface the scanner
  can call to reclassify findings as `real_threat`, `benign_example` or
  `uncertain`. Verdicts are matched back to findings by `(RuleID, Line)`.
- Two inert implementations ship with the engine: `NoopVerifier` (returns
  `uncertain` for everything, leaving the deterministic result untouched) and
  `ScriptedVerifier` (a test double).
- `model.Finding.Triage` — a `*TriageVerdict` carrying classification,
  confidence, rationale and source. **Omitted from JSON when nil**, so
  un-triaged scans produce byte-identical output to v0.3.x.
- `scanner.Options.Verifier` and `scanner.Options.TriageTimeout`.

### Changed
- Axis grading now skips findings that triage has confidently classified as
  benign: `Finding.IsSuppressed()` is true at classification `benign_example`
  with confidence ≥ `model.TriageDemoteThreshold` (0.85).

### Why
- The engine deliberately ships **no** LLM-backed verifier. Adding one here
  would put an API key, a network call and a non-reproducible verdict into a
  CI-facing CLI. The LLM implementation lives in the hosted scanner
  (`skilltrust`), which supplies caching to keep results stable.

### Compatibility
- **Default behavior is unchanged.** With no verifier injected — which is every
  CLI invocation — the scanner takes the same path as v0.3.3 and emits the same
  JSON.
- Triage failures are conservative by construction: a verifier error or a
  timeout marks affected findings `uncertain` / `source: "unavailable"`, so a
  grade can never come out *weaker* because triage broke.
- Registry checksum at this tag: `f1dcffd63faabeb3` (23 rules).

---

## v0.3.3 — 2026-05-25

### Added
- **`SD-023` — `settings.json` Unrestricted Permission Grant** (HIGH,
  permission_hygiene axis). Flags a bare `"*"` in `permissions.allow` in
  `.claude/settings.json` / `settings.local.json`.

### Why
- A wildcard grant slipped past `SD-017`, `SD-018` and `SD-019`, all of which
  look for specific over-broad patterns rather than the total absence of a
  restriction. Caught in the production dogfood: a settings file granting `"*"`
  left `permission_hygiene` at grade A. With `SD-023` the same fixture now
  grades D.

### Compatibility
- New rule → the registry checksum moves. Repositories with a wildcard grant
  will see `permission_hygiene` drop.

---

## v0.3.2 — 2026-05-25

### Added
- **`SD-022` — DNS Exfiltration** (HIGH, security axis). Detects data
  exfiltration over DNS: `dig` / `nslookup` / `drill` / `resolvectl` / `host`
  combined with a dynamically built dotted hostname (`$(...)`, backticks, or a
  variable). Static lookups do not fire.
- **Per-commit recall tripwire** — `cmd/skill-detector/bench_recall_test.go`
  over `testdata/bench/`. Asserts a curated slice of known attacks still grades
  C/D/F, guarding against recall lost to pattern tightening.

### Why
- `SD-022` closes the only miss in the SP-7 validation benchmark: a DNS-channel
  exfiltration sample using `nslookup` plus base64-encoded environment variables
  and no HTTP at all. Recall on the headline pool moves 0.875 → 1.0. Both
  `semgrep` and raw grep scored 0.25 on the same set.

### Fixed
- GoReleaser targeted the pre-transfer `velzepooz` org, so release asset upload
  failed with a 307 after the repository moved. Now points at `skilltrust`. The
  Homebrew tap intentionally stays at `velzepooz/homebrew-tap`.

### Compatibility
- New rule → the registry checksum moves.

---

## v0.3.1 — 2026-05-21

### Changed
- `pkg/delta.findingKey` now uses `hash/fnv` (FNV-1a, 64-bit) instead of `crypto/sha256`. Behavior identical; the change signals that the hash is content-addressing only, not a cryptographic primitive. Hash output width widens from 12 to 16 hex chars — internal-only, no wire impact.

## v0.3.0 — 2026-05-21

### Added
- `pkg/delta` package — pure-function trust-score delta computation over two `model.ScanResult`s. Returns per-axis grade movement, finding diff, and axis-downgrade explanations.
- `skill-detector delta <base.json> <head.json>` CLI sub-command emitting JSON or markdown.

### Why
- Powers the new `skilltrust/scan-action@v1` GitHub Action's optional `delta: true` mode.
- Single source of truth for delta semantics shared by the Action and the skillmoss-go PR-comment bot (SP-4). skillmoss-go's `internal/prbot.ComputeDelta` becomes a thin adapter over `pkg/delta.Compute` in a paired refactor; render snapshots remain byte-identical.

---

## v0.2.1 — 2026-05-19

### Fixed

- **SD-007** no longer flags bare URLs inside `.md`, `.txt`, or `.rst` documentation files. The network-command (`curl`/`wget`/`nc`/`ncat`) and Python-requests branches continue to fire on those file types so real attack patterns (e.g., `curl ... | bash` instructions inside `CLAUDE.md`) are still caught. Documentation links such as `https://github.com/owner/repo.git` in `INSTALL.md` no longer produce high-severity false positives. Surfaced by the `skillmoss-go` SP-2 dogfood scan of `obra/superpowers`.

---

## v0.2.0 — 2026-05-19 (SP-1: Multi-Axis Engine)

### Scope (BREAKING vs v0.1.x)
- Scanner default behavior: walks only AI-agent configuration files
  (SKILL.md, CLAUDE.md, .claude/settings*.json, .mcp.json) plus
  arbitrary files inside .claude/, .codex/, .opencode/ dirs.
- Honors .gitignore at the scan root (best-effort; missing or
  malformed .gitignore is a no-op).
- Hardcoded skip-list: node_modules, vendor, dist, build, target,
  .next, .git — always skipped, regardless of .gitignore.
- New --scan-all flag bypasses scope tightening and .gitignore
  filtering. For migration or whole-repo audits.
- All 14 pre-SP-1 rules now gate by path; they previously fired on
  any file with a matching extension. This is a breaking change
  vs. v0.1.x default behavior. --scan-all + the rules' built-in
  path gating means walking more files won't reproduce v0.1.x
  output exactly.
- New dependency: github.com/sabhiram/go-gitignore (MIT, zero
  transitive deps).

### Added
- **Multi-axis trust score.** Every scan now emits four A–F grades:
  Security, Permission hygiene, Transparency, Quality. Rendered as
  a "Trust Score" block above the existing findings list.
- **7 new detection rules** covering the `.claude/` configuration
  surface previously not scanned:
  - `SD-015` — `claude_md.sql_injection_by_instruction` (LayerX disclosure, Mar 2026)
  - `SD-016` — `claude_md.comment_and_control` (2026 prompt-injection family)
  - `SD-017` — `settings_json.bash_curl_wildcard` (broad-shell permission grants)
  - `SD-018` — `settings_json.subcommand_limit_bypass` (Apr 2026 CVE shape)
  - `SD-019` — `settings_json.unsanctioned_hook` (out-of-repo hook commands)
  - `SD-020` — `hooks.shell_metacharacter_interpolation` (CVE-2025-59536 family)
  - `SD-021` — `mcp.external_domain_reach` (Trend Micro 2026)
- **New library packages**:
  - `pkg/axes` — `Axis` and `Grade` enums (wire-stable).
  - `pkg/grade` — pure aggregator `Grade(axis, findings) → AxisResult`
    using worst-finding-wins with per-axis caps.
- **CLI flags**:
  - `--fail-on-axis <axis>=<grade>` — repeatable. Exits 2 if axis
    grade is worse than threshold. Combines with `--fail-on`
    (worst wins).
  - `--strict-mcp` — raises `SD-021` from Medium to High.
  - `--axes-only` — emits Trust Score to stdout, findings to
    stderr. For shell pipelines and the PR-comment renderer in SP-4.
- **CVE reproducer fixtures** under `testdata/cve/` — minimal repos
  reproducing five named 2026 incidents. Used by
  `cmd/skill-detector/cve_repro_test.go` for both Go-API and
  binary-E2E smoke tests.
- **Scanner walks `.claude/`, `.codex/`, `.opencode/`** despite the
  general hidden-directory skip. Other hidden dirs (`.git`,
  `.next`, `node_modules`, etc.) continue to be skipped.

### Changed
- **`Rule` interface gains `Axis() axes.Axis` method**. All existing
  rule implementations now declare an axis. New invariant:
  `baseRule.newFinding` stamps `Finding.Axis = b.axis` so rule code
  cannot forget.
- **`model.Finding` gains `Axis` field** (`json:"axis,omitempty"`).
  Existing consumers continue to parse unchanged.
- **`model.ScanResult` gains `Axes map[axes.Axis]AxisResult`** field
  (`json:"axes,omitempty"`). Existing fields preserved.
- **Existing 6 rule groups** now declare axis assignments
  (`injection/supply_chain/exfiltration/integrity → security`;
  `misconfiguration/access_control → permission_hygiene`). No
  behavior change — only adds axis tag to every emitted Finding.
- **`registry.Checksum()` extended** to include per-rule axis and
  the canonical form of the grade package's cap table + rationale
  templates. Any tampering with rule registration, axis assignment,
  cap-table thresholds, or template strings now invalidates the
  pinned `expectedChecksum` ldflag.
- **Text reporter** prepends a Trust Score block above the existing
  findings list.
- **JSON reporter** emits the new `axes` map and per-finding `axis`
  field (additive).

### Compatibility
- Existing JSON consumers parsing the old shape continue to work —
  new fields are additive and use `omitempty`.
- Existing CLI users running `skill-detector .` see the same
  findings list plus a new Trust Score block above. No flag flip
  required.
- Homebrew tap distribution unchanged. GoReleaser flow unchanged.
- `expectedChecksum` ldflag value differs from v0.1 — release
  artifacts ship with the new value.

### Notes for downstream consumers
- `skillmoss-go` and `skilltrust/scan-action@v1` consumers should
  bump the `skill-detector` dependency to `v0.2.x`.
- Old rule IDs `SD-001..SD-014` are unchanged. New rule IDs are
  `SD-015..SD-021` (skipped `SD-007..SD-013` to avoid collision
  with the original plan numbers).

### Dogfood pass
An SP-1 release-candidate dogfood pass was run and logged internally.
Verdict: ship-as-is; pre-existing-rule FPs noted as SP-2 follow-up.

---
