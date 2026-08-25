# Changelog

## Unreleased

### Changed
- **SD-007 tells a declared endpoint from a call.** In a documentation or
  data file a URL is a disclosure — a Notion skill's manifest naming
  `https://api.notion.com/v1/pages` is saying what it talks to, not doing
  something wrong — and it now grades **Medium on `transparency`** instead of
  **High on `security`**. It stays High/security when the statement sends
  local state (`curl -d "$(env)"`), when the host is one a published API would
  not use (bare IP, non-standard port, ephemeral tunnel or request-bin), when
  the target is not visible, and always inside executable code. The URL is now
  read from the whole shell statement, so a target on a backslash continuation
  is seen. Registered severity stays High/security — that is the ceiling and
  what `registry.Checksum()` hashes, so the checksum is unmoved.
- **SD-007 no longer matches the English verb "fetch".** `\bfetch\s+` fired on
  "a script to fetch live data" and "not visible to fetch". The JS `fetch(...)`
  call and shell `fetch https://...` still fire.

  Measured on a 600-sample MalSkillBench slice (300 malicious / 300 benign),
  `--fail-on-axis security=B`, skills scanned as installed:

  | | precision | recall | FP-rate | benign flagged |
  |---|---|---|---|---|
  | before | 0.644 | 0.707 | 0.390 | 117 / 300 |
  | after | 0.678 | 0.647 | 0.307 | 92 / 300 |

  (Superseded by the combined figures below once the review fixes landed.)

  Recall on code-level behaviours (B1–B9) moves 0.97 → 0.94. Of the 11
  malicious samples that stop being flagged, all 11 were held up by SD-007
  alone and 9 of those by the prose verb; the two real ones are
  privilege-escalation *instructions* in a manifest, which SD-002 should catch
  deliberately rather than SD-007 catching by accident.
- **A truncated statement no longer hides the line after it.** `shellStatement`
  stops joining at 8 lines; it reported having consumed one line more than it
  wrote, so the caller skipped a line nothing had scanned. Eight
  backslash-continued lines were enough to hide a `curl` from SD-007 entirely.
  A detection bypass introduced by the de-duplication fix below, found in
  review before either shipped.
- **`curl -T` / `--upload-file` count as sending local state**, anchored to a
  curl invocation. They take a bare filename, so they could never match a
  pattern ending in `\S*@\S`, and they are the flags that most directly upload
  a local file — but `reNetworkCommand` covers wget too, and GNU wget's `-T` is
  `--timeout`, so an unqualified check read `wget -T 30 https://…` as an upload.
- **A short option's value may be attached.** curl parses `-d@FILE` exactly as
  `-d @FILE` (verified against curl 8.7.1: both fail with "error encountered
  when reading a file", where a literal body reaches the connection attempt).
  Requiring a separator made the whole check a one-character evasion.
- **The body-flag list is complete**: `--data-ascii` was missing, and wget's
  `--post-file=` — its equivalent of `curl -T` — is now covered too.
- **An `@` inside a literal request body is no longer read as a file upload.**
  `-d '{"email":"user@example.com"}'` matched the upload idiom and kept the
  finding at High. The `@` now has to open the argument or a `field=` value.
- **A statement's continuation lines are no longer re-judged as statements.**
  SD-007 read the URL from the backslash-joined statement but did not skip the
  lines it consumed, so a wrapped command produced one finding per line —
  three for a single call. Found in review of this PR; it removed 25 duplicate
  findings from the 600-sample slice (SD-007 benign 901 → 881, malicious
  1359 → 1354), which was small enough that the headline figures held.
- **`curl -d @file` counts as sending local state again.** `exfiltratesLocalData`
  returned early unless it saw `$(`, so the `@`-prefixed upload idiom —
  `-d @path`, `--data-binary @path`, `-F field=@path`, the form the repo's own
  canonical SD-007 fixture uses — was demoted to transparency in documentation.
  Found in review of this PR.
- **SD-008 no longer treats every long alphanumeric run as a payload.** `/` is
  in the base64 alphabet, so a deep path matched; so did a hex wallet address
  and any single-case identifier. Worst of all, npm lockfile `"integrity"`
  values matched — 322 findings on benign skills against **zero** on malicious
  ones. The inline branch now requires the token to look encoded (mixed case
  plus a digit or `+`/`/`, and not a path shape) and damps subresource-integrity
  and hex-literal lines. The decode-call branches (`base64 -d`, `atob`,
  `b64decode`) are untouched — that is where the signal was all along
  (22.6% of malicious hits vs 2.0% of benign).

  SD-008 findings across the same 600 samples: **benign 410 → 31**, malicious
  221 → 136. The exemption for path-shaped tokens is a case-stability test, not
  a slash test: `/` is in the base64 alphabet, and across 20000 encodings of 30
  random bytes **24.8%** contain a `/` with no `+` and no padding, so a slash
  test discarded a quarter of all genuine payloads. A path is several word-like
  segments — `claude/skills/CORE/USER/Art` flips case on 2% of its character
  boundaries where random base64 flips on 33%. The shipped test catches 74.5%
  of the corpus path tokens and discards **0 of 20000** genuine payloads. Found
  in review of this PR. Findings on benign skills overall 1724 → 1271; the worst single
  benign skill went from 244 findings to 109.


### Changed
- **An empty scan no longer grades A.** Discovery is deliberately wider than
  the rules' path gates, so "N files scanned" never meant the agent surface was
  read. When no discovered file is agent surface, the scan now sets
  `no_agent_surface`, emits **no** axes and **no** permissions, warns, and its
  text verdict reads `∅ Nothing checked — no agent configuration files in
  scope` instead of `✓ No concerns`. Previously such a scan reported four A
  grades and a clean verdict, and that A travelled into CI exit codes, badges
  and downstream databases. `--fail-on-axis` already treats a missing axis as
  "nothing to compare", so exit codes are unchanged for graded scans.
- **Schema `1.4` → `1.5`** — additive: `no_agent_surface` (bool, omitempty).
  Registry checksum unmoved (no rule metadata or cap-table change).

- **Text output hides the `quality` axis while nothing drives it.** The axis
  is a reserved slot with zero rules mapped, so the unconditional
  `Quality A` row read as "quality was checked and it's excellent" when
  nothing was checked. The row is skipped when the axis has no driving
  findings and reappears by itself the day a rule lands on the axis.
  **JSON is unchanged** — all four axes stay in the wire format (ADR-0001),
  and `--fail-on-axis quality=...` still works. Registry checksum unmoved.

### Fixed
- **`.agents/` is now in scope.** `isInAgentConfigDir` / `inAgentDir` /
  `walkableHiddenDirs` listed every harness dot-dir except `.agents/` — the
  path `npx skills add` installs into, and the convention third-party skill
  registries publish for. A skill installed the standard way was invisible:
  the same fixture graded **F** under `.claude/skills/` and **A** under
  `.agents/skills/` with "0 files scanned". Script extensions
  (`.ts`, `.py`, ...) inside the tree are scanned there like in any other
  agent config dir, which is what catches payloads bundled in `*.test.ts` /
  `conftest.py` that the developer's own test runner executes.

## v0.6.0 — 2026-08-14

Engine-review wave (F-02, F-03, F-05, F-06, F-08, F-09, F-10 of
`docs/engine-review-findings-2026-08-14.md`). Registry checksum unchanged
(`589619b6386d2c41`); JSON schema version unchanged (`1.4` — no shape change).

### Fixed
- **`delta` no longer reports churn on line shifts** (F-02). Inserting a line
  above a finding shifted its line number, which was part of the match key, so
  every finding below the edit came back as a `resolved` + `new` pair — enough
  to fail a `skilltrust` PR check on a whitespace-only change. Leftovers from
  the exact match are now paired one-for-one on the same key minus the line
  number, and only the residue is reported. `findingKey` and the finding
  payload are unchanged; ruleset checksum unmoved. ADR-0007.
- **`delta` output is deterministic.** `new_findings` / `resolved_findings` were
  built by ranging over maps, so their order — and which finding got quoted in
  `axis_explanations` — varied between runs on identical input. Both lists now
  follow scan order.
- **Triage verdicts are no longer mis-applied on key collisions** (F-03).
  Verdicts were matched back to findings by `{RuleID, Line}` alone; rules that
  emit several findings with the same key (SD-021: one per MCP server, all on
  line 1; SD-002: several signals per line) got last-write-wins, so a
  `benign_example` verdict for one finding could suppress a `real_threat`
  sibling from axis grading. `triage.Verdict` gains an optional 1-based
  `Index` naming the finding it applies to (additive API); a key claimed by
  two findings or two verdicts now falls to the `unavailable` fail-safe
  instead of being guessed. Shipped verifiers stamp `Index`.
- **Capability inference no longer goes stale silently** (F-08). Findings from
  SD-005, SD-006, SD-016, SD-017, SD-019, SD-020, SD-021, SD-022, SD-023 and
  SD-024 now contribute to the reported `permissions`; previously only nine
  rule IDs did, so a skill flagged solely by SD-022 (DNS exfiltration) reported
  no `network` capability at all. The hardcoded switch is now a table
  (`ruleCapabilities` / `capabilityFreeRules`) and a new test fails whenever a
  registered rule is in neither, so new rules cannot skip classification.

### Added
- Schema-version enforcement (F-10). `model.SchemaVersion` is now a named
  constant, `cmd/skill-detector/testdata/schema_output.golden` holds real
  `scan --format json` output, and `schema_shapes.json` pins each version to a
  fingerprint of the emitted shape — changing the output without bumping the
  version now fails the build. Bump procedure documented in
  `docs/development-guide.md`.
- README documents the warn-without-failing CI recipe for exit code `1`
  (F-05): a `|| [ $? -eq 1 ]` one-liner and an explicit `case` form emitting
  `::warning::`, plus a caution that `|| true` swallows exit `3`.

### Removed
- `rules.RegisterMCPRulesStrict` — dead since v0.2.0, when `--strict-mcp` moved
  to a post-hoc severity upgrade (`applyStrictMCP`) to keep the checksum stable.
  No caller existed in this repo or downstream. Exported-API removal, but only
  in name: calling it produced a registry the CLI never used (F-06).
- `cmd/skill-detector::newRegistry` — a hand-maintained duplicate of
  `rules.DefaultRegistry()`, plus the parity test that existed only to catch
  drift between the two. Rule groups are registered in one place again (F-06).

## v0.5.0 — 2026-08-05

### Added
- **`SD-024` — MCP Auto-Installed Package Execution** (MEDIUM, transparency
  axis — the first rule on that axis). Flags MCP server entries whose
  `command` is a package auto-fetcher (`npx`, `uvx`, `pipx`, `bunx`): the
  server pulls and runs a registry package at startup rather than a pinned,
  audited binary.
- **Multi-harness coverage.** The harness-agnostic content rules (SD-002,
  SD-003, SD-004, SD-015, SD-016, and friends) now also run over Codex
  CLI/OpenCode (`AGENTS.md`), Gemini CLI (`GEMINI.md`), Cursor
  (`.cursorrules`, `.cursor/rules/*.mdc`), Windsurf (`.windsurfrules`), and
  GitHub Copilot (`.github/copilot-instructions.md`) instruction files.
  `.cursor/mcp.json` and `.vscode/mcp.json` (including VS Code's `servers`
  key) are now classified as MCP configs. Discovery also follows in-tree
  symlinks (e.g. `CLAUDE.md -> AGENTS.md`), previously skipped as
  non-regular files.
- Agent-config-dir script discovery: extensionless and `.zsh` files inside
  `.claude/`, `.codex/`, `.opencode/`, etc. are now walked, closing a blind
  spot where hook scripts without a recognized extension were invisible to
  every content rule.
- **Gitignore-blindness warning.** When `.gitignore` causes an agent config
  path (`.claude/settings.json`, `SKILL.md`, etc.) to be skipped, the scan
  now emits a warning in `ScanResult.Warnings` naming the count and
  suggesting `--scan-all`. Schema version bumped to **1.4**
  (`ScanResult.SchemaVersion`) for the new field.
- `--fail-on-axis` now rejects a misspelled/unknown axis name instead of
  silently treating it as a no-op.

### Changed
- **Nested hooks schema.** SD-019/SD-020 now parse the real Claude Code
  hooks shape (`{"hooks":{"PreToolUse":[{"matcher":"...","hooks":[{"command":"..."}]}]}}`)
  in addition to the old flat shape; hook commands nested under a matcher
  were previously invisible to both rules.
- **Permission-string syntax coverage.** `Bash(curl:*)` (colon-prefix
  wildcard) and `Bash(curl*)` (no-space wildcard, strictly broader than
  `Bash(curl *)`) are now recognized, as is the PowerShell tool shape
  alongside Bash. SD-017/SD-018/SD-023 all share the widened parser.
- **SD-018 reworded and renamed** to "settings.json Redundant Deny Rule"
  (was "Subcommand Limit Bypass"). Deny still wins over allow in Claude
  Code, so a narrower `deny` next to a broader `allow` was never an actual
  bypass — it's a redundant deny that signals the allow is overbroad. The
  rule name, finding message, and remediation now say that instead of
  "bypass".
- **SD-004/SD-013 damping veto narrowed.** The shell-invocation veto used to
  cancel the documentary damping on a bare backtick or bare `>` anywhere on
  the line, which reintroduced the FP class for any Markdown-formatted
  threat-model doc (code-span-wrapped paths, `->` arrows in table rows). A
  backtick now only vetoes via the text it wraps (an imperative command
  span still fires; a path span doesn't), and a single `>` only vetoes when
  it's redirect-shaped (`>` followed by `~`, `./`, `/`, or `$`, not
  preceded by `-`) — `>>` still vetoes unconditionally.
- **SD-023 downgraded High → Medium; SD-018 rename above.** Registry
  checksum moved to `589619b6386d2c41` (severity and name are both part of
  the hashed rule metadata, ADR-0003).
- **SD-002 (prompt injection)** now also scans `.claude/commands/`,
  `.claude/agents/`, and skill content files, not just `SKILL.md`/`CLAUDE.md`.
- **SD-001** now scans fenced code blocks inside Markdown
  (`shellFencedLines()` gates the per-line scan to fence contents so prose
  outside a fence doesn't fire) and registers for `.zsh` and extensionless
  scripts, matching the agent-dir script discovery above. Fence scanning is
  restricted to fences tagged `bash`/`sh`/`zsh`/`shell`/`console`/`terminal`
  or untagged — fences tagged with a non-shell language (```` ```js ````,
  ```` ```jsx ````, ```` ```python ````, etc.) are skipped, so a JS/TS
  template literal like `` `Status: ${x}` `` in a code sample no longer
  reads as shell backtick command substitution.
- **Invisible-Unicode coverage** widened to detect the Unicode Tags block
  and bidi-override characters, and now emits one finding per affected line
  instead of one per invisible character (a line with multiple invisible
  characters used to produce a finding per character; it now collapses to
  one finding per line).
- **False-positive damping.** SD-004/SD-013 no longer flag prohibition
  guidance ("never touch `~/.ssh`") or documentary context (Markdown table
  rows, interrogative bullets) as Critical, with a shell-invocation guard so
  an imperative command smuggled into that same shape (piped through a
  table cell) still fires. SD-020 exempts harness-provided `$CLAUDE_*`
  hook variables (e.g. `$CLAUDE_PROJECT_DIR`) from the unquoted-variable
  check — they aren't attacker-controlled.
- Config cascading lookup now also accepts `.skill-detector.yml` (in
  addition to `.skill-detectorrc`, checked first), matching what the
  README has documented.

### Fixed
- Gitignore matching now matches a gitignored directory node by both
  `dirname` and `dirname/` forms — a trailing-slash mismatch previously let
  some gitignored directories slip through.

### Breaking
- **New exit code `3`** for tool errors (bad arguments, unreadable path,
  internal failure), distinct from `1` (findings below threshold) and `2`
  (at/above threshold). Previously tool errors exited `1`, indistinguishable
  from "findings, none above threshold" — a CI gate treating `1` as
  "findings exist" could not tell a scan failure from a clean-ish scan.
- **`--fail-on-axis` with an unknown/misspelled axis now errors** instead of
  silently doing nothing. CI configs with a typo'd axis name (e.g.
  `securty=B`) previously passed every scan unconditionally; they now fail
  fast with an "unknown axis" error.

### Known issues
- **SD-003** (path traversal) fires on ordinary in-package relative paths —
  roughly 60% of findings in the validation corpus are this false-positive
  class. A proper fix needs to distinguish traversal-shaped paths
  (`../../etc`) from same-package relative references and is deferred to
  its own design pass rather than bundled into this release.

---

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
