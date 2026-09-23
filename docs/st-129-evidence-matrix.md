# ST-129 evidence matrix and analysis context

This is the traceability contract for CFG-01 through CFG-08. It records what
the cited source establishes; it does not claim the detector implements the
semantic check. Sibling issues replace **future** with a named passing test and
its actual result when they implement a row. One row has one semantic owner.

## Evidence rules

- **Release anchor** means behavior is evidenced at that release only. It does
  not establish the first affected version or every later version.
- **Prerelease anchor** remains separate from stable behavior.
- **Current docs** are mutable and were observed on 2026-09-23. They establish
  current documented behavior, not an introduction version.
- **Unknown** is evidence state, not an empty value. The internal states are
  `known`, `candidate`, `absent`, `empty`, `malformed`, `unsupported`,
  `unavailable`, and the zero-value `unknown`.
- A repository path can identify a candidate harness or declaration source.
  It cannot establish installed version, effective managed policy, user trust,
  session topology, runtime activation, network confinement, or host inventory.
- All fixtures are inert text. No command, helper, hook, package, server, URL,
  host home, or outside-scope reference is executed or opened.
- For every row, the source key identifies harness/provider and version anchor.
  Unless the row says otherwise, settings source is a repository candidate and
  trust/session/activation are unknown. Each controls cell names both a risky
  fixture and a benign or inactive twin; unavailable-only rows name an absence
  control instead.

## Shared source catalogue

| Key | Primary source | Kind / observed |
|---|---|---|
| C268 | [Claude Code v2.1.268](https://github.com/anthropics/claude-code/releases/tag/v2.1.268) | release, 2026-09-10 |
| C271 | [Claude Code v2.1.271](https://github.com/anthropics/claude-code/releases/tag/v2.1.271) | release, 2026-09-14 |
| C273 | [Claude Code v2.1.273](https://github.com/anthropics/claude-code/releases/tag/v2.1.273) | release, 2026-09-15 |
| C274 | [Claude Code v2.1.274](https://github.com/anthropics/claude-code/releases/tag/v2.1.274) | release, 2026-09-17 |
| C275 | [Claude Code v2.1.275](https://github.com/anthropics/claude-code/releases/tag/v2.1.275) | release, 2026-09-17 |
| C277 | [Claude Code v2.1.277](https://github.com/anthropics/claude-code/releases/tag/v2.1.277) | release, 2026-09-18 |
| P083 | [Copilot CLI v1.0.83](https://github.com/github/copilot-cli/releases/tag/v1.0.83) | release, 2026-09-04 |
| P085 | [Copilot CLI v1.0.85](https://github.com/github/copilot-cli/releases/tag/v1.0.85) | release, 2026-09-16 |
| P086 | [Copilot CLI v1.0.86](https://github.com/github/copilot-cli/releases/tag/v1.0.86) | release, 2026-09-17 |
| P087p | [Copilot CLI v1.0.87-0](https://github.com/github/copilot-cli/releases/tag/v1.0.87-0) | **prerelease**, 2026-09-18 |
| DSET | [Claude settings reference](https://code.claude.com/docs/en/settings-reference) | current docs, observed 2026-09-23 |
| DHOOK | [Claude hooks reference](https://code.claude.com/docs/en/hooks) | current docs, observed 2026-09-23 |
| DMCP | [Claude managed MCP reference](https://code.claude.com/docs/en/managed-mcp) | current docs, observed 2026-09-23 |
| DGATE | [Claude apps gateway configuration](https://code.claude.com/docs/en/claude-apps-gateway-config) | current docs, observed 2026-09-23 |

## CFG-01 — inline shell and per-command network grants

Owner: **ST-136**.

| Row | Evidence and context | Supported input; inert controls | Expected diagnostic; engine/test result |
|---|---|---|---|
| 01.1 Inline `!` commands | C271: at v2.1.271 auto-mode skill/slash inline commands use default-mode permissions; undecided commands become reviewed tool calls. Claude provider; skill/command candidate source; trust/session unknown. Older range unknown. | Parsed inline executable syntax. Risky: undecided `!` command in `testdata/malicious/claude-permission-context`; benign: literal prose in the paired clean fixture. | Conditional review warning; never execute. `TestInlineShellDistinguishesExecutableSyntax` passed: inline/fenced executable forms differ from prose, escaped and assignment forms. |
| 01.2 Per-command domains | C271: `allowed_domains` for Bash, PowerShell and Monitor in auto mode with sandboxing, scoped to one command. Project declaration is candidate only; enforcement/session unknown. | Risky: broader/different destination in the malicious fixture. Benign: narrow destination in the paired clean fixture; absence control: unavailable context. | Declaration inventory without confinement claim. `TestAllowedDomainsArePerCommandDeclarations` passed for narrow, wildcard-broad, different and missing-command contexts across all three tools. |
| 01.3 Parser safety | C271 establishes syntax behavior, not detector execution. Harness/version may be known or unknown; host state unavailable. | Risky: executable command/helper marker. Benign: same bytes in prose or an inactive field. | Parse only; no process/network call. `TestInlineAndDomainAnalysisIsInert` and `TestClaudeDiagnosticsSurviveEmptyRegistry` passed; marker commands were not executed and warnings survived scoring with no rules. |

## CFG-02 — Copilot approval and sandbox switches

Owner: **ST-139**.

| Row | Evidence and context | Supported input; inert controls | Expected diagnostic; engine/test result |
|---|---|---|---|
| 02.1 `COPILOT_ALLOW_ALL` | P085: falsey values disable automatic approval and arbitrary values no longer abort startup. Exact accepted spellings still require authoritative schema/source inspection; release prose alone is insufficient. Environment declaration source; session unknown. | Risky: each source-backed enabling spelling. Benign: absent and each source-backed falsey spelling. | No generic-language truthiness. **Future ST-139:** `TestCopilotAllowAllExactValues`; blocked on schema evidence and ST-130 parser. |
| 02.2 Sandbox bypass | P085 documents managed `sandbox.allowBypass`, approved session disable, and unmanaged pre-auth `--yolo`; P087p only confirms unmanaged `--yolo` survives startup checks. Managed source/trust must be supplied; stable behavior beyond P085 otherwise unknown. | Risky: managed bypass allowed plus disable. Benign: managed deny; unknown control: unmanaged `--yolo`. | Do not call unmanaged startup a managed bypass. **Future ST-139:** `TestCopilotSandboxBypassSourceConditions`; not implemented/run. |
| 02.3 Developer-tool grants | P083: sandbox file and shell tools inherit developer-tool paths, including token-bearing config; `sandbox.allowDevToolAccess=false` disables grants. Credential access still requires ST-126 evidence. | Risky: grant plus evidenced credential read. Benign: false/absent or grant without access. | Grant is capability context, not proof of secret read. **Future ST-139:** `TestCopilotDeveloperToolGrantNeedsAccessEvidence`; not implemented/run. |

## CFG-03 — session, plugin and worktree path resolution

Owner: **ST-139**; ST-130 owns format discovery/parsing.

| Row | Evidence and context | Supported input; inert controls | Expected diagnostic; engine/test result |
|---|---|---|---|
| 03.1 Additional MCP config | P085: relative `--additional-mcp-config @file` resolves from session cwd under resume/worktree and `~/` expands. Launch cwd is not the base; home content remains unavailable. | Risky: outside-scope or launch-cwd decoy. Benign: in-scope file under asymmetric session cwd; absence: `~/`. | Resolve only against supplied virtual paths; never host home. **Future ST-139:** `TestAdditionalMCPConfigUsesSessionCWD`; not implemented/run. |
| 03.2 Plugin MCP root | P085: plugin agents expand `${PLUGIN_ROOT}` in `mcp-servers` frontmatter. Plugin origin must be supplied; caller cwd is not provenance. | Risky: caller-cwd decoy or unresolved placeholder. Benign: supplied plugin root. | Preserve unresolved state; no host expansion. **Future ST-139:** `TestPluginMCPRootUsesPluginOrigin`; not implemented/run. |
| 03.3 Worktree templates | P087p prerelease: `{repoPath}`, `{repo}`, `{branch}`, `{branchSlug}` are supported. No stable anchor or traversal guarantee found. | Risky: traversal-looking substitution. Benign: every documented placeholder with inert values and literal path. | Inventory visible assumptions; label prerelease/unknown stable range. **Future ST-139:** `TestWorktreeTemplatePrereleasePlaceholders`; not implemented/run. |
| 03.4 Scope boundary | `pkg/scanner/discover.go`; P085/P087p do not authorize external reads. Referenced file availability depends on submitted scope. | Risky: escaping symlink/external reference. Benign: in-scope file; absence: missing external file. | Unavailable, not clean or host-resolved. **Future ST-139:** `TestCopilotReferencesCannotEscapeSubmission`; not implemented/run. |

## CFG-04 — instruction precedence and session topology

Owner: **ST-138**.

| Row | Evidence and context | Supported input; inert controls | Expected diagnostic; engine/test result |
|---|---|---|---|
| 04.1 `CLAUDE.md` / `AGENTS.md` fallback | C277: with no `CLAUDE.md`, Claude reads `AGENTS.md`; project selection is configurable; unavailable on Bedrock, Vertex and Foundry at that release. Provider/version are required for a definite applicability statement. | Risky: both files or unknown provider/version. Benign: one file under known supported/excluded provider; test both directions. | Never claim both load simultaneously. **Future ST-138:** `TestClaudeAgentsFallbackVersionProvider`; not implemented/run. |
| 04.2 `omitClaudeMd` | C271: agent frontmatter/`--agents` can omit user/project/local CLAUDE.md while managed policy still loads. Declaration source/session activation unknown. | Risky: true with project instructions assumed active. Benign: false/absent; control: managed instructions. | Explain omitted tiers without claiming managed policy is present. **Future ST-138:** `TestOmitClaudeMdKeepsManagedTier`; not implemented/run. |
| 04.3 Multi-repository cloud | Primary introduction source unresolved. Current settings documentation observed 2026-09-23 describes source scopes, but does not date the claimed multi-repository restriction. Cloud/session topology must be supplied. | Risky: multi-repo per-repo permissions/hooks/env. Benign: single-repo or plugin/marketplace declaration. | Until primary behavior is verified, explicit unknown—not effective-policy verdict. **Future ST-138:** `TestCloudRepositorySettingsNeedTopologyEvidence`; blocked on primary evidence. |
| 04.4 Worktree/account skills | C277: untracked project skills now load in worktrees. C275: account skills/plugins sync to signed-in terminal sessions. A committed-tree scan cannot enumerate either unless supplied. | Risky: untracked/account-only unavailable skill. Benign: supplied committed skill. | Scope warning; no claim of complete session inventory. **Future ST-138:** `TestExternalSkillSurfacesRemainUnavailable`; not implemented/run. |

## CFG-05 — marketplace schemas and installed-plugin provenance

Owner: **ST-138**.

| Row | Evidence and context | Supported input; inert controls | Expected diagnostic; engine/test result |
|---|---|---|---|
| 05.1 Marketplace policies | C277 fixes one malformed `strictKnownMarketplaces`/`blockedMarketplaces` entry disabling the whole policy. DSET says these are managed controls; current docs are not an introduction range. Effective managed provenance must be supplied. | Risky: malformed or permissive valid entry. Benign: restrictive valid/empty entry; absence control. | Keep absent/empty/malformed/valid distinct; schema validity does not prove enforcement. **Future ST-138:** `TestMarketplacePolicyStatesAndSource`; not implemented/run. |
| 05.2 Installed commit evidence | C277 fixes official plugins missing commits and stale pinned commits in `installed_plugins.json`. Host inventory absent from submission is unavailable. | Risky: missing/stale commit. Benign: supplied name+commit; absence control: no inventory. | Do not infer installed state from plugin name. **Future ST-138:** `TestInstalledPluginCommitEvidence`; not implemented/run. |
| 05.3 npm scripts vs runtime risk | C275: npm plugin fetch uses `npm pack --ignore-scripts` plus integrity verification. This suppresses install scripts, not runtime plugin code. | Risky: npm source with lifecycle script/runtime declaration. Benign: package without scripts. | Explain bounded protection without declaring package safe. **Future ST-138:** `TestNPMPluginInstallScriptsAreNotRuntimeSafety`; not implemented/run. |
| 05.4 SDK MCP compatibility | C274: `type=sdk` MCP entries are skipped with a warning; only SDK hosts register in-process servers. Host/session context unknown. | Risky compatibility case: SDK entry assumed executable. Benign semantic controls: command and HTTP transports. | Compatibility diagnostic, never executing-server finding. **Future ST-138:** `TestSDKMCPIsCompatibilityOnly`; not implemented/run. |

## CFG-06 — lifecycle and stale/foreign runtime state

Owners are identified per row because the original lifecycle checklist grouped
Copilot and Claude behavior in one bullet.

| Row | Evidence and context | Supported input; inert controls | Expected diagnostic; engine/test result |
|---|---|---|---|
| 06.1 Copilot plugin state (ST-139) | P086: config read/validation failures no longer discard active plugins; missing file and intentional removal are unchanged. Prior runtime state is unavailable to static scan. | Risky: invalid config with assumed stop. Benign: intentional removal; absence control: missing file/unknown prior state. | Invalid config means activity unknown, not stopped. **Future:** `TestCopilotInvalidConfigPreservesUnknownPluginActivity`; not implemented/run. |
| 06.2 Scheduled tasks (ST-138) | C273 fixes copied `.claude/scheduled_tasks.json` tasks running in the wrong session. Copied declarations do not establish current session binding. | Risky: copied task with unknown session. Benign: supplied matching binding or inert nonmatching reference. | Inventory only; no execution claim. **Future:** `TestScheduledTasksNeedSessionBinding`; not implemented/run. |
| 06.3 Teammate agent provenance (ST-138) | C268 fixes respawned teammate loading same-name agent files from untrusted folders. Trust/source context must be supplied; older range unknown. | Risky: same name with untrusted/unknown source. Benign: different name or trusted source. | Conditional provenance diagnostic, no simulated agent. **Future:** `TestRespawnedAgentNeedsSourceTrust`; not implemented/run. |
| 06.4a Copilot `/clear` lifecycle (ST-139) | P085: `/clear` runs `sessionEnd`. Session/event context may be unknown. | Risky: matching sessionEnd after `/clear`. Benign: nonmatching event; unknown context control. | Preserve event-specific activation. **Future:** `TestClearRunsSessionEnd`; not implemented/run. |
| 06.4b Claude `SubagentStop` lifecycle (ST-137) | C275: a specific matcher no longer fires for a stopping subagent with empty agent type. | Risky: matching nonempty type. Benign: nonmatching/empty type; unknown control. | Preserve matcher-specific activation. **Future:** `TestSubagentStopEmptyTypeDoesNotMatch`; not implemented/run. |
| 06.5 Historical ranges (ST-135) | Release anchors above verify fixed/reported behavior only. No primary source establishes complete affected historical ranges. | Risky metadata: inferred affected range. Benign metadata: dated anchor with unknown bounds; no runtime fixture. | Keep older behavior unknown; never backfill a range from fix version. Verified by matrix review; no engine test applicable. |

## CFG-07 — gateway egress assumptions and upstream headers

Owner: **ST-137**.

| Row | Evidence and context | Supported input; inert controls | Expected diagnostic; engine/test result |
|---|---|---|---|
| 07.1 Gateway declarations | C277 adds `CLAUDE_GATEWAY_PROXY_IS_EGRESS_BOUNDARY=1` and static upstream `headers`; DGATE documents current gateway shape. Wrapper/config source is candidate only. | Risky: explicit boundary claim treated as proof. Benign: absent claim and static placeholder headers. | Inventory claim and headers without proving topology. **Future ST-137:** `TestGatewayBoundaryDeclarationNeedsTopology`; not implemented/run. |
| 07.2 Sole-egress precondition | C277 states the flag is for gateways whose only egress is a forward proxy and changes hostname resolution behavior. DNS/routing remain unavailable to static scan. | Risky: claim with unknown topology. Benign: supplied sole-egress evidence; absence control. | State vendor precondition; never contact hosts or certify confinement. **Future ST-137:** `TestGatewayBoundaryDoesNotProveConfinement`; not implemented/run. |
| 07.3 Secret-safe output | DHOOK/DGATE describe header values; ST-128 owns shared hosted redaction, not detector output. | Risky: synthetic credential-bearing headers/URLs. Benign: static placeholders. | No secret value in finding, warning, text or provider context. **Future ST-137:** `TestGatewayDiagnosticsRedactCredentials`; not implemented/run. |

## CFG-08 — existing permission and hook checks

Owners are identified per row because the original precedence checklist grouped
permission and MCP behavior in one bullet.

| Row | Evidence and context | Supported input; inert controls | Expected diagnostic; engine/test result |
|---|---|---|---|
| 08.1a Permission precedence (ST-136) | DSET: deny applies in every mode, including bypass; managed-only rules prevent lower-tier allow/ask/deny and lower tiers cannot negate managed restrictions. C268/C273 anchor symlink and unanalyzable-shell changes, showing semantics vary by release. Exact Read/Edit/Write historical ranges remain unknown. | Risky: broad project allow/bypass, ineffective `Write(path)`, source-local negation in the malicious fixture. Benign: protective deny, narrow project allow and `Read(path)` in the paired clean fixture; known project/managed and unknown-source contexts cover symlink/path/shell limits. | Protective deny retained. `TestPermissionPrecedenceNeedsVersionSource` and `TestClaudeDiagnosticsSurviveScoringAndKeepProtectiveDeny` passed for known current/old project, known managed and unknown candidate contexts; scorer text never recommends deny removal. |
| 08.1b Managed MCP precedence (ST-138) | DMCP documents current allow/deny evaluation. C271 says unreadable managed MCP retains exclusive control and warns. Effective managed source remains caller evidence. | Risky: user server against managed deny or malformed managed policy. Benign: allowed managed server; unknown-provenance control. | Never convert unresolved effective policy into clean. **Future:** `TestManagedMCPFailureIsNotClean`; not implemented/run. |
| 08.2 Compound exclusions (ST-136) | C277 fixes one matching component exempting an entire compound command; every component must match. This anchors fixed behavior at 2.1.277 only. | Unit model: risky when only one component matches; benign when every component matches. Paired scanner fixtures carry wildcard versus narrow exclusion declarations, not runtime commands. | `TestSandboxExcludedCommandsRequireEveryComponent` passed for the bounded matcher: one/all simple components differ and complex shell stays unresolved. Production diagnostics inventory narrow/broad declarations and explain the anchor; they do not claim to match a runtime command. |
| 08.3 Hook context (ST-137) | DHOOK documents command/HTTP handlers, event matchers, POST event data, URL allowlists and env/header exposure. Current docs do not establish historical ranges. | Risky: matching HTTP hook with sensitive exposure. Benign: command/nonmatching hook and harmless external URL/header placeholders. | Preserve generic SD-007; external is not inherently malicious; response text is data. **Future:** `TestHookTypeEventMatcherAndExposure`; not implemented/run. |

## Internal analysis-context contract

`model.AnalysisContext` is carried on `model.FileContext`. It contains harness,
version, provider, declaration origin, trust, session and named activation
conditions. `ContextValue` always carries a state; `known` and `candidate` may
carry a value and evidence location. The zero state is `unknown`.

| State | Meaning |
|---|---|
| `unknown` | No evidence establishes whether a value exists or what it is. |
| `known` | Explicit supplied evidence establishes the value within its stated scope. |
| `candidate` | Submitted file placement suggests a value but not effective activation. |
| `absent` | The supplied source was available and the value was not present. |
| `empty` | The value was present and explicitly empty. |
| `malformed` | The value was present but could not be parsed as its supported shape. |
| `unsupported` | The value was parsed, but its form or semantics are outside bounded analysis. |
| `unavailable` | Named evidence could not be inspected within the submitted scope. |

`Scanner.Scan` supplies no runtime metadata, so production runtime facts stay
unknown. During discovery the scanner may stamp candidate harness/origin from
the submitted path (`.codex/config.toml`, Claude settings, MCP config). It does
not parse repository claims into trust, version, provider or session facts.
There is deliberately no JSON field, CLI/API option, or hosted caller wiring.
The context is unreachable from `ScanResult`; schema version 1.5 is unchanged.

Rules receive this context without IO through their existing `FileContext`.
The internal scanner core can receive known context for discriminating tests;
it does not expose a public caller method. If a real caller and consumer emerge,
their provenance and rescan semantics must be designed before exposing one.

Configuration validation and limitation messages use
`rules.ConfigurationDiagnostics`, which the scanner invokes before enabled
rules. A malformed/unsupported analyzed input therefore returns an error even
with an empty registry, and warnings survive the finding scorer.

## Completed analysis-context contract evidence

| Test | Result represented |
|---|---|
| `TestContextStatesRemainDistinct` | All context states are distinct; zero remains unknown. |
| `TestScanRepositoryCannotSelfCertifyContext` | Repository values cannot establish version/provider/trust/session. |
| `TestRunPropagatesSuppliedContextWithoutPathOverride` | Known internal context reaches per-file rules unchanged. |
| `TestFileAnalysisContextCandidates` | Placement produces only bounded candidates. |
| `TestCodexValidationCannotReturnCleanResult` | Unsupported/malformed analyzed input yields no graded result. |
| `TestClaudeSettingsValidationFailsClosed` | Malformed Claude settings and unsupported analyzed field types return a sanitized error. |
| `TestMalformedClaudeSettingsCannotReturnGradedResult` | Claude validation failure yields no graded result with default or empty registries. |
| `TestCodexDiagnosticsSurviveDisabledRulesAndScoring` | Diagnostics remain with no semantic rules and after scoring. |
| `TestCodexDoesNotExecuteOrReadExternalConfiguration` | No helper/server executes and host config is not read. |

All completed tests above passed under `go test ./...` on 2026-09-23; lint passed
with `golangci-lint run`. The sibling rows remain future requirements until
their owners replace the future status with their actual result.
