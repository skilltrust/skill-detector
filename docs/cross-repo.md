# Downstream consumers

`skill-detector` is one of three repositories. It is the only one that decides
what a scan concludes; the other two present its results to users. They consume
it in different ways, and the difference decides what a change here can break.

## The three repositories

| Repository | Role | Visibility |
|---|---|---|
| `skill-detector` | The detection engine. The file walk, the rules, the grading, and the CLI. | Public. |
| The hosted scanner, `skilltrust` | The web application at [skilltrust.app](https://skilltrust.app): the scan pages, the reports, the badge service and the GitHub App backend. Embeds this engine as a Go library. | Private. |
| `scan-action`, the GitHub Action | Wraps a scan so a repository can gate its pull requests on the result. Contains no Go: it downloads a released binary and reads its output. | Public. |

## `pkg/` is a published API

Everything under `pkg/` is imported as a library by the hosted scanner, which
compiles against this module. `cmd/` is the CLI entry point and is not imported
by anything.

The consequence is direct: **every exported change under `pkg/` is
downstream-visible.** A renamed field on `model.Finding`, a changed signature
on `scanner.Options`, a new required argument — each is a compile break in the
hosted scanner that this repository's own test suite will not notice. The types
that travel furthest are `model.ScanResult` and everything nested inside it,
`axes.Axis` and `axes.Grade`, the `rules.Rule` interface and
`rules.DefaultRegistry()`, and `delta.Compute`.

## The CLI surface is an API too

The Action does not compile against this module. It pins a version, downloads
the released binary for the runner's platform, invokes it and reads what comes
back — so its dependency is the CLI surface rather than the Go one, and it
breaks in ways a compiler cannot catch:

- **Flag names and semantics.** A renamed or removed flag, or one whose default
  changes, breaks the Action at runtime with no build failure anywhere.
- **Exit codes.** The Action turns the exit code into a pass or fail verdict,
  so the `0` / `1` / `2` / `3` contract is load-bearing outside this repository.
- **The JSON output shape.** It parses the result rather than embedding the
  types.

The JSON wire format reaches furthest of all, because anything reading a result
out of process depends on it — the Action, the `delta` sub-command comparing two
stored results, and any consumer that persists a scan. Its version lives in
`pkg/model.SchemaVersion` and is bumped in the same commit as any change to the
shape of `ScanResult` — see [`architecture.md`](architecture.md).

Two properties of `pkg/` exist because it is embedded elsewhere, and are not
incidental: the packages that do the reasoning are pure — no IO, no global
state — and `pkg/rules` never touches the filesystem, reading only the
`FileContext` it is handed. Introducing a global, or a disk read inside a rule,
breaks the embedding rather than just this repository.

Codex TOML support adds `rules.IsCodexConfig`, `CodexConfigDiagnostics` and
`RegisterCodexRules`; existing signatures and JSON fields are unchanged.
Consumers of `Scanner.Scan` must preserve its error path and display warnings:
unsupported analyzed configuration returns no result, while unresolved runtime
activation is reported through the existing `Warnings` field. Direct rule
consumers should call the shared `rules.ConfigurationDiagnostics` entry point;
`CodexConfigDiagnostics` remains available for compatibility. They have the
diagnostic obligation described in
[`architecture.md`](architecture.md). The hosted sparse selector already
includes the entire `.codex/` subtree, including nested and named profiles;
this feature needs no broader sparse scope.

ST-135 adds internal context types and `FileContext.Analysis`, plus the shared
diagnostics entry point. These are additive Go API changes. Existing keyed
`FileContext` literals and `Scanner.Scan` callers compile unchanged. There is no
new scanner option, method argument, CLI flag or JSON field; the hosted scanner
therefore has nothing to supply or persist, and runtime facts remain unknown.

ST-137 adds `rules.SanitizeConfigurationForVerifier`, used by the scanner
before invoking an optional verifier. Embedders that bypass `scanner.Scanner`
and send Claude hook/gateway configuration to another analyzer should apply
the same boundary; header values and URL credentials/query data must not cross
it. `ScanResult`, CLI JSON and schema version are unchanged.

## A release is not done when the tag is cut

Three places downstream pin this engine's version, and **none of them notices a
new tag**:

1. **`action.yml` in the GitHub Action** — the `detector-version` input. Moving
   it is necessary but not sufficient: the Action needs its own release before
   the change reaches anyone using it by tag.
2. **`go.mod` in the hosted scanner** — the version of this module it compiles
   against.
3. **The hosted scanner's fixture clones** — two pins in
   `.github/workflows/ci.yml` and one in `.github/workflows/nightly.yml`, checking
   out this repository at a fixed version to generate test fixtures. It is easy
   to move the first two consumers and forget these clones; the symptom is a
   green build testing an engine nobody is running.

Moving all three is part of the release, not follow-up work. Until they move,
the tag exists and no user is running it.

An agent working only inside this repository cannot do any of that — all three
pins live in repositories it cannot see. The correct ending for a release done
from here is a handoff that names the three pins, not a claim that the work
shipped.

## Merging to the hosted scanner's `main` deploys production

The hosted scanner deploys from its default branch. A merge to `main` there is
a production deployment, including a documentation-only merge. This matters
from here because a change in this repository frequently lands as a version
bump there, and that bump is a deploy.

## Coordination records

Records of how these repositories are coordinated — release history, downstream
state, and the reasoning behind the arrangement above — are kept privately by
the maintainer and are not part of this repository. If you need to know
something about a downstream consumer that this page does not answer, open an
issue.
