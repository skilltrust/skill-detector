# Documentation map

Entry point for humans and agents working on `skill-detector`. Each kind of
project knowledge has exactly one home; nothing here is documented twice.

| Location | What lives here |
|----------|-----------------|
| [`README.md`](README.md) | This map. |
| [`product-context.md`](product-context.md) | What the tool is for and who uses it. Start here if you are new. |
| [`architecture.md`](architecture.md) | **Single source of truth** for the package layout, the pipeline, and the contracts between packages. |
| [`glossary.md`](glossary.md) | Domain terms and invariants: skill root, axis, grade, path gate, schema version. |
| [`cross-repo.md`](cross-repo.md) | The published API surface, its consumers, and what a release has to move downstream. |
| [`development-guide.md`](development-guide.md) | Build, test, lint and release instructions for contributors. |
| [`../README.md`](../README.md) | User-facing: what the tool does, installation, flags, scope. |
| [`../CHANGELOG.md`](../CHANGELOG.md) | Released behaviour, per version. Authoritative. |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | How to propose a change. |
| [`../AGENTS.md`](../AGENTS.md) | The coding contract: scope rules, how to add a rule, testdata conventions, what is settled. `CLAUDE.md` is a symlink to it. |

`AGENTS.md` also states **when** each artifact above should be written.

## What is not here

This project's internal engineering records are kept privately by the
maintainer and are not part of this repository. The doc set above is what this
repository carries, and it is complete as it stands. If something you need to
know is missing or looks wrong, open an issue rather than treating a gap as a
file that failed to land; a question in an issue is the supported route and
gets an answer.

## Conventions

- Everything here is written in English.
- `docs/` is allow-listed in `.gitignore`. A new file in this directory
  publishes nothing until it is named in that list, and it is named there only
  after it has been read for anything that should not be public. Adding a doc
  means adding a row above and a line to `.gitignore`, in the same change.
