# skill-detector — Development Guide

## Prerequisites

| Requirement    | Version   | Notes                          |
| -------------- | --------- | ------------------------------ |
| Go             | 1.26+     | Required for building          |
| golangci-lint  | v2.11.4+  | Required for linting (gosec)   |
| GoReleaser     | v2+       | Only needed for releases       |
| Make           | any       | Build automation               |

## Getting Started

```bash
# Clone the repository
git clone https://github.com/velzepooz/skill-detector.git
cd skill-detector

# Build the binary
make build
# Output: bin/skill-detector

# Run tests
make test

# Run linter
make lint
```

## Available Make Targets

| Target      | Command                                  | Description                                   |
| ----------- | ---------------------------------------- | --------------------------------------------- |
| `build`     | `go build -ldflags ... -o bin/skill-detector` | Build binary with version info           |
| `fmt`       | `go fmt ./...`                           | Format Go source with standard tab indentation |
| `test`      | `go test ./...`                          | Run all tests                                 |
| `lint`      | `golangci-lint run`                      | Run linter with gosec                         |
| `run`       | `go run ./cmd/skill-detector scan ...`   | Run against test fixture                      |
| `self-scan` | Build then scan `testdata/clean/simple-skill` | Smoke test the built binary              |
| `clean`     | `rm -rf bin/ dist/`                      | Remove build artifacts                        |

## Running the Tool

```bash
# Scan a skill package directory
./bin/skill-detector scan <path-to-skill-directory>

# Example: scan the malicious test fixture
./bin/skill-detector scan ./testdata/malicious/credential-theft

# Example: scan a clean skill
./bin/skill-detector scan ./testdata/clean/simple-skill
```

## Formatting

Go source is formatted with standard `gofmt` tab indentation.

```bash
make fmt
```

## Project Structure

```
cmd/skill-detector/    → CLI entry point (Cobra)
internal/config/       → Configuration loading
internal/model/        → Shared domain types
internal/scanner/      → File discovery & scan orchestration
internal/rules/        → Security rule implementations
internal/permission/   → Skill manifest permission extraction
internal/scorer/       → Risk score computation
internal/reporter/     → Output formatting (text/JSON/quiet)
testdata/              → Test fixtures (clean, malicious, edge-cases)
```

## Testing

```bash
# Run all tests
make test

# Run tests with verbose output
go test -v ./...

# Run tests for a specific package
go test -v ./internal/rules/...

# Run a specific test
go test -v -run TestScanner_CleanScan ./internal/scanner/
```

### Test Fixture Structure

- **`testdata/clean/`** — Skills that should pass with zero findings
- **`testdata/malicious/`** — Skills that should trigger specific security rules
  - `credential-theft/`, `shell-injection/`, `prompt-injection/`, `exfiltration/`, `supply-chain/`, `persistence/`
- **`testdata/edge-cases/`** — Boundary conditions
  - `empty-skill/`, `malformed-yaml/`, `hidden-dir/`, `binary-file/`

## Linting

The project uses golangci-lint v2 with the `standard` preset plus `gosec` for security checks:

```bash
make lint
```

Configuration is in `.golangci.yml`:
- Preset: `standard` (default linters)
- Additional: `gosec` (Go security linter)
- Exclusions: comments, standard error handling, common false positives
- gosec `G101` (hardcoded credentials) is excluded in test files

## Adding a New Security Rule

1. Create a new file in `internal/rules/` (e.g., `new_threat.go`)
2. Implement the Rule interface defined in `internal/rules/rule.go`
3. Register the rule in the registry (`internal/rules/registry.go`)
4. Add test fixtures in `testdata/malicious/` for the new threat type
5. Write tests in `internal/rules/new_threat_test.go`
6. Run `make test` and `make lint` to verify

## CI/CD

### CI Pipeline (`.github/workflows/ci.yml`)

Runs on every push to `main` and all pull requests:

1. **Lint** — `make lint` (golangci-lint with gosec)
2. **Test** — `make test` (all Go tests)
3. **Build** — `make build` (compile binary)
4. **Self-scan** — `make self-scan` (scan test fixtures with built binary)

### Release Pipeline (`.github/workflows/release.yml`)

Triggered by pushing a version tag (`v*`):

1. Runs GoReleaser to build cross-platform binaries
2. Creates a GitHub Release with artifacts
3. Updates the Homebrew tap (`velzepooz/homebrew-tap`)

## Releasing

Releases are cut via Git tags. Pushing a `v*` tag triggers the release
workflow (`.github/workflows/release.yml`), which runs GoReleaser to build
cross-platform binaries and update the Homebrew cask in the tap repo.

### One-time setup

Already in place — only re-do these if something breaks:

1. **Public tap repo:** `github.com/velzepooz/homebrew-tap` holds the
   `Casks/skill-detector.rb` file that Homebrew installs from.
2. **Personal Access Token:** fine-grained PAT scoped to
   `velzepooz/homebrew-tap`, permission `Contents: Read and write`. This is
   needed because the default `GITHUB_TOKEN` only has write access to the
   current repo, not to a separate tap repo.
3. **Repo secret:** `HOMEBREW_TAP_GITHUB_TOKEN` stored under Settings →
   Secrets and variables → Actions on `velzepooz/skill-detector`. Referenced
   in both `.goreleaser.yml` and `.github/workflows/release.yml`.

If a release fails at the Homebrew step with a `403` or "resource not
accessible by integration" error, rotate the PAT and update the secret.

### Cutting a release

Use the Makefile target:

```bash
make release VERSION=v0.2.0
```

Safety checks run before the tag is pushed:

- `VERSION` is provided and matches `vMAJOR.MINOR.PATCH[-prerelease]`
- Working tree is clean (no staged or unstaged changes)
- Currently on the `main` branch
- Local `HEAD` equals `origin/main` (in sync with the remote)
- Tag does not already exist

If any check fails, the target aborts before touching Git. On success it
creates an annotated tag and pushes it to `origin`. Watch the workflow at:

```
https://github.com/velzepooz/skill-detector/actions
```

### Versioning

The project follows [semver](https://semver.org):

- `v0.X.Y` — early-stage. Breaking changes allowed between minor versions.
- `v1.0.0` — first stable release. Breaking changes require a major bump.
- Prerelease suffixes (`v0.2.0-rc1`, `v0.2.0-beta.1`) are allowed and accepted
  by the `make release` validator.

Rough guidance for picking the bump:

| Change                          | Bump  |
| ------------------------------- | ----- |
| Bug fix, false-positive tweak   | patch |
| New rule, new CLI flag          | minor |
| Breaking rule output / exit code | major |

### Dry-running a release locally

Before tagging — especially after editing `.goreleaser.yml` — you can build
exactly what the pipeline would build without publishing anything:

```bash
goreleaser release --snapshot --clean --skip=publish
```

Inspect `dist/` to see the generated archives, checksums, and
`dist/homebrew/Casks/skill-detector.rb`. Requires `brew install goreleaser`.

### If a release fails

**Workflow fails before the GitHub Release is created** (build or lint errors):
fix the issue on `main`, then delete the bad tag locally and remotely and
re-cut:

```bash
git tag -d v0.2.0
git push --delete origin v0.2.0
# fix, commit, push, then:
make release VERSION=v0.2.0
```

**Workflow fails at the Homebrew step but the GitHub Release was created:**
binaries are already published — only the cask update failed. Fix the root
cause (usually the PAT or `.goreleaser.yml`), push the fix to `main`, then
re-run just the failed job from the Actions UI. Do not delete the GitHub
Release unless the binaries themselves are bad.

**Bad release already published and users installed it:** do *not*
force-overwrite an existing tag. Cut a new patch version with the fix. Tag
immutability keeps user installs reproducible — a user who installed
`v0.2.0` yesterday should get the same bits tomorrow.

## Configuration

The tool reads configuration from a YAML file. Configuration supports:
- Per-rule enable/disable toggles
- Allowlists for suppressing known-safe findings
- Default values are provided in `internal/config/defaults.go`
