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

### Creating a Release

```bash
git tag v1.0.0
git push origin v1.0.0
# GitHub Actions will build and publish automatically
```

## Configuration

The tool reads configuration from a YAML file. Configuration supports:
- Per-rule enable/disable toggles
- Allowlists for suppressing known-safe findings
- Default values are provided in `internal/config/defaults.go`
