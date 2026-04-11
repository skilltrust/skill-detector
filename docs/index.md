# skill-detector — Documentation Index

## Project Overview

- **Type:** Monolith CLI Tool
- **Primary Language:** Go 1.26
- **Architecture:** Pipeline (scan → rules → score → report)
- **Framework:** Cobra (CLI)
- **Repository:** github.com/velzepooz/skill-detector

## Quick Reference

- **Tech Stack:** Go 1.26, Cobra, gopkg.in/yaml.v3
- **Entry Point:** `cmd/skill-detector/main.go`
- **Architecture Pattern:** Pipeline / Chain of Responsibility
- **Build:** `make build` → `bin/skill-detector`
- **Test:** `make test` (219 tests across 18 files)
- **Lint:** `make lint` (golangci-lint + gosec)
- **Release:** GoReleaser on tag push → GitHub Releases + Homebrew

## Generated Documentation

- [Project Overview](./project-overview.md)
- [Architecture](./architecture.md)
- [Source Tree Analysis](./source-tree-analysis.md)
- [Development Guide](./development-guide.md)

## Getting Started

```bash
# Build
make build

# Run against a skill package
./bin/skill-detector scan <path-to-skill-directory>

# Test
make test

# Lint
make lint
```
