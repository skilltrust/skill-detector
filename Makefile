.PHONY: build fmt test lint run clean self-scan release

build:
	go build -ldflags "-X main.version=dev" -o bin/skill-detector ./cmd/skill-detector

fmt:
	go fmt ./...

test:
	go test ./...

lint:
	golangci-lint run

run:
	go run ./cmd/skill-detector scan ./testdata/malicious/credential-theft

self-scan: build
	./bin/skill-detector scan ./testdata/clean/simple-skill

clean:
	rm -rf bin/ dist/

# Tag and push a release. Usage: make release VERSION=v0.1.0
# Pushes the tag to origin, which triggers .github/workflows/release.yml
# (GoReleaser builds binaries + updates the Homebrew tap).
release:
	@test -n "$(VERSION)" || { echo "Usage: make release VERSION=v0.1.0"; exit 1; }
	@echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$$' || { echo "VERSION must match vMAJOR.MINOR.PATCH (e.g. v0.1.0)"; exit 1; }
	@git diff --quiet || { echo "Dirty working tree — commit or stash first"; exit 1; }
	@git diff --cached --quiet || { echo "Staged changes present — commit or reset first"; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = "main" || { echo "Not on main branch"; exit 1; }
	@git fetch origin main --quiet
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/main)" || { echo "Local main diverges from origin/main"; exit 1; }
	@git rev-parse "$(VERSION)" >/dev/null 2>&1 && { echo "Tag $(VERSION) already exists"; exit 1; } || true
	@echo "Tagging $(VERSION) and pushing to origin..."
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)
	@echo "Done. Watch: https://github.com/velzepooz/skill-detector/actions"
