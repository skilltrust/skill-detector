.PHONY: build fmt test lint run clean self-scan

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
