package scanner

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	ignore "github.com/sabhiram/go-gitignore"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// walkableHiddenDirs lists hidden directories that should still be walked
// despite the general hidden-dir skip. These contain AI-agent configuration
// files (CLAUDE.md, settings.json, MCP configs) that are core to the
// skill-detector scope.
var walkableHiddenDirs = map[string]bool{
	".claude":   true,
	".codex":    true,
	".opencode": true,
}

// alwaysSkipDirs lists directory names always skipped during discovery
// regardless of .gitignore or --scan-all. These are dirs that are never
// the product's scope (build output, vendored deps, VCS metadata).
var alwaysSkipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".next":        true,
	".git":         true,
}

// scannableExts defines file extensions that are relevant for security scanning.
var scannableExts = map[string]bool{
	".md": true, ".yaml": true, ".yml": true,
	".sh": true, ".bash": true,
	".txt": true, ".json": true, ".toml": true,
	".env": true, ".cfg": true, ".conf": true,
	".ini": true, ".xml": true,
}

// DiscoverOptions controls walker behavior.
type DiscoverOptions struct {
	// ScanAll disables .gitignore filtering. Hardcoded skip-dirs
	// (node_modules, .git, etc.) still apply.
	ScanAll bool
}

// Discover walks the root directory and returns scannable files using
// default options (honor .gitignore, skip hardcoded noise dirs).
func Discover(root string) ([]model.FileContext, error) {
	return discoverImpl(root, DiscoverOptions{})
}

// DiscoverWithOptions is the option-aware sibling of Discover. Discover()
// remains for callers that want default behavior.
func DiscoverWithOptions(root string, opts DiscoverOptions) ([]model.FileContext, error) {
	return discoverImpl(root, opts)
}

func discoverImpl(root string, opts DiscoverOptions) ([]model.FileContext, error) {
	root = filepath.Clean(root)

	// Open a scoped root to prevent symlink TOCTOU traversal (gosec G122).
	osRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	defer osRoot.Close()

	var ignoreMatcher *ignore.GitIgnore
	if !opts.ScanAll {
		ignoreMatcher, err = loadGitignore(root)
		if err != nil {
			// Don't fail discovery on a broken .gitignore — treat as no-op.
			ignoreMatcher = nil
		}
	}

	var files []model.FileContext

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission denied or other walk error on a subdirectory — skip it.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hardcoded noise dirs (always, regardless of options).
		if d.IsDir() && path != root && alwaysSkipDirs[d.Name()] {
			return filepath.SkipDir
		}

		// Honor .gitignore (best-effort; missing/broken file = no-op).
		if ignoreMatcher != nil {
			relForIgnore, err := filepath.Rel(root, path)
			if err == nil && relForIgnore != "." {
				if ignoreMatcher.MatchesPath(filepath.ToSlash(relForIgnore)) {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
		}

		// Skip hidden directories (but not the root itself), except for an allowlist
		// of hidden dirs that contain security-relevant config.
		if d.IsDir() && path != root && d.Name()[0] == '.' {
			if !walkableHiddenDirs[d.Name()] {
				return filepath.SkipDir
			}
		}

		// Only process regular files.
		if !d.Type().IsRegular() {
			return nil
		}

		// Check extension against scannable set.
		ext := filepath.Ext(path)
		if !scannableExts[ext] {
			return nil
		}

		// Build relative path.
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}

		// Read file content via scoped root to prevent TOCTOU races.
		content, err := readFromRoot(osRoot, relPath)
		if err != nil {
			// Unreadable file — skip silently.
			return nil
		}

		// Skip binary files.
		if isBinary(content) {
			return nil
		}

		files = append(files, model.FileContext{
			Path:    relPath,
			Ext:     ext,
			Content: content,
		})

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}

	return files, nil
}

// readFromRoot reads file content through the scoped os.Root to avoid TOCTOU races.
func readFromRoot(root *os.Root, relPath string) ([]byte, error) {
	f, err := root.Open(relPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// isBinary checks whether the data appears to be binary by looking for NUL bytes
// in the first 512 bytes.
func isBinary(data []byte) bool {
	checkLen := 512
	if len(data) < checkLen {
		checkLen = len(data)
	}
	for _, b := range data[:checkLen] {
		if b == 0 {
			return true
		}
	}
	return false
}
