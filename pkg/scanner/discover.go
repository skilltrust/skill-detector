package scanner

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

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

// scannableExts defines file extensions that are relevant for security scanning.
var scannableExts = map[string]bool{
	".md": true, ".yaml": true, ".yml": true,
	".sh": true, ".bash": true,
	".txt": true, ".json": true, ".toml": true,
	".env": true, ".cfg": true, ".conf": true,
	".ini": true, ".xml": true,
}

// Discover walks the root directory and returns a slice of FileContext entries
// for all scannable, non-binary files. Hidden directories are skipped.
func Discover(root string) ([]model.FileContext, error) {
	root = filepath.Clean(root)

	// Open a scoped root to prevent symlink TOCTOU traversal (gosec G122).
	osRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	defer osRoot.Close()

	var files []model.FileContext

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission denied or other walk error on a subdirectory — skip it.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
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
