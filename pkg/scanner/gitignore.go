package scanner

import (
	"os"
	"path/filepath"

	ignore "github.com/sabhiram/go-gitignore"
)

// loadGitignore reads <root>/.gitignore if present and returns a matcher.
// Returns (nil, nil) when no .gitignore exists — caller treats as no-op.
// Returns (nil, err) only on read errors that aren't "not exists".
func loadGitignore(root string) (*ignore.GitIgnore, error) {
	path := filepath.Join(root, ".gitignore")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return ignore.CompileIgnoreFile(path)
}
