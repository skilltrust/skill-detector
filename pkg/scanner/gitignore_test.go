package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadGitignore_Missing(t *testing.T) {
	dir := t.TempDir()
	matcher, err := loadGitignore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matcher != nil {
		t.Errorf("expected nil matcher for missing .gitignore, got non-nil")
	}
}

func TestLoadGitignore_Present(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"),
		[]byte("secret.md\nnode_modules/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	matcher, err := loadGitignore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matcher == nil {
		t.Fatal("expected non-nil matcher")
	}
	if !matcher.MatchesPath("secret.md") {
		t.Errorf("expected secret.md to match")
	}
	if !matcher.MatchesPath("node_modules/foo") {
		t.Errorf("expected node_modules/foo to match")
	}
	if matcher.MatchesPath("README.md") {
		t.Errorf("expected README.md NOT to match")
	}
}

func TestLoadGitignore_Negation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"),
		[]byte("*.md\n!CLAUDE.md\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	matcher, err := loadGitignore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matcher.MatchesPath("README.md") {
		t.Errorf("expected README.md to match (gitignored)")
	}
	if matcher.MatchesPath("CLAUDE.md") {
		t.Errorf("expected CLAUDE.md NOT to match (negated)")
	}
}
