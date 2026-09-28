package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/rules"
)

func writeBareFixture(t *testing.T, root, dir, config string) {
	t.Helper()
	base := filepath.Join(root, dir)
	if err := os.MkdirAll(filepath.Join(base, "objects", "ab"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"HEAD": "ref: refs/heads/main\n", "config": config,
		"objects/ab/1234": "inert object marker",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNestedBareGitConfigInventory(t *testing.T) {
	root := t.TempDir()
	writeBareFixture(t, root, "work/deep.git", "[core]\n bare = true\n fsmonitor = ./sentinel.sh\n")
	if err := os.WriteFile(filepath.Join(root, "work/deep.git/sentinel.sh"), []byte("#!/bin/sh\ntouch ../executed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := New(rules.DefaultRegistry(), Options{}).Scan(context.Background(), localDir(root))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].FilePath != "work/deep.git/config" || result.Findings[0].Line != 3 || !strings.Contains(result.Findings[0].Description, "not confirmed") {
		t.Fatalf("expected conditional fsmonitor finding at config:3, got %+v", result.Findings)
	}
	if _, err := os.Stat(filepath.Join(root, "work/executed")); !os.IsNotExist(err) {
		t.Fatalf("fixture executed: %v", err)
	}
}

func TestNestedBareGitDetachedHEAD(t *testing.T) {
	root := t.TempDir()
	writeBareFixture(t, root, "nested", "[core]\n bare = true\n fsmonitor = ./sentinel\n")
	if err := os.WriteFile(filepath.Join(root, "nested/HEAD"), []byte(strings.Repeat("a", 40)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := New(rules.DefaultRegistry(), Options{}).Scan(context.Background(), localDir(root))
	if err != nil || len(result.Findings) != 1 || result.Findings[0].RuleID != "SD-027" {
		t.Fatalf("detached bare HEAD not inventoried: %+v, %v", result, err)
	}
}

func TestNestedBareGitExampleInDocumentationIsInert(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("Example bare Git config:\n[core]\n bare = true\n fsmonitor = ./sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := New(rules.DefaultRegistry(), Options{}).Scan(context.Background(), localDir(root))
	if err != nil || len(result.Findings) != 0 || !result.NoAgentSurface {
		t.Fatalf("documentation must not create Git findings or grades: %+v, %v", result, err)
	}
}

func TestNestedBareGitConfigDiffExternal(t *testing.T) {
	root := t.TempDir()
	writeBareFixture(t, root, "deep", "[core]\n bare = true\n[diff]\n external = ./sentinel\n")
	result, err := New(rules.DefaultRegistry(), Options{}).Scan(context.Background(), localDir(root))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Line != 4 || !strings.Contains(result.Findings[0].Description, "diff.external") {
		t.Fatalf("expected conditional diff.external inventory, got %+v", result.Findings)
	}
}

func TestNestedBareGitConfigControls(t *testing.T) {
	for _, tc := range []struct {
		name, location, config string
		removeSignature        bool
	}{
		{"boolean fsmonitor", "work/nested", "[core]\n bare = true\n fsmonitor = false\n", false},
		{"ordinary Git config", "work/nested", "[core]\n bare = true\n filemode = true\n", false},
		{"unrelated subsection", "work/nested", "[core]\n bare = true\n[diff \"driver\"]\n external = ./sentinel\n", false},
		{"non-bare config", "work/nested", "[core]\n bare = false\n fsmonitor = ./sentinel\n", false},
		{"not a bare repository", "work/nested", "[core]\n bare = true\n fsmonitor = ./sentinel\n", true},
		{"excluded git metadata", ".git/nested", "[core]\n bare = true\n fsmonitor = ./sentinel\n", false},
		{"excluded vendor", "vendor/nested", "[core]\n bare = true\n fsmonitor = ./sentinel\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeBareFixture(t, root, tc.location, tc.config)
			if tc.removeSignature {
				if err := os.RemoveAll(filepath.Join(root, tc.location, "objects")); err != nil {
					t.Fatal(err)
				}
			}
			result, err := New(rules.DefaultRegistry(), Options{ScanAll: true}).Scan(context.Background(), localDir(root))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) != 0 {
				t.Fatalf("unexpected findings: %+v", result.Findings)
			}
		})
	}
}

func TestNestedBareGitConfigIncompleteFailsClosed(t *testing.T) {
	for _, config := range []string{
		"[core]\n bare = true\n fsmonitor = ./sentinel\n[include]\n path = other.conf\n",
		"[core]\n bare = true\n[INCLUDE]\n path = other.conf\n",
		"[core]\n bare = true\n[diff] # []\n external = ./sentinel\n",
		"[core] # []\n bare = true\n fsmonitor = ./sentinel\n",
		"[core]\n bare = true\n[include] # []\n path = other.conf\n",
		"[core]\n bare = true\n fsmonitor = ./sentinel\nnot a git assignment\n",
		"[]\n[core]\n bare = true\n fsmonitor = ./sentinel\n",
		"[core]\n fsmonitor = ./sentinel\n",
		"[core]\n bare = true\n" + strings.Repeat("x", 65536),
	} {
		root := t.TempDir()
		writeBareFixture(t, root, "nested", config)
		result, err := New(rules.DefaultRegistry(), Options{}).Scan(context.Background(), localDir(root))
		if err == nil || result != nil {
			t.Fatalf("incomplete config returned graded result: %+v, %v", result, err)
		}
	}
}

func TestNestedBareGitConfigSymlinkCannotEscape(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeBareFixture(t, root, "nested", "[core]\n bare = true\n fsmonitor = ./sentinel\n")
	if err := os.Remove(filepath.Join(root, "nested", "config")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "config"), []byte("[core]\n bare = true\n fsmonitor = ./sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "config"), filepath.Join(root, "nested", "config")); err != nil {
		t.Fatal(err)
	}
	result, err := New(rules.DefaultRegistry(), Options{}).Scan(context.Background(), localDir(root))
	if err == nil || result != nil {
		t.Fatalf("escaping config symlink must not produce a result: %+v, %v", result, err)
	}
}

func TestNestedBareGitHEADSymlinkIsNotSilentlyClean(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeBareFixture(t, root, "nested", "[core]\n bare = true\n fsmonitor = ./sentinel\n")
	if err := os.Remove(filepath.Join(root, "nested", "HEAD")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "HEAD"), filepath.Join(root, "nested", "HEAD")); err != nil {
		t.Fatal(err)
	}
	result, err := New(rules.DefaultRegistry(), Options{}).Scan(context.Background(), localDir(root))
	if err == nil || result != nil {
		t.Fatalf("unsupported HEAD symlink must not produce a result: %+v, %v", result, err)
	}
}

func TestNestedBareGitConfigHonorsGitignore(t *testing.T) {
	root := t.TempDir()
	writeBareFixture(t, root, "nested", "[core]\n bare = true\n fsmonitor = ./sentinel\n")
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("nested/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		all  bool
		want int
	}{{false, 0}, {true, 1}} {
		result, err := New(rules.DefaultRegistry(), Options{ScanAll: tc.all}).Scan(context.Background(), localDir(root))
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Findings) != tc.want {
			t.Fatalf("scanAll=%v: findings=%+v, want %d", tc.all, result.Findings, tc.want)
		}
	}
}

func TestNestedBareGitConfigCandidateLimit(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 65; i++ {
		writeBareFixture(t, root, filepath.Join("nested", string(rune('a'+i/26)), string(rune('a'+i%26))), "[core]\n bare = true\n")
	}
	result, err := New(rules.DefaultRegistry(), Options{}).Scan(context.Background(), localDir(root))
	if err == nil || result != nil {
		t.Fatalf("candidate overflow returned a graded result: %+v, %v", result, err)
	}
}

type localDir string

func (d localDir) Path() string { return string(d) }
