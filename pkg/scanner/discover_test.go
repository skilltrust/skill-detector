package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestDiscover(t *testing.T) {
	tests := []struct {
		name      string
		root      string
		wantCount int
		wantErr   bool
		wantPaths []string
	}{
		{
			name:      "clean skill discovers all scannable files",
			root:      "../../testdata/clean/simple-skill",
			wantCount: 4,
			wantPaths: []string{"README.md", "prompt.txt", "setup.sh", "skill.yaml"},
		},
		{
			name:      "binary file is skipped",
			root:      "../../testdata/edge-cases/binary-file",
			wantCount: 1,
			wantPaths: []string{"README.md"},
		},
		{
			name:      "hidden directory is skipped",
			root:      "../../testdata/edge-cases/hidden-dir",
			wantCount: 1,
			wantPaths: []string{"visible.md"},
		},
		{
			name:      "malformed yaml is still discovered",
			root:      "../../testdata/edge-cases/malformed-yaml",
			wantCount: 1,
			wantPaths: []string{"bad.yaml"},
		},
		{
			name:      "empty directory returns zero entries",
			root:      "../../testdata/edge-cases/empty-dir",
			wantCount: 0,
		},
		{
			name:    "nonexistent path returns error",
			root:    "../../testdata/does-not-exist",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := Discover(tt.root)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := len(files); got != tt.wantCount {
				t.Errorf("file count = %d, want %d", got, tt.wantCount)
				for _, f := range files {
					t.Logf("  discovered: %s", f.Path)
				}
			}

			if len(tt.wantPaths) > 0 {
				gotPaths := make([]string, len(files))
				for i, f := range files {
					gotPaths[i] = f.Path
				}
				sort.Strings(gotPaths)

				wantSorted := make([]string, len(tt.wantPaths))
				copy(wantSorted, tt.wantPaths)
				sort.Strings(wantSorted)

				if len(gotPaths) != len(wantSorted) {
					t.Errorf("paths = %v, want %v", gotPaths, wantSorted)
				} else {
					for i := range gotPaths {
						if gotPaths[i] != wantSorted[i] {
							t.Errorf("path[%d] = %q, want %q", i, gotPaths[i], wantSorted[i])
						}
					}
				}
			}
		})
	}
}

func TestDiscoverFileContextFields(t *testing.T) {
	files, err := Discover("../../testdata/clean/simple-skill")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range files {
		// Path must be relative (not absolute).
		if filepath.IsAbs(f.Path) {
			t.Errorf("path %q is absolute, want relative", f.Path)
		}

		// Ext must match filepath.Ext of the path.
		wantExt := filepath.Ext(f.Path)
		if f.Ext != wantExt {
			t.Errorf("file %q: ext = %q, want %q", f.Path, f.Ext, wantExt)
		}

		// Content must be non-empty and match the actual file contents.
		if len(f.Content) == 0 {
			t.Errorf("file %q: content is empty", f.Path)
		}

		fullPath := filepath.Join("../../testdata/clean/simple-skill", f.Path)
		expected, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("failed to read %q: %v", fullPath, err)
		}
		if string(f.Content) != string(expected) {
			t.Errorf("file %q: content mismatch", f.Path)
		}
	}
}

func TestDiscoverSkipsNonScannableExtensions(t *testing.T) {
	// The binary-file fixture has image.png which is both non-scannable ext AND binary.
	// Create a temp dir with a non-scannable text file to test ext filtering alone.
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "data.csv"), []byte("a,b,c\n1,2,3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "readme.md"), []byte("# Hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	files, err := Discover(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("file count = %d, want 1", len(files))
	}
	if files[0].Path != "readme.md" {
		t.Errorf("path = %q, want %q", files[0].Path, "readme.md")
	}
}

func TestDiscoverWalksClaudeDir(t *testing.T) {
	dir := t.TempDir()
	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{"permissions":{"allow":["Bash(curl *)"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var found bool
	for _, f := range files {
		if filepath.ToSlash(f.Path) == ".claude/settings.json" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf(".claude/settings.json not discovered. Walked files: %+v", files)
	}
}

func TestDiscoverStillSkipsGitDir(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	gitFile := filepath.Join(gitDir, "config")
	if err := os.WriteFile(gitFile, []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	for _, f := range files {
		if strings.HasPrefix(filepath.ToSlash(f.Path), ".git/") {
			t.Errorf(".git/ should still be skipped, got walked file: %s", f.Path)
		}
	}
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty data", []byte{}, false},
		{"text content", []byte("hello world"), false},
		{"nul at start", []byte{0, 'h', 'e', 'l', 'l', 'o'}, true},
		{"nul in middle", []byte{'h', 'e', 0, 'l', 'o'}, true},
		{"utf8 text", []byte("Привет мир"), false},
		{"png header without nul", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, false},
		{"actual binary with nul", []byte{0x89, 'P', 'N', 'G', 0, 0, 0, '\n'}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBinary(tt.data); got != tt.want {
				t.Errorf("isBinary() = %v, want %v", got, tt.want)
			}
		})
	}
}
