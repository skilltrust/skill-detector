package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/scanner"
)

type dirInput string

func (d dirInput) Path() string { return string(d) }

func TestScanReturnsResultForCleanFixture(t *testing.T) {
	in := dirInput("../../testdata/clean")
	s := scanner.New(rules.DefaultRegistry(), scanner.Options{Version: "test"})
	res, err := s.Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("clean fixture should produce no findings, got %d", len(res.Findings))
	}
}

func TestScanRespectsContextCancellation(t *testing.T) {
	in := dirInput("../../testdata/clean")
	s := scanner.New(rules.DefaultRegistry(), scanner.Options{Version: "test"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Scan(ctx, in)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestScanDoesNotWriteOutsideInputDir(t *testing.T) {
	tmp := t.TempDir()
	if err := copyDir("../../testdata/clean", tmp); err != nil {
		t.Fatalf("setup: %v", err)
	}
	parent := filepath.Dir(tmp)
	before, _ := os.ReadDir(parent)
	s := scanner.New(rules.DefaultRegistry(), scanner.Options{Version: "test"})
	if _, err := s.Scan(context.Background(), dirInput(tmp)); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	after, _ := os.ReadDir(parent)
	if len(after) != len(before) {
		t.Fatalf("Scan created files outside input dir: before=%d after=%d", len(before), len(after))
	}
}

func TestScanHonorsTimeoutOption(t *testing.T) {
	in := dirInput("../../testdata/clean")
	s := scanner.New(rules.DefaultRegistry(), scanner.Options{
		Version: "test",
		Timeout: time.Nanosecond,
	})
	_, err := s.Scan(context.Background(), in)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}
