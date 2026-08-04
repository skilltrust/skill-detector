package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestLoad_ConfigInScanDir(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "fail_on: high\n")

	cfg, err := Load(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FailOn != model.SeverityHigh {
		t.Errorf("FailOn = %v, want HIGH", cfg.FailOn)
	}
}

func TestLoad_ConfigInParentDir(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "sub", "deep")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatal(err)
	}
	writeRC(t, parent, "fail_on: medium\n")

	cfg, err := Load(child, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FailOn != model.SeverityMedium {
		t.Errorf("FailOn = %v, want MEDIUM", cfg.FailOn)
	}
}

func TestLoad_HomeConfigFallback(t *testing.T) {
	// Create a temp dir to act as $HOME.
	fakeHome := t.TempDir()
	configDir := filepath.Join(fakeHome, ".config", "skill-detector")
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("fail_on: low\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", fakeHome)

	// Scan from a dir with no .skill-detectorrc (use a subdir of fakeHome to avoid
	// accidentally finding config in the real filesystem).
	scanDir := filepath.Join(fakeHome, "project")
	if err := os.MkdirAll(scanDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(scanDir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FailOn != model.SeverityLow {
		t.Errorf("FailOn = %v, want LOW", cfg.FailOn)
	}
}

func TestLoad_NoConfigDefaults(t *testing.T) {
	// Use a temp dir with no config files and a fake HOME with no config.
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	scanDir := filepath.Join(fakeHome, "empty-project")
	if err := os.MkdirAll(scanDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(scanDir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FailOn != model.SeverityCritical {
		t.Errorf("FailOn = %v, want CRITICAL (default)", cfg.FailOn)
	}
}

func TestLoad_ExplicitConfigFlag(t *testing.T) {
	dir := t.TempDir()
	customPath := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(customPath, []byte("fail_on: info\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("/some/scan/path", customPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FailOn != model.SeverityInfo {
		t.Errorf("FailOn = %v, want INFO", cfg.FailOn)
	}
}

func TestLoad_ExplicitConfigNotFound(t *testing.T) {
	_, err := Load("/some/path", "/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent explicit config")
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "fail_on: [invalid yaml\n")

	_, err := Load(dir, "")
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestLoad_InvalidFailOn(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "fail_on: extreme\n")

	_, err := Load(dir, "")
	if err == nil {
		t.Fatal("expected error for invalid fail_on value")
	}
}

func TestLoad_FailOnHighParsed(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "fail_on: high\n")

	cfg, err := Load(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FailOn != model.SeverityHigh {
		t.Errorf("FailOn = %v, want HIGH", cfg.FailOn)
	}
}

func TestLoad_RulesAndAllowParsed(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, `fail_on: high
rules:
  SD-005:
    enabled: false
  SD-007:
    severity: medium
allow:
  network:
    - "api.example.com"
  filesystem:
    - "/usr/local/share"
`)

	cfg, err := Load(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(cfg.Rules))
	}
	sd005, ok := cfg.Rules["SD-005"]
	if !ok {
		t.Fatal("SD-005 rule config missing")
	}
	if sd005.Enabled == nil || *sd005.Enabled != false {
		t.Errorf("SD-005.Enabled = %v, want false", sd005.Enabled)
	}

	sd007, ok := cfg.Rules["SD-007"]
	if !ok {
		t.Fatal("SD-007 rule config missing")
	}
	if sd007.Severity != "medium" {
		t.Errorf("SD-007.Severity = %q, want %q", sd007.Severity, "medium")
	}

	if len(cfg.Allow.Network) != 1 || cfg.Allow.Network[0] != "api.example.com" {
		t.Errorf("Allow.Network = %v, want [api.example.com]", cfg.Allow.Network)
	}
	if len(cfg.Allow.Filesystem) != 1 || cfg.Allow.Filesystem[0] != "/usr/local/share" {
		t.Errorf("Allow.Filesystem = %v, want [/usr/local/share]", cfg.Allow.Filesystem)
	}
}

func TestLoad_InvalidRuleSeverity(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "rules:\n  SD-007:\n    severity: extreme\n")

	_, err := Load(dir, "")
	if err == nil {
		t.Fatal("expected error for invalid rule severity")
	}
	if !strings.Contains(err.Error(), "invalid severity") {
		t.Errorf("expected 'invalid severity' in error, got: %v", err)
	}
}

func TestLoad_ValidRuleSeverities(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, `rules:
  SD-005:
    enabled: false
  SD-007:
    severity: medium
  SD-001:
    severity: low
`)

	cfg, err := Load(dir, "")
	if err != nil {
		t.Fatalf("unexpected error for valid rule severities: %v", err)
	}
	if cfg.Rules["SD-007"].Severity != "medium" {
		t.Errorf("SD-007.Severity = %q, want %q", cfg.Rules["SD-007"].Severity, "medium")
	}
}

func TestLoad_EmptyRuleSeveritySkipsValidation(t *testing.T) {
	dir := t.TempDir()
	// No severity field — just enabled: false. Should not error.
	writeRC(t, dir, "rules:\n  SD-005:\n    enabled: false\n")

	_, err := Load(dir, "")
	if err != nil {
		t.Fatalf("unexpected error for empty severity: %v", err)
	}
}

func TestLoad_EmptyConfigFile_UsesDefaults(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "")

	cfg, err := Load(dir, "")
	if err != nil {
		t.Fatalf("empty config file should not error: %v", err)
	}
	if cfg.FailOn != model.SeverityCritical {
		t.Errorf("FailOn = %v, want CRITICAL (default)", cfg.FailOn)
	}
}

func TestLoad_CommentOnlyConfigFile_UsesDefaults(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "# TODO: configure later\n")

	cfg, err := Load(dir, "")
	if err != nil {
		t.Fatalf("comment-only config file should not error: %v", err)
	}
	if cfg.FailOn != model.SeverityCritical {
		t.Errorf("FailOn = %v, want CRITICAL (default)", cfg.FailOn)
	}
}

func TestLoad_ContextExpected(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "rules:\n  SD-007:\n    context: expected\n")

	cfg, err := Load(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Rules["SD-007"].Context != "expected" {
		t.Errorf("SD-007.Context = %q, want %q", cfg.Rules["SD-007"].Context, "expected")
	}
}

func TestLoad_ContextInvalid(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "rules:\n  SD-007:\n    context: wrong\n")

	_, err := Load(dir, "")
	if err == nil {
		t.Fatal("expected error for invalid context value")
	}
	want := `config: invalid context "wrong" for rule SD-007`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestLoad_ContextAndSeverityTogether(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "rules:\n  SD-007:\n    severity: medium\n    context: expected\n")

	cfg, err := Load(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Rules["SD-007"].Severity != "medium" {
		t.Errorf("SD-007.Severity = %q, want %q", cfg.Rules["SD-007"].Severity, "medium")
	}
	if cfg.Rules["SD-007"].Context != "expected" {
		t.Errorf("SD-007.Context = %q, want %q", cfg.Rules["SD-007"].Context, "expected")
	}
}

func TestLoad_ContextEmpty_NoValidationError(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "rules:\n  SD-005:\n    enabled: false\n")

	_, err := Load(dir, "")
	if err != nil {
		t.Fatalf("unexpected error for rule without context: %v", err)
	}
}

func TestLoad_ConfigYamlFilename(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".skill-detector.yml"), []byte("fail_on: high\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FailOn != model.SeverityHigh {
		t.Errorf("FailOn = %v, want HIGH", cfg.FailOn)
	}
}

func TestLoad_ConfigRCTakesPrecedenceOverYaml(t *testing.T) {
	dir := t.TempDir()
	writeRC(t, dir, "fail_on: high\n")
	if err := os.WriteFile(filepath.Join(dir, ".skill-detector.yml"), []byte("fail_on: low\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FailOn != model.SeverityHigh {
		t.Errorf("FailOn = %v, want HIGH (.skill-detectorrc should take precedence)", cfg.FailOn)
	}
}

// writeRC writes a .skill-detectorrc file in the given directory.
func writeRC(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".skill-detectorrc"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
