package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

// --- Helper ---

// runScan executes the scan command with the given args and returns stdout, stderr, exit code, and error.
func runScan(t *testing.T, args ...string) (stdout, stderr string, code int, err error) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)

	scanExitCode = 0
	err = cmd.Execute()
	return outBuf.String(), errBuf.String(), scanExitCode, err
}

// runScanJSON executes the scan in JSON mode and returns the parsed ScanResult.
func runScanJSON(t *testing.T, path string, extraArgs ...string) model.ScanResult {
	t.Helper()
	args := append([]string{"scan", "--format", "json"}, extraArgs...)
	args = append(args, path)
	stdout, _, _, err := runScan(t, args...)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var result model.ScanResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, stdout)
	}
	return result
}

// findingRuleIDs returns a set of unique rule IDs from findings.
func findingRuleIDs(findings []model.Finding) map[string]bool {
	ids := make(map[string]bool)
	for _, f := range findings {
		ids[f.RuleID] = true
	}
	return ids
}

// hasPermissionType checks if permissions include a given type.
func hasPermissionType(perms []model.Permission, typ string) bool {
	for _, p := range perms {
		if p.Type == typ {
			return true
		}
	}
	return false
}

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func findFindingByRule(t *testing.T, findings []model.Finding, ruleID string) model.Finding {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f
		}
	}
	t.Fatalf("expected %s finding in output", ruleID)
	return model.Finding{}
}

// --- E2E: Malicious Fixtures ---

func TestE2E_MaliciousCredentialTheft(t *testing.T) {
	result := runScanJSON(t, "../../testdata/malicious/credential-theft")

	if len(result.Findings) == 0 {
		t.Fatal("expected findings for credential-theft fixture")
	}

	// Must detect credential access (SD-004) and outbound network call (SD-007).
	ids := findingRuleIDs(result.Findings)
	for _, expected := range []string{"SD-004", "SD-007"} {
		if !ids[expected] {
			t.Errorf("expected rule %s to fire, got rules: %v", expected, ids)
		}
	}

	// Permissions: filesystem (with credentials) and network.
	if !hasPermissionType(result.Permissions, "filesystem") {
		t.Error("expected filesystem permission")
	}
	if !hasPermissionType(result.Permissions, "network") {
		t.Error("expected network permission")
	}

	// Exit code 2 (critical findings with default threshold).
	stdout, _, code, err := runScan(t, "scan", "--no-color", "../../testdata/malicious/credential-theft")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stdout, "behaviors detected") {
		t.Errorf("expected 'behaviors detected' verdict, got: %s", stdout)
	}
	// Verify confidence icons appear in text output.
	hasIcon := strings.Contains(stdout, "●") || strings.Contains(stdout, "◐") || strings.Contains(stdout, "○")
	if !hasIcon {
		t.Errorf("expected confidence icons (●/◐/○) in text output, got: %s", stdout)
	}
	// Verify OWASP category tags appear.
	if !strings.Contains(stdout, "Access Control") && !strings.Contains(stdout, "Data Exfiltration") {
		t.Errorf("expected OWASP category tags in output, got: %s", stdout)
	}
	// Verify diagnosis lines appear below findings.
	foundDiagnosis := false
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Likely") || strings.HasPrefix(strings.TrimSpace(line), "Possible") {
			foundDiagnosis = true
			break
		}
	}
	if !foundDiagnosis {
		t.Errorf("expected diagnosis lines in default text output, got: %s", stdout)
	}
}

func TestE2E_MaliciousExfiltration(t *testing.T) {
	result := runScanJSON(t, "../../testdata/malicious/exfiltration")

	if len(result.Findings) == 0 {
		t.Fatal("expected findings for exfiltration fixture")
	}

	ids := findingRuleIDs(result.Findings)
	// Must detect: hardcoded secret (SD-006), network call (SD-007), base64 obfuscation (SD-008).
	for _, expected := range []string{"SD-006", "SD-007", "SD-008"} {
		if !ids[expected] {
			t.Errorf("expected rule %s to fire, got rules: %v", expected, ids)
		}
	}

	if !hasPermissionType(result.Permissions, "network") {
		t.Error("expected network permission")
	}

	_, _, code, _ := runScan(t, "scan", "--no-color", "../../testdata/malicious/exfiltration")
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestE2E_MaliciousPersistence(t *testing.T) {
	result := runScanJSON(t, "../../testdata/malicious/persistence")

	if len(result.Findings) == 0 {
		t.Fatal("expected findings for persistence fixture")
	}

	ids := findingRuleIDs(result.Findings)
	// Must detect: persistence (SD-013), git hooks (SD-014), post-install hook (SD-012),
	// curl pipe bash (SD-009), network call (SD-007).
	for _, expected := range []string{"SD-009", "SD-012", "SD-013", "SD-014"} {
		if !ids[expected] {
			t.Errorf("expected rule %s to fire, got rules: %v", expected, ids)
		}
	}

	if !hasPermissionType(result.Permissions, "shell_execution") {
		t.Error("expected shell_execution permission")
	}

	_, _, code, _ := runScan(t, "scan", "--no-color", "../../testdata/malicious/persistence")
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestE2E_MaliciousPromptInjection(t *testing.T) {
	result := runScanJSON(t, "../../testdata/malicious/prompt-injection")

	if len(result.Findings) == 0 {
		t.Fatal("expected findings for prompt-injection fixture")
	}

	ids := findingRuleIDs(result.Findings)
	// Must detect prompt injection (SD-002).
	if !ids["SD-002"] {
		t.Errorf("expected rule SD-002 to fire, got rules: %v", ids)
	}

	// Should also detect credential access reference (~/.ssh/id_rsa) via SD-004.
	if !ids["SD-004"] {
		t.Errorf("expected rule SD-004 to fire (credential reference in prompt), got rules: %v", ids)
	}

	_, _, code, _ := runScan(t, "scan", "--no-color", "../../testdata/malicious/prompt-injection")
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestE2E_MaliciousShellInjection(t *testing.T) {
	result := runScanJSON(t, "../../testdata/malicious/shell-injection")

	if len(result.Findings) == 0 {
		t.Fatal("expected findings for shell-injection fixture")
	}

	ids := findingRuleIDs(result.Findings)
	// Must detect shell injection (SD-001).
	if !ids["SD-001"] {
		t.Errorf("expected rule SD-001 to fire, got rules: %v", ids)
	}

	if !hasPermissionType(result.Permissions, "shell_execution") {
		t.Error("expected shell_execution permission")
	}

	_, _, code, _ := runScan(t, "scan", "--no-color", "../../testdata/malicious/shell-injection")
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestE2E_MaliciousSupplyChain(t *testing.T) {
	result := runScanJSON(t, "../../testdata/malicious/supply-chain")

	if len(result.Findings) == 0 {
		t.Fatal("expected findings for supply-chain fixture")
	}

	ids := findingRuleIDs(result.Findings)
	// Must detect: curl pipe bash (SD-009), runtime download (SD-010),
	// vulnerable dependencies (SD-011), network calls (SD-007).
	for _, expected := range []string{"SD-007", "SD-009", "SD-010", "SD-011"} {
		if !ids[expected] {
			t.Errorf("expected rule %s to fire, got rules: %v", expected, ids)
		}
	}

	if !hasPermissionType(result.Permissions, "network") {
		t.Error("expected network permission")
	}
	if !hasPermissionType(result.Permissions, "shell_execution") {
		t.Error("expected shell_execution permission")
	}

	_, _, code, _ := runScan(t, "scan", "--no-color", "../../testdata/malicious/supply-chain")
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

// --- E2E: Clean Fixture ---

func TestE2E_CleanSimpleSkill(t *testing.T) {
	result := runScanJSON(t, "../../testdata/clean/simple-skill")

	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for clean skill, got %d: %+v", len(result.Findings), result.Findings)
	}

	if result.FileCount == 0 {
		t.Error("expected at least 1 file scanned")
	}
	if result.RuleCount == 0 {
		t.Error("expected rules to be loaded")
	}
	if result.SchemaVersion != "1.1" {
		t.Errorf("schema_version = %q, want %q", result.SchemaVersion, "1.1")
	}
	if len(result.ConfigOverrides) != 0 {
		t.Errorf("expected no config overrides for clean scan, got %d", len(result.ConfigOverrides))
	}

	stdout, _, code, err := runScan(t, "scan", "--no-color", "../../testdata/clean/simple-skill")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout, "No concerns") {
		t.Errorf("expected 'No concerns' verdict, got: %s", stdout)
	}
	// Verify inline permissions appear on verdict line.
	if !strings.Contains(stdout, "no network") {
		t.Errorf("expected inline permissions with 'no network' in clean scan output, got: %s", stdout)
	}
}

// --- E2E: Edge Cases ---

func TestE2E_EdgeCase_BinaryFile(t *testing.T) {
	result := runScanJSON(t, "../../testdata/edge-cases/binary-file")

	// README.md should be scanned, image.png should be skipped.
	if result.FileCount != 1 {
		t.Errorf("expected 1 file scanned (README.md only, binary skipped), got %d", result.FileCount)
	}

	// README.md is clean.
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}
}

func TestE2E_EdgeCase_EmptySkill(t *testing.T) {
	result := runScanJSON(t, "../../testdata/edge-cases/empty-skill")

	// Only README.md exists.
	if result.FileCount != 1 {
		t.Errorf("expected 1 file scanned, got %d", result.FileCount)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}

	_, _, code, _ := runScan(t, "scan", "--no-color", "../../testdata/edge-cases/empty-skill")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestE2E_EdgeCase_HiddenDir(t *testing.T) {
	result := runScanJSON(t, "../../testdata/edge-cases/hidden-dir")

	// visible.md should be discovered; .hidden/secret.md should be skipped.
	if result.FileCount != 1 {
		t.Errorf("expected 1 file scanned (visible.md only), got %d", result.FileCount)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}
}

func TestE2E_EdgeCase_MalformedYAML(t *testing.T) {
	// Malformed YAML should not crash the scanner.
	result := runScanJSON(t, "../../testdata/edge-cases/malformed-yaml")

	if result.FileCount != 1 {
		t.Errorf("expected 1 file scanned, got %d", result.FileCount)
	}
	// No panic or error — graceful handling.
}

func TestE2E_EdgeCase_EmptyDir(t *testing.T) {
	result := runScanJSON(t, "../../testdata/edge-cases/empty-dir")

	if result.FileCount != 0 {
		t.Errorf("expected 0 files scanned for empty dir, got %d", result.FileCount)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}

	_, _, code, _ := runScan(t, "scan", "--no-color", "../../testdata/edge-cases/empty-dir")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

// --- E2E: Verbose Mode ---

func TestE2E_VerboseMode(t *testing.T) {
	stdout, _, _, err := runScan(t, "scan", "--no-color", "--verbose", "../../testdata/malicious/credential-theft")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verbose output should include Rule:, File:, Confidence:, Your check: lines.
	for _, keyword := range []string{"Rule:", "File:", "Confidence:", "Your check:"} {
		if !strings.Contains(stdout, keyword) {
			t.Errorf("verbose output missing %q\noutput: %s", keyword, stdout)
		}
	}

	// Should contain rule IDs in verbose detail.
	if !strings.Contains(stdout, "SD-004") {
		t.Errorf("verbose output missing SD-004 rule ID\noutput: %s", stdout)
	}
}

func TestE2E_VerboseShowsDiagnosis(t *testing.T) {
	stdout, _, _, err := runScan(t, "scan", "--no-color", "--verbose", "../../testdata/malicious/exfiltration")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Diagnosis appears in Confidence: line (e.g., "high · Likely ...").
	// Check that some diagnostic text is present.
	lines := strings.Split(stdout, "\n")
	foundDiagnosis := false
	for _, line := range lines {
		if strings.Contains(line, "Confidence:") && strings.Contains(line, "·") {
			foundDiagnosis = true
			break
		}
	}
	if !foundDiagnosis {
		t.Errorf("verbose output missing diagnosis in Confidence line\noutput: %s", stdout)
	}
}

// --- E2E: JSON Schema Validation ---

func TestE2E_JSONSchemaFields(t *testing.T) {
	result := runScanJSON(t, "../../testdata/malicious/credential-theft")

	if result.SchemaVersion != "1.1" {
		t.Errorf("schema_version = %q, want %q", result.SchemaVersion, "1.1")
	}
	if result.Version == "" {
		t.Error("expected non-empty version field")
	}
	if result.RuleCount == 0 {
		t.Error("expected non-zero rule count")
	}
	if result.Checksum == "" {
		t.Error("expected non-empty checksum")
	}
	if len(result.Checksum) != 16 {
		t.Errorf("expected 16-char checksum, got %d chars: %q", len(result.Checksum), result.Checksum)
	}

	// Validate finding fields are populated.
	for i, f := range result.Findings {
		if f.RuleID == "" {
			t.Errorf("finding[%d]: empty RuleID", i)
		}
		if f.RuleName == "" {
			t.Errorf("finding[%d]: empty RuleName", i)
		}
		if f.Category == "" {
			t.Errorf("finding[%d]: empty Category", i)
		}
		if f.Description == "" {
			t.Errorf("finding[%d]: empty Description", i)
		}
		if f.FilePath == "" {
			t.Errorf("finding[%d]: empty FilePath", i)
		}
		if f.Remediation == "" {
			t.Errorf("finding[%d]: empty Remediation", i)
		}
		if f.Line <= 0 {
			t.Errorf("finding[%d]: expected positive line number, got %d", i, f.Line)
		}
	}

	// Validate permission fields.
	for i, p := range result.Permissions {
		if p.Type == "" {
			t.Errorf("permission[%d]: empty Type", i)
		}
	}
}

func TestE2E_JSONNilSlicesNormalized(t *testing.T) {
	// Clean scan should produce empty arrays, not null.
	stdout, _, _, err := runScan(t, "scan", "--format", "json", "../../testdata/clean/simple-skill")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// findings and permissions should be [] not null.
	for _, key := range []string{"findings", "permissions", "config_overrides"} {
		if val, ok := raw[key]; ok {
			trimmed := strings.TrimSpace(string(val))
			if trimmed == "null" {
				t.Errorf("expected empty array for %q, got null", key)
			}
		}
	}
}

func TestE2E_JSONConfigOverrides(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/run.sh", []byte(sd007Content), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := writeConfigFile(t, "rules:\n  SD-007:\n    severity: medium\n")

	result := runScanJSON(t, dir, "--config", configPath)
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

// --- E2E: Cross-Format Consistency ---

func TestE2E_TextAndJSONFindingsCountMatch(t *testing.T) {
	fixtures := []string{
		"../../testdata/malicious/credential-theft",
		"../../testdata/malicious/exfiltration",
		"../../testdata/malicious/shell-injection",
		"../../testdata/malicious/supply-chain",
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			jsonResult := runScanJSON(t, fixture)
			jsonCount := len(jsonResult.Findings)

			// Text mode with verbose shows all findings.
			stdout, _, _, err := runScan(t, "scan", "--no-color", "--verbose", fixture)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Count "Rule:" lines in verbose output (one per finding).
			textCount := strings.Count(stdout, "Rule:")
			if textCount != jsonCount {
				t.Errorf("text verbose shows %d findings (Rule: lines) but JSON has %d findings", textCount, jsonCount)
			}
		})
	}
}

// --- E2E: Permission Extraction ---

func TestE2E_PermissionsCredentialTheft(t *testing.T) {
	result := runScanJSON(t, "../../testdata/malicious/credential-theft")

	// Must have filesystem (with credential details) and network permissions.
	var fsPerm *model.Permission
	for i := range result.Permissions {
		if result.Permissions[i].Type == "filesystem" {
			fsPerm = &result.Permissions[i]
			break
		}
	}
	if fsPerm == nil {
		t.Fatal("expected filesystem permission")
	}

	hasCredentialDetail := false
	for _, d := range fsPerm.Details {
		if strings.Contains(d, "credentials") {
			hasCredentialDetail = true
			break
		}
	}
	if !hasCredentialDetail {
		t.Errorf("expected filesystem permission to mention credentials, details: %v", fsPerm.Details)
	}
}

func TestE2E_PermissionsShellInjection(t *testing.T) {
	result := runScanJSON(t, "../../testdata/malicious/shell-injection")

	if !hasPermissionType(result.Permissions, "shell_execution") {
		t.Error("expected shell_execution permission for shell-injection fixture")
	}
}

func TestE2E_PermissionsSupplyChain(t *testing.T) {
	result := runScanJSON(t, "../../testdata/malicious/supply-chain")

	// Supply chain fixture involves network + shell.
	if !hasPermissionType(result.Permissions, "network") {
		t.Error("expected network permission")
	}
	if !hasPermissionType(result.Permissions, "shell_execution") {
		t.Error("expected shell_execution permission")
	}
}

func TestE2E_CleanSkillPermissions(t *testing.T) {
	result := runScanJSON(t, "../../testdata/clean/simple-skill")

	// Clean skill should have filesystem (files exist) but no network/shell.
	if hasPermissionType(result.Permissions, "network") {
		t.Error("clean skill should not have network permission")
	}
	if hasPermissionType(result.Permissions, "shell_execution") {
		t.Error("clean skill should not have shell_execution permission")
	}
}

// --- E2E: Exit Codes Across All Fixtures ---

func TestE2E_ExitCodesAllFixtures(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantCode int
	}{
		{"clean/simple-skill", "../../testdata/clean/simple-skill", 0},
		{"malicious/credential-theft", "../../testdata/malicious/credential-theft", 2},
		{"malicious/exfiltration", "../../testdata/malicious/exfiltration", 2},
		{"malicious/persistence", "../../testdata/malicious/persistence", 2},
		{"malicious/prompt-injection", "../../testdata/malicious/prompt-injection", 2},
		{"malicious/shell-injection", "../../testdata/malicious/shell-injection", 2},
		{"malicious/supply-chain", "../../testdata/malicious/supply-chain", 2},
		{"edge-cases/binary-file", "../../testdata/edge-cases/binary-file", 0},
		{"edge-cases/empty-skill", "../../testdata/edge-cases/empty-skill", 0},
		{"edge-cases/hidden-dir", "../../testdata/edge-cases/hidden-dir", 0},
		{"edge-cases/malformed-yaml", "../../testdata/edge-cases/malformed-yaml", 0},
		{"edge-cases/empty-dir", "../../testdata/edge-cases/empty-dir", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, code, err := runScan(t, "scan", "--no-color", tt.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
		})
	}
}

// --- E2E: Verdict Strings ---

func TestE2E_VerdictStrings(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		verdict string
	}{
		{"clean", "../../testdata/clean/simple-skill", "No concerns"},
		{"malicious-critical", "../../testdata/malicious/credential-theft", "behaviors detected"},
		{"malicious-critical-supply", "../../testdata/malicious/supply-chain", "behaviors detected"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, _, err := runScan(t, "scan", "--no-color", tt.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(stdout, tt.verdict) {
				t.Errorf("expected verdict %q in output, got: %s", tt.verdict, stdout)
			}
		})
	}
}

// --- E2E: Text Output Structure ---

func TestE2E_TextOutputContainsMetadata(t *testing.T) {
	stdout, _, _, err := runScan(t, "scan", "--no-color", "../../testdata/malicious/credential-theft")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Metadata line should contain file count and rule count.
	if !strings.Contains(stdout, "files scanned") {
		t.Errorf("output missing 'files scanned' metadata\noutput: %s", stdout)
	}
	if !strings.Contains(stdout, "rules") {
		t.Errorf("output missing 'rules' metadata\noutput: %s", stdout)
	}
}

func TestE2E_TextOutputContainsPermissionSummary(t *testing.T) {
	stdout, _, _, err := runScan(t, "scan", "--no-color", "../../testdata/malicious/credential-theft")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Malicious scans with permissions should include a permission summary.
	if !strings.Contains(stdout, "filesystem") && !strings.Contains(stdout, "network") {
		t.Errorf("output missing permission summary\noutput: %s", stdout)
	}
}

func TestE2E_TextOutputPermissionSummary(t *testing.T) {
	stdout, _, _, err := runScan(t, "scan", "--no-color", "../../testdata/malicious/credential-theft")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// credential-theft has permissions → "Permissions:" summary line.
	if !strings.Contains(stdout, "Permissions:") {
		t.Errorf("output missing 'Permissions:' summary line\noutput: %s", stdout)
	}
}

// --- E2E: Scoring / Confidence ---

func TestE2E_CorroboratingSignalsBoostConfidence(t *testing.T) {
	// credential-theft has SD-004 + SD-007 which are corroborating → HIGH confidence.
	result := runScanJSON(t, "../../testdata/malicious/credential-theft")

	highConfCount := 0
	for _, f := range result.Findings {
		if f.Confidence == model.ConfidenceHigh {
			highConfCount++
		}
	}
	if highConfCount == 0 {
		t.Error("expected at least one HIGH confidence finding from corroborating signals (SD-004 + SD-007)")
	}
}

func TestE2E_ShellInjectionIsolatedLowerConfidence(t *testing.T) {
	// shell-injection has only SD-001 findings (no corroborating supply chain).
	result := runScanJSON(t, "../../testdata/malicious/shell-injection")

	for _, f := range result.Findings {
		if f.RuleID == "SD-001" && f.Confidence == model.ConfidenceHigh {
			// SD-001 alone (without SD-009/SD-010) should not be HIGH unless
			// there are 3+ distinct rules. Only fail if unexpected.
			ids := findingRuleIDs(result.Findings)
			if len(ids) < 3 {
				t.Errorf("SD-001 has HIGH confidence without corroborating signals and <3 distinct rules")
			}
		}
	}
}

// --- E2E: Fail-On Across Fixtures ---

func TestE2E_FailOnInfo_AllMaliciousExit2(t *testing.T) {
	fixtures := []string{
		"../../testdata/malicious/credential-theft",
		"../../testdata/malicious/exfiltration",
		"../../testdata/malicious/persistence",
		"../../testdata/malicious/prompt-injection",
		"../../testdata/malicious/shell-injection",
		"../../testdata/malicious/supply-chain",
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			_, _, code, err := runScan(t, "scan", "--no-color", "--fail-on", "info", fixture)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != 2 {
				t.Errorf("expected exit code 2 with --fail-on info, got %d", code)
			}
		})
	}
}

// --- E2E: Deterministic Output ---

// --- E2E: Context Expected & Override Tests (Story 5.4) ---

func TestE2E_ContextExpected_TextOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/run.sh", []byte(sd007Content), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := writeConfigFile(t, "rules:\n  SD-007:\n    context: expected\n")

	stdout, _, code, err := runScan(t, "scan", "--no-color", "--config", configPath, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "(expected)") {
		t.Errorf("expected '(expected)' in text output for context: expected rule, got: %s", stdout)
	}
	// Context: expected keeps the finding but lowers it below the default critical threshold.
	if code != 1 {
		t.Errorf("expected exit code 1 (finding remains, but context: expected lowers EffSeverity to INFO), got %d", code)
	}
}

func TestE2E_ContextExpected_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/run.sh", []byte(sd007Content), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := writeConfigFile(t, "rules:\n  SD-007:\n    context: expected\n")

	result := runScanJSON(t, dir, "--config", configPath)
	finding := findFindingByRule(t, result.Findings, "SD-007")
	if finding.EffSeverity != model.SeverityInfo {
		t.Errorf("expected effective_severity INFO for SD-007 with context override, got %v", finding.EffSeverity)
	}

	found := false
	for _, co := range result.ConfigOverrides {
		if co.RuleID == "SD-007" && co.Field == "context" && co.Original == "" && co.Override == "expected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected config_overrides to contain {rule_id: SD-007, field: context, original: '', override: 'expected'}, got: %+v", result.ConfigOverrides)
	}
}

func TestE2E_SeverityOverride_StillWorks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/run.sh", []byte(sd007Content), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := writeConfigFile(t, "rules:\n  SD-007:\n    severity: medium\n")

	result := runScanJSON(t, dir, "--config", configPath)

	finding := findFindingByRule(t, result.Findings, "SD-007")
	if finding.EffSeverity != model.SeverityMedium {
		t.Errorf("expected effective_severity MEDIUM for SD-007 with severity override, got %v", finding.EffSeverity)
	}
}

func TestE2E_ContextAndSeverity_ContextWins(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/run.sh", []byte(sd007Content), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := writeConfigFile(t, "rules:\n  SD-007:\n    severity: medium\n    context: expected\n")

	result := runScanJSON(t, dir, "--config", configPath)

	finding := findFindingByRule(t, result.Findings, "SD-007")
	if finding.EffSeverity != model.SeverityInfo {
		t.Errorf("expected effective_severity INFO when both severity and context set (context wins), got %v", finding.EffSeverity)
	}
}

func TestE2E_DeterministicJSONOutput(t *testing.T) {
	// Running the same scan twice should produce identical JSON output.
	result1 := runScanJSON(t, "../../testdata/malicious/credential-theft")
	result2 := runScanJSON(t, "../../testdata/malicious/credential-theft")

	if len(result1.Findings) != len(result2.Findings) {
		t.Fatalf("findings count differs: %d vs %d", len(result1.Findings), len(result2.Findings))
	}

	for i := range result1.Findings {
		f1, f2 := result1.Findings[i], result2.Findings[i]
		if f1.RuleID != f2.RuleID || f1.FilePath != f2.FilePath || f1.Line != f2.Line {
			t.Errorf("finding[%d] differs: %s:%s:%d vs %s:%s:%d",
				i, f1.RuleID, f1.FilePath, f1.Line, f2.RuleID, f2.FilePath, f2.Line)
		}
	}
}
