package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// --- JSON golden file tests (Story 5.4) ---

func TestJSONReporter_Golden_CleanScan(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		Findings:        []model.Finding{},
		Permissions:     []model.Permission{{Type: "filesystem", Details: []string{"reads local files"}}},
		FileCount:       12,
		RuleCount:       14,
		Version:         "0.1.0-dev",
		Checksum:        "abc123",
		SchemaVersion:   "1.1",
		ConfigOverrides: []model.ConfigOverride{},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !json.Valid([]byte(got)) {
		t.Fatalf("output is not valid JSON: %s", got)
	}
	goldenTest(t, "json_clean", got)
}

func TestJSONReporter_Golden_WithFindings(t *testing.T) {
	r := &JSONReporter{}
	result := goldenFindingsResult()
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !json.Valid([]byte(got)) {
		t.Fatalf("output is not valid JSON: %s", got)
	}
	// Verify snake_case field names
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	for key := range m {
		if key != strings.ToLower(key) {
			t.Errorf("non-snake_case top-level key: %q", key)
		}
	}
	goldenTest(t, "json_findings", got)
}

func TestJSONReporter_Golden_WithOverrides(t *testing.T) {
	r := &JSONReporter{}
	result := goldenFindingsResult()
	// Add both severity and context overrides
	for i := range result.Findings {
		if result.Findings[i].RuleID == "SD-007" {
			result.Findings[i].EffSeverity = model.SeverityInfo
		}
	}
	result.ConfigOverrides = []model.ConfigOverride{
		{RuleID: "SD-007", Field: "context", Original: "", Override: "expected"},
		{RuleID: "SD-008", Field: "severity", Original: "MEDIUM", Override: "LOW"},
	}
	result.Findings[2].EffSeverity = model.SeverityLow
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !json.Valid([]byte(got)) {
		t.Fatalf("output is not valid JSON: %s", got)
	}
	goldenTest(t, "json_overrides", got)
}

func TestJSONReporter_CleanScan(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		FileCount:     12,
		RuleCount:     14,
		Version:       "0.1.0-dev",
		Checksum:      "abc123",
		SchemaVersion: "1.1",
	}

	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Fatalf("output is not valid JSON: %s", buf.String())
	}

	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}

	// findings should be [] not null
	findings, ok := m["findings"].([]interface{})
	if !ok {
		t.Fatal("findings is not an array")
	}
	if len(findings) != 0 {
		t.Errorf("expected empty findings, got %d", len(findings))
	}

	// Check metadata fields
	if m["files_scanned"] != float64(12) {
		t.Errorf("files_scanned = %v, want 12", m["files_scanned"])
	}
	if m["rules_applied"] != float64(14) {
		t.Errorf("rules_applied = %v, want 14", m["rules_applied"])
	}
	if m["version"] != "0.1.0-dev" {
		t.Errorf("version = %v, want 0.1.0-dev", m["version"])
	}
	if m["schema_version"] != "1.1" {
		t.Errorf("schema_version = %v, want 1.1", m["schema_version"])
	}
}

func TestJSONReporter_WithFindings(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		FileCount:     5,
		RuleCount:     10,
		Version:       "0.1.0-dev",
		SchemaVersion: "1.1",
		Findings: []model.Finding{
			{
				RuleID:      "SD-004",
				RuleName:    "Credential File Access",
				Severity:    model.SeverityCritical,
				EffSeverity: model.SeverityCritical,
				Category:    "Access Control",
				Description: "reads ~/.aws/credentials",
				FilePath:    "install.sh",
				Line:        12,
				Confidence:  model.ConfidenceHigh,
				Remediation: "Remove credential file access",
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}

	var parsed model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}

	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed.Findings))
	}

	f := parsed.Findings[0]
	if f.RuleID != "SD-004" {
		t.Errorf("rule_id = %q, want SD-004", f.RuleID)
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want CRITICAL", f.Severity)
	}
	if f.EffSeverity != model.SeverityCritical {
		t.Errorf("effective_severity = %v, want CRITICAL", f.EffSeverity)
	}
	if f.FilePath != "install.sh" {
		t.Errorf("file_path = %q, want install.sh", f.FilePath)
	}
	if f.Line != 12 {
		t.Errorf("line = %d, want 12", f.Line)
	}
	if f.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %v, want HIGH", f.Confidence)
	}
}

func TestJSONReporter_OverriddenSeverity(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		SchemaVersion: "1.1",
		Findings: []model.Finding{
			{
				RuleID:      "SD-001",
				Severity:    model.SeverityCritical,
				EffSeverity: model.SeverityMedium,
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}

	// Parse into raw map to check string values
	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}

	findings := m["findings"].([]interface{})
	f := findings[0].(map[string]interface{})

	if f["severity"] != "CRITICAL" {
		t.Errorf("severity = %v, want CRITICAL", f["severity"])
	}
	if f["effective_severity"] != "MEDIUM" {
		t.Errorf("effective_severity = %v, want MEDIUM", f["effective_severity"])
	}
}

func TestJSONReporter_WithPermissions(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		SchemaVersion: "1.1",
		Permissions: []model.Permission{
			{Type: "filesystem", Details: []string{"reads local files"}},
			{Type: "network", Details: []string{"api.example.com"}},
		},
	}

	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}

	var parsed model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}

	if len(parsed.Permissions) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(parsed.Permissions))
	}
	if parsed.Permissions[0].Type != "filesystem" {
		t.Errorf("permission type = %q, want filesystem", parsed.Permissions[0].Type)
	}
	if parsed.Permissions[1].Type != "network" {
		t.Errorf("permission type = %q, want network", parsed.Permissions[1].Type)
	}
}

func TestJSONReporter_NilSlicesProduceEmptyArrays(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		SchemaVersion: "1.1",
		// Findings and Permissions are nil
	}

	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}

	raw := buf.String()
	if strings.Contains(raw, "null") {
		t.Errorf("JSON contains null, expected empty arrays: %s", raw)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}

	if _, ok := m["findings"].([]interface{}); !ok {
		t.Error("findings should be an array, not null")
	}
	if _, ok := m["permissions"].([]interface{}); !ok {
		t.Error("permissions should be an array, not null")
	}
	if _, ok := m["config_overrides"].([]interface{}); !ok {
		t.Error("config_overrides should be an array, not null")
	}
	if _, ok := m["warnings"].([]interface{}); !ok {
		t.Error("warnings should be an array, not null")
	}
}

func TestJSONReporter_ConfigOverrides(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		SchemaVersion: "1.1",
		ConfigOverrides: []model.ConfigOverride{
			{RuleID: "SD-007", Field: "severity", Original: "HIGH", Override: "MEDIUM"},
		},
	}

	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}

	overrides, ok := m["config_overrides"].([]interface{})
	if !ok {
		t.Fatal("config_overrides is not an array")
	}
	if len(overrides) != 1 {
		t.Fatalf("expected 1 config override, got %d", len(overrides))
	}
	entry := overrides[0].(map[string]interface{})
	if entry["rule_id"] != "SD-007" {
		t.Errorf("rule_id = %v, want SD-007", entry["rule_id"])
	}
	if entry["field"] != "severity" {
		t.Errorf("field = %v, want severity", entry["field"])
	}
	if entry["original"] != "HIGH" {
		t.Errorf("original = %v, want HIGH", entry["original"])
	}
	if entry["override"] != "MEDIUM" {
		t.Errorf("override = %v, want MEDIUM", entry["override"])
	}
}

func TestJSONReporter_NilConfigOverridesProduceEmptyArray(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		SchemaVersion: "1.1",
		// ConfigOverrides is nil
	}

	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}

	overrides, ok := m["config_overrides"].([]interface{})
	if !ok {
		t.Fatal("config_overrides should be an array, not null")
	}
	if len(overrides) != 0 {
		t.Errorf("expected empty config_overrides array, got %d items", len(overrides))
	}
}

func TestJSONReporter_SnakeCaseFieldNames(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		SchemaVersion: "1.1",
		FileCount:     1,
		RuleCount:     1,
		Version:       "0.1.0-dev",
		Findings: []model.Finding{
			{
				RuleID:      "SD-001",
				RuleName:    "Test",
				Severity:    model.SeverityHigh,
				EffSeverity: model.SeverityHigh,
				Category:    "Test",
				Description: "test",
				FilePath:    "test.sh",
				Line:        1,
				Confidence:  model.ConfidenceHigh,
				Remediation: "fix it",
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}

	// Check top-level keys
	expectedTopLevel := []string{"findings", "permissions", "config_overrides", "files_scanned", "rules_applied", "version", "ruleset_checksum", "schema_version", "warnings"}
	for _, key := range expectedTopLevel {
		if _, ok := m[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}

	// Check finding keys
	findings := m["findings"].([]interface{})
	f := findings[0].(map[string]interface{})
	expectedFindingKeys := []string{"rule_id", "rule_name", "severity", "effective_severity", "category", "description", "file_path", "line", "confidence", "diagnosis", "remediation"}
	for _, key := range expectedFindingKeys {
		if _, ok := f[key]; !ok {
			t.Errorf("missing finding key %q", key)
		}
	}

	// Verify no camelCase keys — flag any key containing uppercase that isn't snake_case
	for key := range m {
		if key != strings.ToLower(key) {
			t.Errorf("non-snake_case top-level key: %q", key)
		}
	}
}

func TestJSONReporter_NoANSICodes(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		SchemaVersion: "1.1",
		Findings: []model.Finding{
			{
				RuleID:      "SD-001",
				Severity:    model.SeverityCritical,
				EffSeverity: model.SeverityCritical,
				Description: "test finding",
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(buf.String(), "\033[") {
		t.Error("JSON output contains ANSI escape codes")
	}
}

func TestJSONReporter_SingleJSONObject(t *testing.T) {
	r := &JSONReporter{}
	result := model.ScanResult{
		SchemaVersion: "1.1",
		FileCount:     5,
	}

	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}

	output := strings.TrimSpace(buf.String())

	// Should start with { and end with }
	if !strings.HasPrefix(output, "{") {
		t.Errorf("output does not start with '{': %s", output[:min(50, len(output))])
	}
	if !strings.HasSuffix(output, "}") {
		t.Errorf("output does not end with '}': %s", output[max(0, len(output)-50):])
	}

	// Should be exactly one JSON object (Unmarshal succeeds, no leftover)
	dec := json.NewDecoder(strings.NewReader(output))
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	// Check there's no extra content after the JSON object
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		t.Error("output contains extra content after JSON object")
	}
}
func TestJSONReporterEmitsAxesField(t *testing.T) {
	r := &JSONReporter{}
	res := model.ScanResult{
		Findings: []model.Finding{
			{RuleID: "SD-017", Severity: model.SeverityHigh, EffSeverity: model.SeverityHigh, Axis: axes.PermissionHygiene},
		},
		Axes: map[axes.Axis]model.AxisResult{
			axes.Security:          {Grade: axes.GradeA, Rationale: "no findings on this axis"},
			axes.PermissionHygiene: {Grade: axes.GradeD, Rationale: "High-severity issue"},
			axes.Transparency:      {Grade: axes.GradeA, Rationale: "no findings on this axis"},
			axes.Quality:           {Grade: axes.GradeA, Rationale: "no findings on this axis"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(res, &buf); err != nil {
		t.Fatalf("Report: %v", err)
	}
	var parsed struct {
		Axes map[string]struct {
			Grade     string `json:"grade"`
			Rationale string `json:"rationale"`
		} `json:"axes"`
		Findings []struct {
			Axis string `json:"axis"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\noutput: %s", err, buf.String())
	}
	if parsed.Axes["security"].Grade != "A" {
		t.Errorf("axes.security.grade = %q, want A", parsed.Axes["security"].Grade)
	}
	if parsed.Axes["permission_hygiene"].Grade != "D" {
		t.Errorf("axes.permission_hygiene.grade = %q, want D", parsed.Axes["permission_hygiene"].Grade)
	}
	if len(parsed.Findings) != 1 || parsed.Findings[0].Axis != "permission_hygiene" {
		t.Errorf("findings[0].axis = %q, want permission_hygiene", parsed.Findings[0].Axis)
	}
}
