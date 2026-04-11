package model

import (
	"encoding/json"
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "CRITICAL"},
		{SeverityHigh, "HIGH"},
		{SeverityMedium, "MEDIUM"},
		{SeverityLow, "LOW"},
		{SeverityInfo, "INFO"},
	}

	for _, tt := range tests {
		got := tt.sev.String()
		if got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(tt.sev), got, tt.want)
		}
	}
}

func TestConfidenceString(t *testing.T) {
	tests := []struct {
		conf Confidence
		want string
	}{
		{ConfidenceHigh, "HIGH"},
		{ConfidenceMedium, "MEDIUM"},
		{ConfidenceLow, "LOW"},
	}

	for _, tt := range tests {
		got := tt.conf.String()
		if got != tt.want {
			t.Errorf("Confidence(%d).String() = %q, want %q", int(tt.conf), got, tt.want)
		}
	}
}

func TestSeverityMarshalJSON(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, `"CRITICAL"`},
		{SeverityHigh, `"HIGH"`},
		{SeverityMedium, `"MEDIUM"`},
		{SeverityLow, `"LOW"`},
		{SeverityInfo, `"INFO"`},
	}
	for _, tt := range tests {
		got, err := json.Marshal(tt.sev)
		if err != nil {
			t.Fatalf("Severity(%d).MarshalJSON() error: %v", int(tt.sev), err)
		}
		if string(got) != tt.want {
			t.Errorf("Severity(%d) JSON = %s, want %s", int(tt.sev), got, tt.want)
		}
	}
}

func TestSeverityUnmarshalJSON(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{`"CRITICAL"`, SeverityCritical},
		{`"HIGH"`, SeverityHigh},
		{`"MEDIUM"`, SeverityMedium},
		{`"LOW"`, SeverityLow},
		{`"INFO"`, SeverityInfo},
	}
	for _, tt := range tests {
		var got Severity
		if err := json.Unmarshal([]byte(tt.input), &got); err != nil {
			t.Fatalf("UnmarshalJSON(%s) error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("UnmarshalJSON(%s) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestConfidenceMarshalJSON(t *testing.T) {
	tests := []struct {
		conf Confidence
		want string
	}{
		{ConfidenceHigh, `"HIGH"`},
		{ConfidenceMedium, `"MEDIUM"`},
		{ConfidenceLow, `"LOW"`},
	}
	for _, tt := range tests {
		got, err := json.Marshal(tt.conf)
		if err != nil {
			t.Fatalf("Confidence(%d).MarshalJSON() error: %v", int(tt.conf), err)
		}
		if string(got) != tt.want {
			t.Errorf("Confidence(%d) JSON = %s, want %s", int(tt.conf), got, tt.want)
		}
	}
}

func TestConfidenceUnmarshalJSON(t *testing.T) {
	tests := []struct {
		input string
		want  Confidence
	}{
		{`"HIGH"`, ConfidenceHigh},
		{`"MEDIUM"`, ConfidenceMedium},
		{`"LOW"`, ConfidenceLow},
	}
	for _, tt := range tests {
		var got Confidence
		if err := json.Unmarshal([]byte(tt.input), &got); err != nil {
			t.Fatalf("UnmarshalJSON(%s) error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("UnmarshalJSON(%s) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input   string
		want    Severity
		wantErr bool
	}{
		{"critical", SeverityCritical, false},
		{"high", SeverityHigh, false},
		{"medium", SeverityMedium, false},
		{"low", SeverityLow, false},
		{"info", SeverityInfo, false},
		{"CRITICAL", SeverityCritical, false},
		{"  High  ", SeverityHigh, false},
		{"extreme", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseSeverity(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseSeverity(%q) expected error, got %v", tt.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSeverity(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestScanResultHasSchemaVersion(t *testing.T) {
	r := ScanResult{SchemaVersion: "1.1"}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["schema_version"]; !ok {
		t.Error("schema_version field missing from JSON")
	} else if v != "1.1" {
		t.Errorf("schema_version = %v, want 1.1", v)
	}
}

func TestScanResultHasConfigOverrides(t *testing.T) {
	r := ScanResult{
		SchemaVersion: "1.1",
		ConfigOverrides: []ConfigOverride{
			{RuleID: "SD-007", Field: "severity", Original: "HIGH", Override: "MEDIUM"},
		},
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
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
