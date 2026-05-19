package model

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/axes"
)

// Severity levels — ordered from most to least severe.
type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
	SeverityInfo
)

var severityNames = [...]string{
	"CRITICAL",
	"HIGH",
	"MEDIUM",
	"LOW",
	"INFO",
}

func (s Severity) String() string {
	if int(s) >= 0 && int(s) < len(severityNames) {
		return severityNames[s]
	}
	return fmt.Sprintf("Severity(%d)", int(s))
}

// ParseSeverity converts a lowercase string to a Severity constant.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	case "info":
		return SeverityInfo, nil
	default:
		return 0, fmt.Errorf("unknown severity %q", s)
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	for i, n := range severityNames {
		if n == name {
			*s = Severity(i)
			return nil
		}
	}
	return fmt.Errorf("unknown severity: %q", name)
}

// Confidence levels.
type Confidence int

const (
	ConfidenceHigh Confidence = iota
	ConfidenceMedium
	ConfidenceLow
)

var confidenceNames = [...]string{
	"HIGH",
	"MEDIUM",
	"LOW",
}

func (c Confidence) String() string {
	if int(c) >= 0 && int(c) < len(confidenceNames) {
		return confidenceNames[c]
	}
	return fmt.Sprintf("Confidence(%d)", int(c))
}

func (c Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *Confidence) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	for i, n := range confidenceNames {
		if n == name {
			*c = Confidence(i)
			return nil
		}
	}
	return fmt.Errorf("unknown confidence: %q", name)
}

// Finding — flat struct, shared by rules, scorer, permission extractor, reporters.
type Finding struct {
	RuleID      string     `json:"rule_id"`
	RuleName    string     `json:"rule_name"`
	Severity    Severity   `json:"severity"`
	EffSeverity Severity   `json:"effective_severity"`
	Category    string     `json:"category"`
	Description string     `json:"description"`
	FilePath    string     `json:"file_path"`
	Line        int        `json:"line"`
	Confidence  Confidence `json:"confidence"`
	Diagnosis   string     `json:"diagnosis"`
	Remediation string     `json:"remediation"`
	Axis        axes.Axis  `json:"axis,omitempty"`
}

// ConfigOverride — records a user-configured severity adjustment for a rule.
type ConfigOverride struct {
	RuleID   string `json:"rule_id"`
	Field    string `json:"field"`
	Original string `json:"original"`
	Override string `json:"override"`
}

// ScanResult — top-level result from a scan.
type ScanResult struct {
	Findings        []Finding                `json:"findings"`
	Permissions     []Permission             `json:"permissions"`
	ConfigOverrides []ConfigOverride         `json:"config_overrides"`
	FileCount       int                      `json:"files_scanned"`
	RuleCount       int                      `json:"rules_applied"`
	Version         string                   `json:"version"`
	Checksum        string                   `json:"ruleset_checksum"`
	SchemaVersion   string                   `json:"schema_version"`
	Axes            map[axes.Axis]AxisResult `json:"axes,omitempty"`
}

// Permission — inferred capability.
type Permission struct {
	Type    string   `json:"type"`
	Details []string `json:"details"`
}

// AxisResult — per-axis grade from the SP-1 multi-axis trust score work.
type AxisResult struct {
	Grade           axes.Grade      `json:"grade"`
	Rationale       string          `json:"rationale"`
	DrivingFindings []DrivingFinding `json:"driving_findings"`
}

// DrivingFinding — a rule ID and finding count that contributed to an
// axis grade. Aggregated from the max-severity findings on that axis.
type DrivingFinding struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

// FileContext — metadata about a discovered file.
type FileContext struct {
	Path    string
	Ext     string
	Content []byte
}
