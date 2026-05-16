package scorer

import (
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/config"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func makeFind(ruleID, filePath string) model.Finding {
	return model.Finding{
		RuleID:      ruleID,
		FilePath:    filePath,
		Severity:    model.SeverityHigh,
		EffSeverity: model.SeverityHigh,
		Confidence:  model.ConfidenceMedium,
		Line:        1,
	}
}

func TestScore_EmptyFindings(t *testing.T) {
	result := Score([]model.Finding{})
	if len(result) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result))
	}
}

func TestScore_NilFindings(t *testing.T) {
	result := Score(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestScore_IsolatedFinding(t *testing.T) {
	findings := []model.Finding{makeFind("SD-007", "file.py")}
	result := Score(findings)

	if result[0].Confidence != model.ConfidenceLow {
		t.Errorf("expected ConfidenceLow, got %s", result[0].Confidence)
	}
	if !strings.Contains(result[0].Diagnosis, "Possible") {
		t.Errorf("expected 'Possible' in diagnosis, got %q", result[0].Diagnosis)
	}
	if !strings.Contains(result[0].Diagnosis, "No corroborating signals found") {
		t.Errorf("expected 'No corroborating signals found' in diagnosis, got %q", result[0].Diagnosis)
	}
}

func TestScore_CorroboratedPair(t *testing.T) {
	findings := []model.Finding{
		makeFind("SD-004", "steal.py"),
		makeFind("SD-007", "steal.py"),
	}
	result := Score(findings)

	for _, f := range result {
		if f.Confidence != model.ConfidenceHigh {
			t.Errorf("rule %s: expected ConfidenceHigh, got %s", f.RuleID, f.Confidence)
		}
	}
	// SD-007 should mention corroboration by SD-004
	if !strings.Contains(result[1].Diagnosis, "corroborated by SD-004") {
		t.Errorf("SD-007 diagnosis should mention corroboration by SD-004, got %q", result[1].Diagnosis)
	}
}

func TestScore_ThreeRulesInFile(t *testing.T) {
	findings := []model.Finding{
		makeFind("SD-001", "attack.sh"),
		makeFind("SD-007", "attack.sh"),
		makeFind("SD-008", "attack.sh"),
	}
	result := Score(findings)

	for _, f := range result {
		if f.Confidence != model.ConfidenceHigh {
			t.Errorf("rule %s: expected ConfidenceHigh with 3+ rules in file, got %s", f.RuleID, f.Confidence)
		}
	}
}

func TestScore_TwoRulesNoCorroboration(t *testing.T) {
	findings := []model.Finding{
		makeFind("SD-005", "config.yaml"),
		makeFind("SD-008", "config.yaml"),
	}
	result := Score(findings)

	for _, f := range result {
		if f.Confidence != model.ConfidenceMedium {
			t.Errorf("rule %s: expected ConfidenceMedium (2 rules, no corroboration pair), got %s", f.RuleID, f.Confidence)
		}
	}
}

func TestScore_MultipleFiles(t *testing.T) {
	findings := []model.Finding{
		makeFind("SD-004", "file1.py"),
		makeFind("SD-007", "file2.py"),
	}
	result := Score(findings)

	for _, f := range result {
		if f.Confidence != model.ConfidenceLow {
			t.Errorf("rule %s: expected ConfidenceLow (different files), got %s", f.RuleID, f.Confidence)
		}
	}
}

func TestScore_DiagnosisSD007(t *testing.T) {
	findings := []model.Finding{makeFind("SD-007", "net.py")}
	result := Score(findings)

	diag := result[0].Diagnosis
	if !strings.Contains(diag, "data exfiltration") {
		t.Errorf("SD-007 diagnosis should mention 'data exfiltration', got %q", diag)
	}
	if !strings.Contains(diag, "legitimate API call") {
		t.Errorf("SD-007 diagnosis should mention 'legitimate API call', got %q", diag)
	}
}

func TestScore_DiagnosisHighConfidence(t *testing.T) {
	findings := []model.Finding{
		makeFind("SD-004", "exfil.py"),
		makeFind("SD-007", "exfil.py"),
	}
	result := Score(findings)

	diag := result[1].Diagnosis // SD-007
	if !strings.Contains(diag, "Likely") {
		t.Errorf("high confidence diagnosis should start with 'Likely', got %q", diag)
	}
	if !strings.Contains(diag, "corroborated by") {
		t.Errorf("high confidence diagnosis should mention 'corroborated by', got %q", diag)
	}
}

func TestScore_DiagnosisLowConfidence(t *testing.T) {
	findings := []model.Finding{makeFind("SD-007", "solo.py")}
	result := Score(findings)

	diag := result[0].Diagnosis
	if !strings.Contains(diag, "Possible") {
		t.Errorf("low confidence diagnosis should contain 'Possible', got %q", diag)
	}
	if !strings.Contains(diag, "No corroborating signals found") {
		t.Errorf("low confidence diagnosis should mention 'No corroborating signals found', got %q", diag)
	}
}

func TestScore_Deterministic(t *testing.T) {
	input := func() []model.Finding {
		return []model.Finding{
			makeFind("SD-004", "file.py"),
			makeFind("SD-007", "file.py"),
			makeFind("SD-001", "other.sh"),
		}
	}

	r1 := Score(input())
	r2 := Score(input())

	if len(r1) != len(r2) {
		t.Fatalf("non-deterministic finding count: %d vs %d", len(r1), len(r2))
	}
	for i := range r1 {
		if r1[i] != r2[i] {
			t.Errorf("non-deterministic finding at index %d: %+v vs %+v", i, r1[i], r2[i])
		}
	}
}

func TestScore_EffSeverityUnchanged(t *testing.T) {
	findings := []model.Finding{
		makeFind("SD-004", "file.py"),
		makeFind("SD-007", "file.py"),
	}
	result := Score(findings)

	for _, f := range result {
		if f.EffSeverity != f.Severity {
			t.Errorf("rule %s: EffSeverity (%s) should equal Severity (%s)", f.RuleID, f.EffSeverity, f.Severity)
		}
	}
}

// --- ApplyOverrides tests (Task 7) ---

func boolPtr(b bool) *bool { return &b }

func TestApplyOverrides_NilConfig(t *testing.T) {
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	result, _ := ApplyOverrides(findings, nil)
	if result[0].EffSeverity != model.SeverityHigh {
		t.Errorf("expected EffSeverity unchanged (HIGH), got %s", result[0].EffSeverity)
	}
}

func TestApplyOverrides_EmptyRules(t *testing.T) {
	cfg := &config.Config{Rules: map[string]config.RuleCfg{}}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	result, _ := ApplyOverrides(findings, cfg)
	if result[0].EffSeverity != model.SeverityHigh {
		t.Errorf("expected EffSeverity unchanged (HIGH), got %s", result[0].EffSeverity)
	}
}

func TestApplyOverrides_SeverityOverride(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Severity: "medium"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	result, _ := ApplyOverrides(findings, cfg)
	if result[0].EffSeverity != model.SeverityMedium {
		t.Errorf("expected EffSeverity MEDIUM, got %s", result[0].EffSeverity)
	}
	// Original Severity must remain unchanged.
	if result[0].Severity != model.SeverityHigh {
		t.Errorf("expected original Severity HIGH unchanged, got %s", result[0].Severity)
	}
}

func TestApplyOverrides_MultipleRules(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Severity: "medium"},
			"SD-001": {Severity: "low"},
		},
	}
	findings := []model.Finding{
		makeFind("SD-007", "f.py"),
		makeFind("SD-001", "f.py"),
	}
	result, _ := ApplyOverrides(findings, cfg)
	if result[0].EffSeverity != model.SeverityMedium {
		t.Errorf("SD-007: expected MEDIUM, got %s", result[0].EffSeverity)
	}
	if result[1].EffSeverity != model.SeverityLow {
		t.Errorf("SD-001: expected LOW, got %s", result[1].EffSeverity)
	}
}

func TestApplyOverrides_RuleNotInConfig(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-999": {Severity: "low"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	result, _ := ApplyOverrides(findings, cfg)
	// SD-007 not in config → EffSeverity unchanged.
	if result[0].EffSeverity != model.SeverityHigh {
		t.Errorf("expected EffSeverity unchanged (HIGH), got %s", result[0].EffSeverity)
	}
}

func TestApplyOverrides_EnabledFalseNoEffect(t *testing.T) {
	// Enabled: false should NOT affect ApplyOverrides — that's Scanner's job.
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Enabled: boolPtr(false), Severity: "medium"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	result, _ := ApplyOverrides(findings, cfg)
	// Even with enabled: false, ApplyOverrides still applies severity override.
	if result[0].EffSeverity != model.SeverityMedium {
		t.Errorf("expected EffSeverity MEDIUM (override applied regardless of enabled), got %s", result[0].EffSeverity)
	}
}

func TestApplyOverrides_ReturnsOverrideMetadata(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Severity: "medium"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	_, overrides := ApplyOverrides(findings, cfg)
	if len(overrides) != 1 {
		t.Fatalf("expected 1 override, got %d", len(overrides))
	}
	o := overrides[0]
	if o.RuleID != "SD-007" {
		t.Errorf("override RuleID = %q, want SD-007", o.RuleID)
	}
	if o.Field != "severity" {
		t.Errorf("override Field = %q, want severity", o.Field)
	}
	if o.Original != "HIGH" {
		t.Errorf("override Original = %q, want HIGH", o.Original)
	}
	if o.Override != "MEDIUM" {
		t.Errorf("override Override = %q, want MEDIUM", o.Override)
	}
}

func TestApplyOverrides_DeduplicatesOverrideMetadataPerRule(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Severity: "medium"},
		},
	}
	findings := []model.Finding{
		makeFind("SD-007", "a.sh"),
		makeFind("SD-007", "b.sh"),
	}

	result, overrides := ApplyOverrides(findings, cfg)
	if len(overrides) != 1 {
		t.Fatalf("expected 1 override for repeated rule, got %d", len(overrides))
	}
	for i, finding := range result {
		if finding.EffSeverity != model.SeverityMedium {
			t.Errorf("finding[%d] EffSeverity = %s, want %s", i, finding.EffSeverity, model.SeverityMedium)
		}
	}
}

func TestApplyOverrides_NoOpSeverityDoesNotEmitMetadata(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Severity: "high"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}

	result, overrides := ApplyOverrides(findings, cfg)
	if len(overrides) != 0 {
		t.Fatalf("expected 0 overrides for no-op severity change, got %d", len(overrides))
	}
	if result[0].EffSeverity != model.SeverityHigh {
		t.Errorf("expected EffSeverity unchanged (HIGH), got %s", result[0].EffSeverity)
	}
}

func TestApplyOverrides_NilConfig_NoOverrideMetadata(t *testing.T) {
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	_, overrides := ApplyOverrides(findings, nil)
	if len(overrides) != 0 {
		t.Errorf("expected 0 overrides with nil config, got %d", len(overrides))
	}
}

func TestApplyOverrides_NoMatchingRules_NoOverrideMetadata(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-999": {Severity: "low"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	_, overrides := ApplyOverrides(findings, cfg)
	if len(overrides) != 0 {
		t.Errorf("expected 0 overrides when no rules match, got %d", len(overrides))
	}
}

// --- Context override tests (Story 5.3) ---

func TestApplyOverrides_ContextExpected(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Context: "expected"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	result, _ := ApplyOverrides(findings, cfg)
	if result[0].EffSeverity != model.SeverityInfo {
		t.Errorf("expected EffSeverity INFO, got %s", result[0].EffSeverity)
	}
}

func TestApplyOverrides_ContextExpected_OriginalSeverityUnchanged(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Context: "expected"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	result, _ := ApplyOverrides(findings, cfg)
	if result[0].Severity != model.SeverityHigh {
		t.Errorf("expected original Severity HIGH unchanged, got %s", result[0].Severity)
	}
	if result[0].EffSeverity != model.SeverityInfo {
		t.Errorf("expected EffSeverity INFO, got %s", result[0].EffSeverity)
	}
}

func TestApplyOverrides_ContextAndSeverity_ContextWins(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Severity: "medium", Context: "expected"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	result, _ := ApplyOverrides(findings, cfg)
	if result[0].EffSeverity != model.SeverityInfo {
		t.Errorf("expected EffSeverity INFO (context wins over severity), got %s", result[0].EffSeverity)
	}
}

func TestApplyOverrides_ContextExpected_ConfigOverrideRecorded(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Context: "expected"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	_, overrides := ApplyOverrides(findings, cfg)
	if len(overrides) != 1 {
		t.Fatalf("expected 1 override, got %d", len(overrides))
	}
	o := overrides[0]
	if o.RuleID != "SD-007" {
		t.Errorf("override RuleID = %q, want SD-007", o.RuleID)
	}
	if o.Field != "context" {
		t.Errorf("override Field = %q, want context", o.Field)
	}
	if o.Original != "" {
		t.Errorf("override Original = %q, want empty", o.Original)
	}
	if o.Override != "expected" {
		t.Errorf("override Override = %q, want expected", o.Override)
	}
}

func TestApplyOverrides_ContextAndSeverity_BothOverridesRecorded(t *testing.T) {
	cfg := &config.Config{
		Rules: map[string]config.RuleCfg{
			"SD-007": {Severity: "medium", Context: "expected"},
		},
	}
	findings := []model.Finding{makeFind("SD-007", "f.py")}
	_, overrides := ApplyOverrides(findings, cfg)
	if len(overrides) != 2 {
		t.Fatalf("expected 2 overrides (severity + context), got %d", len(overrides))
	}
	if overrides[0].Field != "severity" {
		t.Errorf("first override Field = %q, want severity", overrides[0].Field)
	}
	if overrides[1].Field != "context" {
		t.Errorf("second override Field = %q, want context", overrides[1].Field)
	}
}
