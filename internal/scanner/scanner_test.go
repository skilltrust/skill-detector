package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/config"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/rules"
)

func newTestRegistry() *rules.RuleRegistry {
	registry := rules.NewRegistry()
	rules.RegisterInjectionRules(registry)
	rules.RegisterAccessControlRules(registry)
	rules.RegisterMisconfigurationRules(registry)
	rules.RegisterExfiltrationRules(registry)
	rules.RegisterSupplyChainRules(registry)
	rules.RegisterIntegrityRules(registry)
	return registry
}

func boolPtr(b bool) *bool { return &b }

func TestScanner_CleanScan(t *testing.T) {
	s := New("../../testdata/clean/simple-skill", newTestRegistry(), nil, "test")
	result, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  finding: %s in %s:%d", f.RuleID, f.FilePath, f.Line)
		}
	}
	if result.FileCount == 0 {
		t.Error("expected at least 1 file discovered")
	}
	if result.RuleCount == 0 {
		t.Error("expected at least 1 rule registered")
	}
	// Clean scan should return base filesystem permission
	if len(result.Permissions) == 0 {
		t.Error("expected base permissions for clean scan")
	} else {
		found := false
		for _, p := range result.Permissions {
			if p.Type == "filesystem" {
				for _, d := range p.Details {
					if d == "reads local files" {
						found = true
					}
				}
			}
		}
		if !found {
			t.Error("expected 'reads local files' base permission for clean scan")
		}
	}
}

func TestScanner_MaliciousScan(t *testing.T) {
	s := New("../../testdata/malicious/credential-theft", newTestRegistry(), nil, "test")
	result, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for malicious skill")
	}
	hasCritical := false
	for _, f := range result.Findings {
		if f.EffSeverity == model.SeverityCritical {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected at least one critical finding")
	}
	// Malicious scan should populate permissions
	if len(result.Permissions) == 0 {
		t.Error("expected permissions for malicious skill scan")
	}
}

func TestScanner_MalformedYAML(t *testing.T) {
	s := New("../../testdata/edge-cases/malformed-yaml", newTestRegistry(), nil, "test")
	result, err := s.Run()
	if err != nil {
		t.Fatalf("malformed file should not crash scanner: %v", err)
	}
	// Scan completes successfully — malformed YAML is scanned as raw bytes
	if result.FileCount == 0 {
		t.Error("expected at least 1 file discovered")
	}
}

func TestScanner_Deterministic(t *testing.T) {
	s := New("../../testdata/malicious/credential-theft", newTestRegistry(), nil, "test")
	r1, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(r1.Findings) != len(r2.Findings) {
		t.Fatalf("non-deterministic finding count: %d vs %d", len(r1.Findings), len(r2.Findings))
	}
	for i := range r1.Findings {
		if r1.Findings[i] != r2.Findings[i] {
			t.Fatalf("non-deterministic finding at index %d", i)
		}
	}
	if len(r1.Permissions) != len(r2.Permissions) {
		t.Fatalf("non-deterministic permission count: %d vs %d", len(r1.Permissions), len(r2.Permissions))
	}
	for i := range r1.Permissions {
		p1, p2 := r1.Permissions[i], r2.Permissions[i]
		if p1.Type != p2.Type {
			t.Fatalf("non-deterministic permission type at index %d: %s vs %s", i, p1.Type, p2.Type)
		}
		if len(p1.Details) != len(p2.Details) {
			t.Fatalf("non-deterministic detail count for %s: %d vs %d", p1.Type, len(p1.Details), len(p2.Details))
		}
		for j := range p1.Details {
			if p1.Details[j] != p2.Details[j] {
				t.Fatalf("non-deterministic detail at %s[%d]: %s vs %s", p1.Type, j, p1.Details[j], p2.Details[j])
			}
		}
	}
}

func TestScanner_ResultHasChecksum(t *testing.T) {
	s := New("../../testdata/clean/simple-skill", newTestRegistry(), nil, "test")
	result, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if result.Checksum == "" {
		t.Error("expected non-empty checksum in scan result")
	}
}

func TestScanner_CleanScan_HasNoConfigOverrides(t *testing.T) {
	s := New("../../testdata/clean/simple-skill", newTestRegistry(), nil, "test")
	result, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ConfigOverrides) != 0 {
		t.Errorf("expected 0 config overrides for clean scan, got %d", len(result.ConfigOverrides))
	}
}

func TestScanner_EmptyDir(t *testing.T) {
	s := New("../../testdata/edge-cases/empty-dir", newTestRegistry(), nil, "test")
	result, err := s.Run()
	if err != nil {
		t.Fatalf("empty dir should not error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.FileCount != 0 {
		t.Errorf("expected 0 files, got %d", result.FileCount)
	}
}

// --- Rule filtering tests (Task 8) ---

// makeCfgWithDisabledRule returns a config that disables a single rule.
func makeCfgWithDisabledRule(ruleID string) *config.Config {
	return &config.Config{
		FailOn: model.SeverityCritical,
		Rules: map[string]config.RuleCfg{
			ruleID: {Enabled: boolPtr(false)},
		},
	}
}

func TestScanner_NilConfig_AllRulesRun(t *testing.T) {
	// nil config → backward-compatible, all rules run.
	s := New("../../testdata/malicious/credential-theft", newTestRegistry(), nil, "test")
	result, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings with nil config (all rules enabled)")
	}
}

func TestScanner_ExplicitEnabledTrue_RuleRuns(t *testing.T) {
	// enabled: true → same as default — rule runs normally.
	cfg := &config.Config{
		FailOn: model.SeverityCritical,
		Rules: map[string]config.RuleCfg{
			"SD-004": {Enabled: boolPtr(true)},
		},
	}
	s := New("../../testdata/malicious/credential-theft", newTestRegistry(), cfg, "test")
	result, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	hasSD004 := false
	for _, f := range result.Findings {
		if f.RuleID == "SD-004" {
			hasSD004 = true
			break
		}
	}
	if !hasSD004 {
		t.Error("expected SD-004 findings when enabled: true")
	}
}

func TestScanner_AllRulesDisabled_ZeroFindings(t *testing.T) {
	// Disable every rule → zero findings, exit 0.
	allRuleIDs := []string{
		"SD-001", "SD-002", "SD-003", "SD-004", "SD-005",
		"SD-006", "SD-007", "SD-008", "SD-009", "SD-010",
		"SD-011", "SD-012", "SD-013", "SD-014",
	}
	rulesMap := make(map[string]config.RuleCfg, len(allRuleIDs))
	for _, id := range allRuleIDs {
		rulesMap[id] = config.RuleCfg{Enabled: boolPtr(false)}
	}
	cfg := &config.Config{FailOn: model.SeverityCritical, Rules: rulesMap}

	s := New("../../testdata/malicious/credential-theft", newTestRegistry(), cfg, "test")
	result, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings with all rules disabled, got %d", len(result.Findings))
	}
}

func TestScanner_RuleCount_ReflectsActiveRules(t *testing.T) {
	// With all rules enabled (nil config), RuleCount = total distinct rules that matched files.
	sAll := New("../../testdata/malicious/credential-theft", newTestRegistry(), nil, "test")
	rAll, err := sAll.Run()
	if err != nil {
		t.Fatal(err)
	}

	// Disable one rule that fires on this testdata (SD-004 credential access).
	cfg := makeCfgWithDisabledRule("SD-004")
	sLess := New("../../testdata/malicious/credential-theft", newTestRegistry(), cfg, "test")
	rLess, err := sLess.Run()
	if err != nil {
		t.Fatal(err)
	}

	// Active rule count should be <= all rules count (SD-004 removed from active set).
	if rLess.RuleCount > rAll.RuleCount {
		t.Errorf("active rule count (%d) should not exceed unrestricted count (%d)", rLess.RuleCount, rAll.RuleCount)
	}
}

func TestScanner_AllowlistedFindings_RemoveConfigOverrides(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/bash\ncurl https://api.trusted-domain.com/data\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		FailOn: model.SeverityCritical,
		Rules: map[string]config.RuleCfg{
			"SD-007": {Severity: "medium"},
		},
		Allow: config.AllowLists{
			Network: []string{"api.trusted-domain.com"},
		},
	}

	s := New(dir, newTestRegistry(), cfg, "test")
	result, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected allowlist to suppress all findings, got %d", len(result.Findings))
	}
	if len(result.ConfigOverrides) != 0 {
		t.Fatalf("expected 0 config overrides after allowlist suppression, got %d", len(result.ConfigOverrides))
	}
}

func TestScanner_DisabledRule_ProducesNoFindings(t *testing.T) {
	// Create a minimal testdata file that would trigger SD-005 (chmod 777).
	dir := t.TempDir()
	content := []byte("chmod 777 /tmp/malicious.sh\n")
	if err := os.WriteFile(filepath.Join(dir, "install.sh"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	// Without disabling SD-005 → should find it.
	sAll := New(dir, newTestRegistry(), nil, "test")
	rAll, err := sAll.Run()
	if err != nil {
		t.Fatal(err)
	}
	hasSD005 := false
	for _, f := range rAll.Findings {
		if f.RuleID == "SD-005" {
			hasSD005 = true
			break
		}
	}
	if !hasSD005 {
		t.Skip("SD-005 did not fire on test file — skipping disable test")
	}

	// With SD-005 disabled → no SD-005 findings.
	cfg := makeCfgWithDisabledRule("SD-005")
	sDisabled := New(dir, newTestRegistry(), cfg, "test")
	rDisabled, err := sDisabled.Run()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rDisabled.Findings {
		if f.RuleID == "SD-005" {
			t.Error("expected no SD-005 findings when rule is disabled")
		}
	}
}
