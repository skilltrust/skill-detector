package reporter

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

var update = flag.Bool("update", false, "update golden files")

func goldenTest(t *testing.T, name string, got string) {
	t.Helper()
	golden := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(golden), 0o750); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
			t.Fatalf("write golden file: %v", err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden file: %v (run with -update to create)", err)
	}
	if got != string(want) {
		t.Errorf("output mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

func TestTextReporter_CleanScan(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "✓ No concerns") {
		t.Error("expected clean verdict '✓ No concerns'")
	}
	if !strings.Contains(got, "12 files scanned") {
		t.Error("expected file count in metadata")
	}
	if !strings.Contains(got, "14 rules") {
		t.Error("expected rule count in metadata")
	}

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 2 || len(lines) > 3 {
		t.Errorf("clean scan should be 2-3 lines, got %d: %q", len(lines), got)
	}
}

func TestTextReporter_WarningsRendered(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
		Warnings: []string{
			"2 agent config path(s) were skipped because they are gitignored; the scan may be blind to the primary attack surface. Re-run with --scan-all to include them.",
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "⚠ 2 agent config path(s) were skipped because they are gitignored") {
		t.Errorf("expected warning line in output, got: %q", got)
	}
}

func TestTextReporter_CriticalFindings(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
		Findings: []model.Finding{
			{Description: "reads ~/.aws/credentials", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "Access Control"},
			{Description: "outbound calls to api.unknown-domain.com", EffSeverity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Category: "Data Exfiltration"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "⚠") || !strings.Contains(got, "behaviors detected") {
		t.Error("expected yellow verdict '⚠ N behaviors detected'")
	}
	if !strings.Contains(got, "2 behaviors detected") {
		t.Error("expected '2 behaviors detected'")
	}
	if !strings.Contains(got, "reads ~/.aws/credentials") {
		t.Error("expected critical finding description")
	}
	if !strings.Contains(got, "●") {
		t.Error("expected high confidence icon ●")
	}
	if !strings.Contains(got, "Access Control") {
		t.Error("expected OWASP category 'Access Control'")
	}
}

func TestTextReporter_MediumOnlyFindings_YellowVerdict(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
		Findings: []model.Finding{
			{Description: "world-writable permissions on config.yaml", EffSeverity: model.SeverityMedium, Confidence: model.ConfidenceMedium, Category: "Security Misconfiguration"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "⚠") || !strings.Contains(got, "1 behaviors detected") {
		t.Error("expected yellow verdict '⚠ 1 behaviors detected'")
	}
	if !strings.Contains(got, "◐") {
		t.Error("expected medium confidence icon ◐")
	}
	if !strings.Contains(got, "Security Misconfiguration") {
		t.Error("expected OWASP category tag")
	}
}

func TestTextReporter_NoColorOutput(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{FileCount: 5, RuleCount: 10}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if strings.Contains(got, "\033[") {
		t.Error("expected no ANSI escape codes in no-color mode")
	}
}

func TestTextReporter_ColorOutput(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	r := &TextReporter{Theme: NewTheme(false)}
	result := model.ScanResult{FileCount: 5, RuleCount: 10}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "\033[") {
		t.Error("expected ANSI escape codes in color mode")
	}
}

func TestTextReporter_Truncation(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	longDesc := strings.Repeat("a", 100)
	result := model.ScanResult{
		FileCount: 1,
		RuleCount: 1,
		Findings: []model.Finding{
			{Description: longDesc, EffSeverity: model.SeverityMedium, Confidence: model.ConfidenceMedium, Category: "Test"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "...") {
		t.Error("expected truncation ellipsis for long description")
	}

	// Check no line exceeds 80 columns (in no-color mode).
	for _, line := range strings.Split(strings.TrimRight(got, "\n"), "\n") {
		runeLen := len([]rune(line))
		if runeLen > maxWidth {
			t.Errorf("line exceeds %d columns (%d): %q", maxWidth, runeLen, line)
		}
	}
}

func TestTextReporter_OWASPCategoryRightAligned(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "short finding", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "Injection"},
			{Description: "another finding here", EffSeverity: model.SeverityMedium, Confidence: model.ConfidenceMedium, Category: "Access Control"},
			{Description: "third one", EffSeverity: model.SeverityLow, Confidence: model.ConfidenceLow, Category: "SSRF"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")

	// Finding lines contain confidence icons (●/◐/○) followed by OWASP category at end.
	var findingLines []string
	for _, line := range lines {
		if strings.Contains(line, "●") || strings.Contains(line, "◐") || strings.Contains(line, "○") {
			findingLines = append(findingLines, line)
		}
	}

	if len(findingLines) != 3 {
		t.Fatalf("expected 3 finding lines, got %d", len(findingLines))
	}

	// All finding lines should be 80 chars wide (right-aligned to column 80).
	for _, line := range findingLines {
		runeLen := len([]rune(line))
		if runeLen != maxWidth {
			t.Errorf("finding line should be %d chars, got %d: %q", maxWidth, runeLen, line)
		}
	}
}

func TestTextReporter_Max5Findings(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	var findings []model.Finding
	for i := range 7 {
		findings = append(findings, model.Finding{
			Description: strings.Repeat("x", 10+i),
			EffSeverity: model.SeverityMedium,
			Confidence:  model.ConfidenceMedium,
			Category:    "Test",
		})
	}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings:  findings,
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Count finding rows (lines containing the confidence icon ◐ for medium).
	findingCount := strings.Count(got, "◐")
	if findingCount != 5 {
		t.Errorf("expected max 5 finding rows, got %d", findingCount)
	}

	if !strings.Contains(got, "...and 2 more") {
		t.Error("expected '...and 2 more' overflow hint")
	}
	if !strings.Contains(got, "--verbose for details") {
		t.Error("expected '--verbose for details' overflow hint")
	}
}

func TestTextReporter_SortByConfidence(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "low conf finding", Confidence: model.ConfidenceLow, Category: "Test"},
			{Description: "high conf finding", Confidence: model.ConfidenceHigh, Category: "Test"},
			{Description: "med conf finding", Confidence: model.ConfidenceMedium, Category: "Test"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	highIdx := strings.Index(got, "high conf finding")
	medIdx := strings.Index(got, "med conf finding")
	lowIdx := strings.Index(got, "low conf finding")

	if highIdx == -1 || medIdx == -1 || lowIdx == -1 {
		t.Fatal("expected all findings in output")
	}
	if highIdx > medIdx {
		t.Error("high confidence should appear before medium")
	}
	if medIdx > lowIdx {
		t.Error("medium confidence should appear before low")
	}
}

func TestTextReporter_SortByCategoryThenConfidenceThenFilePath(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "beta medium", Confidence: model.ConfidenceMedium, Category: "Beta", FilePath: "b.sh"},
			{Description: "alpha low", Confidence: model.ConfidenceLow, Category: "Alpha", FilePath: "z.sh"},
			{Description: "alpha high second", Confidence: model.ConfidenceHigh, Category: "Alpha", FilePath: "b.sh"},
			{Description: "alpha high first", Confidence: model.ConfidenceHigh, Category: "Alpha", FilePath: "a.sh"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	alphaHeaderIdx := strings.Index(got, "  Alpha\n")
	betaHeaderIdx := strings.Index(got, "  Beta\n")
	alphaHighFirstIdx := strings.Index(got, "alpha high first")
	alphaHighSecondIdx := strings.Index(got, "alpha high second")
	alphaLowIdx := strings.Index(got, "alpha low")
	betaMediumIdx := strings.Index(got, "beta medium")

	if alphaHeaderIdx == -1 || betaHeaderIdx == -1 || alphaHighFirstIdx == -1 || alphaHighSecondIdx == -1 || alphaLowIdx == -1 || betaMediumIdx == -1 {
		t.Fatalf("expected all headers and findings in output: %q", got)
	}
	if alphaHeaderIdx > betaHeaderIdx {
		t.Error("categories should sort alphabetically before confidence")
	}
	if alphaHighFirstIdx > alphaHighSecondIdx {
		t.Error("within a category, higher-confidence ties should fall back to file path")
	}
	if alphaHighSecondIdx > alphaLowIdx {
		t.Error("within a category, high confidence should appear before low")
	}
	if alphaLowIdx > betaMediumIdx {
		t.Error("all Alpha findings should appear before Beta findings")
	}
}

func TestTextReporter_CategoryGrouping(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "reads credentials", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "Injection"},
			{Description: "eval untrusted", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "Injection"},
			{Description: "outbound call", EffSeverity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Category: "SSRF / Data Exfiltration"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Category headers should appear
	if !strings.Contains(got, "Injection") {
		t.Error("expected 'Injection' category header")
	}
	if !strings.Contains(got, "SSRF / Data Exfiltration") {
		t.Error("expected 'SSRF / Data Exfiltration' category header")
	}

	// Category header should appear before its findings
	injIdx := strings.Index(got, "  Injection\n")
	if injIdx == -1 {
		t.Fatal("expected 'Injection' category header on its own line")
	}
	credIdx := strings.Index(got, "reads credentials")
	if credIdx == -1 {
		t.Fatal("expected 'reads credentials' finding")
	}
	if injIdx > credIdx {
		t.Error("category header 'Injection' should appear before its findings")
	}

	ssrfIdx := strings.Index(got, "  SSRF / Data Exfiltration\n")
	if ssrfIdx == -1 {
		t.Fatal("expected 'SSRF / Data Exfiltration' category header on its own line")
	}
	outIdx := strings.Index(got, "outbound call")
	if outIdx == -1 {
		t.Fatal("expected 'outbound call' finding")
	}
	if ssrfIdx > outIdx {
		t.Error("category header should appear before its findings")
	}
}

func TestTextReporter_CategoryGrouping_Max5BoundApplied(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	var findings []model.Finding
	for i := range 7 {
		findings = append(findings, model.Finding{
			Description: fmt.Sprintf("finding-%d", i),
			EffSeverity: model.SeverityMedium,
			Confidence:  model.ConfidenceMedium,
			Category:    "Injection",
		})
	}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings:  findings,
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Only 5 findings should be displayed (count confidence icons)
	findingCount := strings.Count(got, "◐")
	if findingCount != 5 {
		t.Errorf("expected max 5 finding rows, got %d", findingCount)
	}
	if !strings.Contains(got, "...and 2 more") {
		t.Error("expected overflow hint")
	}
}

func TestTextReporter_VerboseField(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true), Verbose: true}
	if !r.Verbose {
		t.Error("expected Verbose to be true")
	}
}

func TestTextReporter_VerboseShowsAllFindings(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true), Verbose: true}
	var findings []model.Finding
	for i := range 7 {
		findings = append(findings, model.Finding{
			Description: fmt.Sprintf("finding-%d", i),
			EffSeverity: model.SeverityMedium,
			Category:    "Injection",
			RuleID:      fmt.Sprintf("SD-%03d", i),
			FilePath:    "scripts/setup.sh",
			Line:        10 + i,
			Confidence:  model.ConfidenceHigh,
			Remediation: "Fix it",
		})
	}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings:  findings,
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// All 7 findings should be displayed (no max limit) — count confidence icons.
	findingCount := strings.Count(got, "●")
	if findingCount != 7 {
		t.Errorf("verbose mode should show all 7 findings, got %d", findingCount)
	}

	// Should NOT have overflow hint
	if strings.Contains(got, "...and") {
		t.Error("verbose mode should not have overflow hint")
	}
}

func TestTextReporter_VerboseFindingDetail(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true), Verbose: true}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
		Findings: []model.Finding{
			{
				Description: "reads credentials",
				EffSeverity: model.SeverityCritical,
				Category:    "Broken Access Control",
				RuleID:      "SD-004",
				FilePath:    "scripts/setup.sh",
				Line:        23,
				Confidence:  model.ConfidenceHigh,
				Remediation: "Remove credential path access",
			},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Check verbose detail fields
	if !strings.Contains(got, "Rule: SD-004 (Broken Access Control)") {
		t.Error("expected rule ID and category in verbose output")
	}
	if !strings.Contains(got, "File: scripts/setup.sh:23") {
		t.Error("expected file:line in verbose output")
	}
	if !strings.Contains(got, "Confidence: high") {
		t.Error("expected confidence in verbose output")
	}
	if !strings.Contains(got, "Your check: Remove credential path access") {
		t.Error("expected remediation in verbose output")
	}
}

func TestTextReporter_VerboseDiagnosis(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true), Verbose: true}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{
				Description: "outbound call",
				EffSeverity: model.SeverityHigh,
				Category:    "SSRF / Data Exfiltration",
				RuleID:      "SD-007",
				FilePath:    "scripts/fetch.sh",
				Line:        12,
				Confidence:  model.ConfidenceLow,
				Diagnosis:   "No corroborating signals",
				Remediation: "Verify URL is required",
			},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "Confidence: low · No corroborating signals") {
		t.Error("expected confidence with diagnosis appended")
	}
	if strings.Count(got, "No corroborating signals") != 1 {
		t.Errorf("expected diagnosis to appear once in verbose output, got %q", got)
	}
}

func TestTextReporter_VerboseCategoryGrouping(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true), Verbose: true}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "finding1", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "Injection", RuleID: "SD-001", Remediation: "fix"},
			{Description: "finding2", EffSeverity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Category: "SSRF", RuleID: "SD-007", Remediation: "fix"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	injIdx := strings.Index(got, "  Injection\n")
	ssrfIdx := strings.Index(got, "  SSRF\n")
	f1Idx := strings.Index(got, "finding1")
	f2Idx := strings.Index(got, "finding2")

	if injIdx == -1 || ssrfIdx == -1 {
		t.Fatal("expected both category headers in verbose mode")
	}
	if injIdx > f1Idx {
		t.Error("Injection header should appear before finding1")
	}
	if ssrfIdx > f2Idx {
		t.Error("SSRF header should appear before finding2")
	}
}

func TestTextReporter_VerboseEmptyCategory(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true), Verbose: true}
	result := model.ScanResult{
		FileCount: 3,
		RuleCount: 5,
		Findings: []model.Finding{
			{Description: "some finding", EffSeverity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Category: "", RuleID: "SD-001", Remediation: "fix it"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Should not have double blank lines from empty category header
	if strings.Contains(got, "\n\n\n") {
		t.Error("spurious blank line when category is empty")
	}
	if !strings.Contains(got, "some finding") {
		t.Error("expected finding to still appear")
	}
}

func TestTextReporter_VerboseLineZero(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true), Verbose: true}
	result := model.ScanResult{
		FileCount: 3,
		RuleCount: 5,
		Findings: []model.Finding{
			{Description: "no line", EffSeverity: model.SeverityMedium, Confidence: model.ConfidenceMedium, Category: "Injection", RuleID: "SD-001", FilePath: "setup.sh", Line: 0, Remediation: "fix"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// When Line is 0, should show file path without :0
	if !strings.Contains(got, "File: setup.sh") {
		t.Error("expected file path without line number")
	}
	if strings.Contains(got, "setup.sh:0") {
		t.Error("should not show :0 for zero line number")
	}
}

func TestTextReporter_VerboseZeroFindings(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true), Verbose: true}
	result := model.ScanResult{
		FileCount: 3,
		RuleCount: 5,
		Findings:  nil,
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "No concerns") {
		t.Error("expected clean verdict in verbose mode with zero findings")
	}
}

func TestTextReporter_VerboseTruncation(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true), Verbose: true}
	longPath := "very/deeply/nested/directory/structure/that/goes/on/and/on/script.sh"
	result := model.ScanResult{
		FileCount: 1,
		RuleCount: 1,
		Findings: []model.Finding{
			{
				Description: "finding",
				EffSeverity: model.SeverityHigh,
				Confidence:  model.ConfidenceHigh,
				Category:    "Injection",
				RuleID:      "SD-001",
				FilePath:    longPath,
				Line:        999,
				Remediation: "This is a very long remediation string that should exceed eighty columns when combined with the Your check prefix and indentation",
			},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, line := range strings.Split(got, "\n") {
		runeLen := len([]rune(line))
		if runeLen > maxWidth {
			t.Errorf("line exceeds %d columns (%d): %q", maxWidth, runeLen, line)
		}
	}
}

func TestTextReporter_DefaultCategoryGroupingSorted(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "inj1", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "Injection"},
			{Description: "ssrf1", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "SSRF"},
			{Description: "inj2", EffSeverity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Category: "Injection"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Injection findings should be grouped together
	inj1Idx := strings.Index(got, "inj1")
	inj2Idx := strings.Index(got, "inj2")
	ssrf1Idx := strings.Index(got, "ssrf1")

	if inj1Idx == -1 || inj2Idx == -1 || ssrf1Idx == -1 {
		t.Fatal("expected all findings in output")
	}

	// Both injection findings should be adjacent (before or after SSRF, but grouped)
	if inj1Idx < ssrf1Idx && ssrf1Idx < inj2Idx {
		t.Error("injection findings should be grouped together, not split by SSRF")
	}
	if inj2Idx < ssrf1Idx && ssrf1Idx < inj1Idx {
		t.Error("injection findings should be grouped together, not split by SSRF")
	}
}

// --- Permission formatting tests (Task 1) ---

func TestFormatInlinePermissions_FilesystemOnly(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files"}},
	}
	got := formatInlinePermissions(perms)
	expected := "reads local files · no network · no shell · no env var access"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestFormatInlinePermissions_FilesystemAndNetwork(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files"}},
		{Type: "network", Details: []string{"api.example.com"}},
	}
	got := formatInlinePermissions(perms)
	expected := "reads local files · network · no shell · no env var access"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestFormatInlinePermissions_AllTypes(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files"}},
		{Type: "network", Details: []string{"api.example.com"}},
		{Type: "shell_execution", Details: []string{}},
		{Type: "env_var_access", Details: []string{"$SECRET"}},
	}
	got := formatInlinePermissions(perms)
	expected := "reads local files · network · shell · env var access"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestFormatPermissionSummary_WithCredentials(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files", "incl. credentials: ~/.aws/credentials"}},
		{Type: "network", Details: []string{"api.unknown-domain.com"}},
		{Type: "shell_execution", Details: []string{}},
	}
	got := formatPermissionSummary(perms)
	expected := "reads filesystem (incl. credentials) · network · shell"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestFormatPermissionSummary_NoCredentials(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files"}},
		{Type: "network", Details: []string{"api.example.com"}},
	}
	got := formatPermissionSummary(perms)
	expected := "reads filesystem · network"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestFormatPermissionSummary_OnlyPositive(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files"}},
	}
	got := formatPermissionSummary(perms)
	if strings.Contains(got, "no ") {
		t.Errorf("findings summary should not contain negative permissions, got %q", got)
	}
	expected := "reads filesystem"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestFormatInlinePermissions_DeterministicOrder(t *testing.T) {
	// Pass permissions in non-canonical order — output should still follow canonical order
	perms := []model.Permission{
		{Type: "shell_execution", Details: []string{}},
		{Type: "filesystem", Details: []string{"reads local files"}},
		{Type: "env_var_access", Details: []string{"$SECRET"}},
		{Type: "network", Details: []string{"api.example.com"}},
	}
	got := formatInlinePermissions(perms)
	expected := "reads local files · network · shell · env var access"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

// --- Explanation builder tests (Task 2) ---

func TestBuildExplanation_CredentialsAndNetwork(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files", "incl. credentials: ~/.aws/credentials"}},
		{Type: "network", Details: []string{"api.unknown-domain.com"}},
	}
	got := buildExplanation(perms)
	// Full sentence exceeds 78 chars → truncated
	expected := "This skill reads ~/.aws/credentials and makes network calls to api.unknown-..."
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestBuildExplanation_ShellOnly(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files"}},
		{Type: "shell_execution", Details: []string{}},
	}
	got := buildExplanation(perms)
	expected := "This skill executes shell commands"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestBuildExplanation_EnvVarAccess(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files"}},
		{Type: "env_var_access", Details: []string{"$AWS_SECRET_ACCESS_KEY"}},
	}
	got := buildExplanation(perms)
	expected := "This skill accesses environment variables ($AWS_SECRET_ACCESS_KEY)"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestBuildExplanation_ThreePhrases(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files", "incl. credentials: ~/.aws/credentials"}},
		{Type: "shell_execution", Details: []string{}},
		{Type: "network", Details: []string{"api.example.com"}},
	}
	got := buildExplanation(perms)
	// Canonical order: filesystem, network, shell — full sentence exceeds 78 chars → truncated
	expected := "This skill reads ~/.aws/credentials, makes network calls to api.example.com..."
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestBuildExplanation_NetworkWithoutDomain(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files"}},
		{Type: "network", Details: []string{}},
	}
	got := buildExplanation(perms)
	expected := "This skill makes outbound network calls"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestBuildExplanation_FilesystemOnlyNoBenign(t *testing.T) {
	// Filesystem without credentials is benign — should be omitted from explanation
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files"}},
	}
	got := buildExplanation(perms)
	// No interesting phrases — explanation should be empty
	if got != "" {
		t.Errorf("expected empty explanation for benign-only perms, got %q", got)
	}
}

func TestBuildExplanation_Truncation(t *testing.T) {
	perms := []model.Permission{
		{Type: "filesystem", Details: []string{"reads local files", "incl. credentials: ~/.very/long/deeply/nested/path/to/credentials/file"}},
		{Type: "network", Details: []string{"api.very-long-domain-name-that-keeps-going.example.com"}},
		{Type: "shell_execution", Details: []string{}},
		{Type: "env_var_access", Details: []string{"$VERY_LONG_ENVIRONMENT_VARIABLE_NAME"}},
	}
	got := buildExplanation(perms)
	if len([]rune(got)) > 78 {
		t.Errorf("explanation exceeds 78 chars (got %d): %q", len([]rune(got)), got)
	}
	if len(got) > 0 && !strings.HasSuffix(got, "...") {
		t.Errorf("truncated explanation should end with '...', got %q", got)
	}
}

// --- Integration tests: permissions in Report() output (Task 3 & 4) ---

func TestTextReporter_CleanScan_WithPermissions(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
		Permissions: []model.Permission{
			{Type: "filesystem", Details: []string{"reads local files"}},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// AC1 / AC4: verdict line includes inline permissions with negatives
	if !strings.Contains(got, "✓ No concerns · reads local files · no network · no shell · no env var access") {
		t.Errorf("expected verdict with inline permissions, got %q", got)
	}

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 2 || len(lines) > 3 {
		t.Errorf("clean scan with perms should be 2-3 lines, got %d: %q", len(lines), got)
	}
}

func TestTextReporter_CleanScan_FilesystemAndNetwork(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
		Permissions: []model.Permission{
			{Type: "filesystem", Details: []string{"reads local files"}},
			{Type: "network", Details: []string{"api.example.com"}},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "✓ No concerns · reads local files · network · no shell · no env var access") {
		t.Errorf("expected verdict with filesystem+network permissions, got %q", got)
	}
}

func TestTextReporter_Findings_WithPermissions(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
		Findings: []model.Finding{
			{Description: "reads ~/.aws/credentials", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "Access Control", RuleID: "SD-004"},
			{Description: "outbound calls to api.unknown-domain.com", EffSeverity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Category: "Data Exfiltration", RuleID: "SD-007"},
		},
		Permissions: []model.Permission{
			{Type: "filesystem", Details: []string{"reads local files", "incl. credentials: ~/.aws/credentials"}},
			{Type: "network", Details: []string{"api.unknown-domain.com"}},
			{Type: "shell_execution", Details: []string{}},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Permission summary line present with "Permissions:" prefix
	if !strings.Contains(got, "Permissions: reads filesystem (incl. credentials) · network · shell") {
		t.Errorf("expected permission summary with Permissions prefix, got %q", got)
	}
}

func TestTextReporter_MediumFindings_WithPermissions(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
		Findings: []model.Finding{
			{Description: "world-writable permissions on config.yaml", EffSeverity: model.SeverityMedium, Confidence: model.ConfidenceMedium, Category: "Security Misconfiguration"},
		},
		Permissions: []model.Permission{
			{Type: "filesystem", Details: []string{"reads local files"}},
			{Type: "network", Details: []string{"api.example.com"}},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Permission summary present with prefix
	if !strings.Contains(got, "Permissions: reads filesystem · network") {
		t.Errorf("expected permission summary for medium findings, got %q", got)
	}
}

func TestTextReporter_NilPermissions_FallbackBehavior(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// No permission text when Permissions is nil
	if strings.Contains(got, "reads") || strings.Contains(got, "no network") || strings.Contains(got, "no shell") {
		t.Errorf("nil permissions should produce no permission text, got %q", got)
	}

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 2 || len(lines) > 3 {
		t.Errorf("nil perms clean scan should be 2-3 lines, got %d", len(lines))
	}
}

func TestTextReporter_CleanScan_WithPermissions_NoColor(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Permissions: []model.Permission{
			{Type: "filesystem", Details: []string{"reads local files"}},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if strings.Contains(got, "\033[") {
		t.Error("expected no ANSI codes in no-color mode")
	}
	if !strings.Contains(got, "reads local files") {
		t.Error("expected permission text in no-color mode")
	}
}

func TestTextReporter_CleanScan_WithPermissions_Color(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	r := &TextReporter{Theme: NewTheme(false)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Permissions: []model.Permission{
			{Type: "filesystem", Details: []string{"reads local files"}},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "\033[") {
		t.Error("expected ANSI codes in color mode")
	}
}

func TestTextReporter_Findings_WithPermissions_80ColConstraint(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
		Findings: []model.Finding{
			{Description: "critical finding", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "Injection"},
		},
		Permissions: []model.Permission{
			{Type: "filesystem", Details: []string{"reads local files", "incl. credentials: ~/.very/long/path/to/credentials"}},
			{Type: "network", Details: []string{"api.very-long-domain.example.com"}},
			{Type: "shell_execution", Details: []string{}},
			{Type: "env_var_access", Details: []string{"$VERY_LONG_VAR"}},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, line := range strings.Split(strings.TrimRight(got, "\n"), "\n") {
		runeLen := len([]rune(line))
		if runeLen > maxWidth {
			t.Errorf("line exceeds %d columns (%d): %q", maxWidth, runeLen, line)
		}
	}
}

func TestTextReporter_Findings_OutputOrder(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 12,
		RuleCount: 14,
		Findings: []model.Finding{
			{Description: "reads ~/.aws/credentials", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "Access Control"},
		},
		Permissions: []model.Permission{
			{Type: "filesystem", Details: []string{"reads local files", "incl. credentials: ~/.aws/credentials"}},
			{Type: "network", Details: []string{"api.example.com"}},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Verify output order: verdict → findings → permissions → metadata
	verdictIdx := strings.Index(got, "behaviors detected")
	findingIdx := strings.Index(got, "reads ~/.aws/credentials")
	permIdx := strings.Index(got, "Permissions:")
	metaIdx := strings.Index(got, "files scanned")

	if verdictIdx == -1 || findingIdx == -1 || permIdx == -1 || metaIdx == -1 {
		t.Fatalf("missing expected sections in output: %q", got)
	}
	if verdictIdx >= findingIdx {
		t.Error("verdict should appear before findings")
	}
	if findingIdx >= permIdx {
		t.Error("findings should appear before permission summary")
	}
	if permIdx >= metaIdx {
		t.Error("permission summary should appear before metadata")
	}
}

func TestTheme_NewTheme_NoColor(t *testing.T) {
	theme := NewTheme(true)
	if !theme.NoColor {
		t.Error("expected NoColor=true when noColor param is true")
	}
}

func TestTheme_NewTheme_Color(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	theme := NewTheme(false)
	if theme.NoColor {
		t.Error("expected NoColor=false when noColor param is false and NO_COLOR not set")
	}
}

func TestTheme_Colorize_NoColor(t *testing.T) {
	theme := Theme{NoColor: true}
	got := theme.Colorize("hello", ansiRed)
	if got != "hello" {
		t.Errorf("expected plain text, got %q", got)
	}
}

func TestTheme_Colorize_WithColor(t *testing.T) {
	theme := Theme{NoColor: false}
	got := theme.Colorize("hello", ansiRed)
	if !strings.Contains(got, "\033[31m") {
		t.Error("expected red ANSI code")
	}
	if !strings.HasSuffix(got, ansiReset) {
		t.Error("expected ANSI reset at end")
	}
}

func TestTheme_VerdictIcon(t *testing.T) {
	theme := Theme{NoColor: true}

	clean := theme.VerdictIcon(true, 0)
	if clean != "✓ No concerns" {
		t.Errorf("expected '✓ No concerns', got %q", clean)
	}

	findings := theme.VerdictIcon(false, 3)
	if findings != "⚠ 3 behaviors detected" {
		t.Errorf("expected '⚠ 3 behaviors detected', got %q", findings)
	}

	single := theme.VerdictIcon(false, 1)
	if single != "⚠ 1 behaviors detected" {
		t.Errorf("expected '⚠ 1 behaviors detected', got %q", single)
	}
}

func TestTextReporter_ConfidenceIcons(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "high confidence finding", Confidence: model.ConfidenceHigh, Category: "Injection"},
			{Description: "medium confidence finding", Confidence: model.ConfidenceMedium, Category: "Injection"},
			{Description: "low confidence finding", Confidence: model.ConfidenceLow, Category: "Injection"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "●") {
		t.Error("expected high confidence icon ●")
	}
	if !strings.Contains(got, "◐") {
		t.Error("expected medium confidence icon ◐")
	}
	if !strings.Contains(got, "○") {
		t.Error("expected low confidence icon ○")
	}

	// Icons should appear before descriptions
	highIcon := strings.Index(got, "●")
	highDesc := strings.Index(got, "high confidence finding")
	if highIcon > highDesc {
		t.Error("● icon should appear before 'high confidence finding'")
	}

	medIcon := strings.Index(got, "◐")
	medDesc := strings.Index(got, "medium confidence finding")
	if medIcon > medDesc {
		t.Error("◐ icon should appear before 'medium confidence finding'")
	}

	lowIcon := strings.Index(got, "○")
	lowDesc := strings.Index(got, "low confidence finding")
	if lowIcon > lowDesc {
		t.Error("○ icon should appear before 'low confidence finding'")
	}
}

func TestTextReporter_DiagnosisInDefaultMode(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{
				Description: "reads credentials",
				Confidence:  model.ConfidenceHigh,
				Category:    "Access Control",
				Diagnosis:   "Likely credential access. Alternative: config read.",
			},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "Likely credential access. Alternative: config read.") {
		t.Error("expected diagnosis to appear in default mode output")
	}
}

func TestTextReporter_NoSeverityInOutput(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "finding one", EffSeverity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Category: "Injection"},
			{Description: "finding two", EffSeverity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Category: "Access Control"},
			{Description: "finding three", EffSeverity: model.SeverityMedium, Confidence: model.ConfidenceLow, Category: "SSRF"},
			{Description: "finding four", EffSeverity: model.SeverityLow, Confidence: model.ConfidenceLow, Category: "Misconfiguration"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if strings.Contains(got, sev) {
			t.Errorf("severity label %q should NOT appear in text output, got %q", sev, got)
		}
	}
}

func TestTextReporter_NoColorConfidenceIcons(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "test finding", Confidence: model.ConfidenceHigh, Category: "Injection"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Icons should render as Unicode without ANSI codes
	if !strings.Contains(got, "●") {
		t.Error("expected confidence icon in no-color mode")
	}
	if strings.Contains(got, "\033[") {
		t.Error("expected no ANSI codes in no-color mode")
	}
}

func TestTheme_ConfidenceIcon(t *testing.T) {
	theme := Theme{NoColor: true}

	if icon := theme.ConfidenceIcon(model.ConfidenceHigh); icon != "●" {
		t.Errorf("expected ●, got %q", icon)
	}
	if icon := theme.ConfidenceIcon(model.ConfidenceMedium); icon != "◐" {
		t.Errorf("expected ◐, got %q", icon)
	}
	if icon := theme.ConfidenceIcon(model.ConfidenceLow); icon != "○" {
		t.Errorf("expected ○, got %q", icon)
	}
}

func TestTheme_ConfidenceStyle(t *testing.T) {
	theme := Theme{NoColor: false}

	high := theme.ConfidenceStyle(model.ConfidenceHigh)
	if len(high) != 1 || high[0] != ansiBold {
		t.Errorf("expected bold for high confidence, got %v", high)
	}

	med := theme.ConfidenceStyle(model.ConfidenceMedium)
	if len(med) != 0 {
		t.Errorf("expected empty for medium confidence, got %v", med)
	}

	low := theme.ConfidenceStyle(model.ConfidenceLow)
	if len(low) != 1 || low[0] != ansiDim {
		t.Errorf("expected dim for low confidence, got %v", low)
	}
}

// --- Expected context tests (Story 5.3) ---

func TestTextReporter_ExpectedFinding(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "outbound calls to api.example.com", Confidence: model.ConfidenceMedium, Category: "Data Exfiltration", RuleID: "SD-007", EffSeverity: model.SeverityInfo},
		},
		ConfigOverrides: []model.ConfigOverride{
			{RuleID: "SD-007", Field: "context", Original: "", Override: "expected"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "(expected)") {
		t.Error("expected '(expected)' tag in output for context override finding")
	}
	if !strings.Contains(got, "Data Exfiltration (expected)") {
		t.Errorf("expected 'Data Exfiltration (expected)' in output, got %q", got)
	}
}

func TestTextReporter_ExpectedFinding_DimStyle(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	r := &TextReporter{Theme: NewTheme(false)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "outbound call", Confidence: model.ConfidenceHigh, Category: "Data Exfiltration", RuleID: "SD-007", EffSeverity: model.SeverityInfo},
		},
		ConfigOverrides: []model.ConfigOverride{
			{RuleID: "SD-007", Field: "context", Original: "", Override: "expected"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	var findingLine string
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "outbound call") {
			findingLine = line
			break
		}
	}
	if findingLine == "" {
		t.Fatalf("expected to find rendered finding row in output: %q", got)
	}

	// Expected findings keep their normal confidence styling; only the tag is dimmed.
	if !strings.Contains(findingLine, ansiBold) {
		t.Error("expected high-confidence finding row to remain bold")
	}
	if !strings.Contains(findingLine, ansiReset+ansiDim+ansiCyan+"Data Exfiltration (expected)"+ansiReset) {
		t.Errorf("expected category tag to remain dim in color mode, got %q", findingLine)
	}
}

func TestTextReporter_ExpectedFindings_SortAfterUnexpected(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "expected call", Confidence: model.ConfidenceHigh, Category: "Data Exfiltration", RuleID: "SD-007", EffSeverity: model.SeverityInfo},
			{Description: "unexpected call", Confidence: model.ConfidenceMedium, Category: "Data Exfiltration", RuleID: "SD-009", EffSeverity: model.SeverityHigh},
		},
		ConfigOverrides: []model.ConfigOverride{
			{RuleID: "SD-007", Field: "context", Original: "", Override: "expected"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	unexpectedIdx := strings.Index(got, "unexpected call")
	expectedIdx := strings.Index(got, "expected call")
	if unexpectedIdx == -1 || expectedIdx == -1 {
		t.Fatal("expected both findings in output")
	}
	if expectedIdx < unexpectedIdx {
		t.Error("expected findings should sort AFTER non-expected in same category")
	}
}

func TestTextReporter_AllExpected_StillShown(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "expected outbound call", Confidence: model.ConfidenceMedium, Category: "Data Exfiltration", RuleID: "SD-007", EffSeverity: model.SeverityInfo},
		},
		ConfigOverrides: []model.ConfigOverride{
			{RuleID: "SD-007", Field: "context", Original: "", Override: "expected"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "expected outbound call") {
		t.Error("expected findings should still appear in output (tool reports facts)")
	}
	if !strings.Contains(got, "1 behaviors detected") {
		t.Error("expected verdict to count expected findings")
	}
}

// --- Golden file tests (Story 5.4) ---

func TestTextReporter_Golden_CleanScan(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
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
	goldenTest(t, "text_clean", buf.String())
}

func TestTextReporter_Golden_Findings_Default(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := goldenFindingsResult()
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	goldenTest(t, "text_findings_default", buf.String())
}

func TestTextReporter_Golden_Findings_Verbose(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true), Verbose: true}
	result := goldenFindingsResult()
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	goldenTest(t, "text_findings_verbose", buf.String())
}

func TestTextReporter_Golden_Overflow(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	var findings []model.Finding
	for i := range 7 {
		findings = append(findings, model.Finding{
			RuleID:      fmt.Sprintf("SD-%03d", i+1),
			RuleName:    fmt.Sprintf("Rule %d", i+1),
			Severity:    model.SeverityMedium,
			EffSeverity: model.SeverityMedium,
			Category:    "Test Category",
			Description: fmt.Sprintf("finding number %d", i+1),
			FilePath:    fmt.Sprintf("scripts/file%d.sh", i+1),
			Line:        10 + i,
			Confidence:  model.ConfidenceMedium,
			Diagnosis:   fmt.Sprintf("Diagnosis for finding %d.", i+1),
			Remediation: fmt.Sprintf("Fix finding %d", i+1),
		})
	}
	result := model.ScanResult{
		Findings:        findings,
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
	goldenTest(t, "text_overflow", buf.String())
}

func TestTextReporter_Golden_ExpectedContext(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := goldenFindingsResult()
	// SD-007 is context: expected → EffSeverity = INFO
	for i := range result.Findings {
		if result.Findings[i].RuleID == "SD-007" {
			result.Findings[i].EffSeverity = model.SeverityInfo
		}
	}
	result.ConfigOverrides = []model.ConfigOverride{
		{RuleID: "SD-007", Field: "context", Original: "", Override: "expected"},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	goldenTest(t, "text_expected_context", buf.String())
}

// goldenFindingsResult returns the shared fixture for golden file tests with findings.
func goldenFindingsResult() model.ScanResult {
	return model.ScanResult{
		Findings: []model.Finding{
			{RuleID: "SD-004", RuleName: "Credential Path Access", Severity: model.SeverityCritical, EffSeverity: model.SeverityCritical, Category: "Access Control", Description: "reads ~/.aws/credentials", FilePath: "scripts/setup.sh", Line: 23, Confidence: model.ConfidenceHigh, Diagnosis: "Likely credential theft attempt (corroborated by SD-007). Alternative: legitimate configuration file access.", Remediation: "Remove credential path access or document why it's needed"},
			{RuleID: "SD-007", RuleName: "Outbound Network Calls", Severity: model.SeverityHigh, EffSeverity: model.SeverityHigh, Category: "Data Exfiltration", Description: "outbound calls to api.example.com", FilePath: "scripts/fetch.sh", Line: 15, Confidence: model.ConfidenceMedium, Diagnosis: "Possible data exfiltration to external service. Alternative: legitimate API call.", Remediation: "Verify the target domain is trusted and necessary"},
			{RuleID: "SD-008", RuleName: "Base64 Obfuscation", Severity: model.SeverityMedium, EffSeverity: model.SeverityMedium, Category: "Data Exfiltration", Description: "base64-encoded string detected", FilePath: "config/setup.yaml", Line: 8, Confidence: model.ConfidenceLow, Diagnosis: "Possible obfuscated malicious payload, but may be legitimate data encoding. No corroborating signals found.", Remediation: "Decode and inspect the base64 content"},
		},
		Permissions:     []model.Permission{{Type: "filesystem", Details: []string{"credential: ~/.aws/credentials"}}, {Type: "network", Details: []string{"api.example.com"}}},
		FileCount:       12,
		RuleCount:       14,
		Version:         "0.1.0-dev",
		Checksum:        "abc123",
		SchemaVersion:   "1.1",
		ConfigOverrides: []model.ConfigOverride{},
	}
}

func TestTextReporterEmitsTrustScoreBlock(t *testing.T) {
	res := model.ScanResult{
		Findings: []model.Finding{
			{
				RuleID:      "SD-017",
				Severity:    model.SeverityHigh,
				Axis:        axes.PermissionHygiene,
				Description: "broad shell permission granted: Bash(curl *)",
				FilePath:    ".claude/settings.json",
				Line:        1,
			},
		},
		Axes: map[axes.Axis]model.AxisResult{
			axes.Security:          {Grade: axes.GradeA, Rationale: "no findings on this axis"},
			axes.PermissionHygiene: {Grade: axes.GradeD, Rationale: "High-severity issue: broad shell permission granted: Bash(curl *)"},
			axes.Transparency:      {Grade: axes.GradeA, Rationale: "no findings on this axis"},
			axes.Quality:           {Grade: axes.GradeA, Rationale: "no findings on this axis"},
		},
	}
	var buf bytes.Buffer
	r := &TextReporter{Theme: NewTheme(true)}
	if err := r.Report(res, &buf); err != nil {
		t.Fatalf("Report: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Trust Score") {
		t.Errorf("output missing Trust Score header: %s", out)
	}
	if !strings.Contains(out, "Security") {
		t.Errorf("output missing Security label: %s", out)
	}
	if !strings.Contains(out, "Permission hygiene") {
		t.Errorf("output missing Permission hygiene label: %s", out)
	}
	if !strings.Contains(out, "D") {
		t.Errorf("output missing the D grade: %s", out)
	}
}

func TestTextReporter_ExpectedFinding_NoColor(t *testing.T) {
	r := &TextReporter{Theme: NewTheme(true)}
	result := model.ScanResult{
		FileCount: 5,
		RuleCount: 10,
		Findings: []model.Finding{
			{Description: "outbound call", Confidence: model.ConfidenceHigh, Category: "Data Exfiltration", RuleID: "SD-007", EffSeverity: model.SeverityInfo},
		},
		ConfigOverrides: []model.ConfigOverride{
			{RuleID: "SD-007", Field: "context", Original: "", Override: "expected"},
		},
	}
	var buf bytes.Buffer
	if err := r.Report(result, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "(expected)") {
		t.Error("expected '(expected)' tag in no-color mode")
	}
	if strings.Contains(got, "\033[") {
		t.Error("expected no ANSI codes in no-color mode")
	}
}
