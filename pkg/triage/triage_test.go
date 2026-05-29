package triage_test

import (
	"context"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/triage"
)

func TestNoopVerifier_ReturnsUncertainPerFinding(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "SD-009", Line: 3},
		{RuleID: "SD-007", Line: 8},
	}
	got, err := triage.NoopVerifier{}.Classify(context.Background(), model.FileContext{}, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(findings) {
		t.Fatalf("want %d verdicts, got %d", len(findings), len(got))
	}
	for i, v := range got {
		if v.Classification != triage.ClassUncertain {
			t.Errorf("verdict %d: want uncertain, got %s", i, v.Classification)
		}
		if v.Source != "noop" {
			t.Errorf("verdict %d: want source noop, got %q", i, v.Source)
		}
		if v.RuleID != findings[i].RuleID || v.Line != findings[i].Line {
			t.Errorf("verdict %d: key mismatch %s/%d", i, v.RuleID, v.Line)
		}
	}
}
