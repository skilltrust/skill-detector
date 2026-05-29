package triage_test

import (
	"context"
	"errors"
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

func TestScriptedVerifier_ReturnsRegisteredOrUncertain(t *testing.T) {
	sv := triage.ScriptedVerifier{Verdicts: map[triage.VerdictKey]triage.Verdict{
		{RuleID: "SD-009", Line: 3}: {
			RuleID: "SD-009", Line: 3,
			Classification: triage.ClassBenign, Confidence: 0.9,
			Rationale: "doc example", Source: "scripted",
		},
	}}
	findings := []model.Finding{
		{RuleID: "SD-009", Line: 3},
		{RuleID: "SD-007", Line: 8},
	}
	got, err := sv.Classify(context.Background(), model.FileContext{}, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].Classification != triage.ClassBenign || got[0].Confidence != 0.9 {
		t.Errorf("finding 0: want benign/0.9, got %s/%v", got[0].Classification, got[0].Confidence)
	}
	if got[1].Classification != triage.ClassUncertain {
		t.Errorf("finding 1: want uncertain, got %s", got[1].Classification)
	}
}

func TestScriptedVerifier_ReturnsErr(t *testing.T) {
	sv := triage.ScriptedVerifier{Err: errScriptTest}
	_, err := sv.Classify(context.Background(), model.FileContext{}, []model.Finding{{RuleID: "X"}})
	if err != errScriptTest {
		t.Fatalf("want errScriptTest, got %v", err)
	}
}

var errScriptTest = errors.New("simulated llm failure")
