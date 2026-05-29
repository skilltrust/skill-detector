package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/triage"
)

func TestApplyTriage_DemotesBenignExample(t *testing.T) {
	s := New(nil, Options{
		Verifier: triage.ScriptedVerifier{Verdicts: map[triage.VerdictKey]triage.Verdict{
			{RuleID: "SD-009", Line: 3}: {
				RuleID: "SD-009", Line: 3,
				Classification: triage.ClassBenign, Confidence: 0.9,
				Rationale: "doc example", Source: "scripted",
			},
		}},
	})
	findings := []model.Finding{
		{RuleID: "SD-009", FilePath: "README.md", Line: 3, Axis: axes.Security, Severity: model.SeverityCritical},
	}
	files := []model.FileContext{{Path: "README.md", Content: []byte("curl x | bash")}}

	got := s.applyTriage(context.Background(), findings, files)
	if !got[0].IsSuppressed() {
		t.Fatalf("finding should be suppressed, triage=%+v", got[0].Triage)
	}
	if got[0].Triage.Source != "scripted" {
		t.Errorf("source = %q, want scripted", got[0].Triage.Source)
	}
}

func TestApplyTriage_FailSafeOnError(t *testing.T) {
	s := New(nil, Options{Verifier: triage.ScriptedVerifier{Err: errTriageDown}})
	findings := []model.Finding{
		{RuleID: "SD-009", FilePath: "a.sh", Line: 1, Axis: axes.Security, Severity: model.SeverityCritical},
	}
	files := []model.FileContext{{Path: "a.sh"}}

	got := s.applyTriage(context.Background(), findings, files)
	if got[0].IsSuppressed() {
		t.Fatal("must not suppress on verifier error")
	}
	if got[0].Triage == nil || got[0].Triage.Source != "unavailable" {
		t.Fatalf("want unavailable marker, got %+v", got[0].Triage)
	}
}

func TestApplyTriage_NilVerifierNoop(t *testing.T) {
	s := New(nil, Options{})
	findings := []model.Finding{{RuleID: "SD-009", FilePath: "a.sh", Line: 1}}
	got := s.applyTriage(context.Background(), findings, []model.FileContext{{Path: "a.sh"}})
	if got[0].Triage != nil {
		t.Fatalf("nil verifier must leave Triage nil, got %+v", got[0].Triage)
	}
}

var errTriageDown = errors.New("llm down")

func TestApplyTriage_FailSafeOnCancelledContext(t *testing.T) {
	s := New(nil, Options{
		Verifier: triage.ScriptedVerifier{Verdicts: map[triage.VerdictKey]triage.Verdict{
			{RuleID: "SD-009", Line: 1}: {RuleID: "SD-009", Line: 1, Classification: triage.ClassBenign, Confidence: 0.9},
		}},
	})
	findings := []model.Finding{
		{RuleID: "SD-009", FilePath: "a.sh", Line: 1, Axis: axes.Security, Severity: model.SeverityCritical},
	}
	files := []model.FileContext{{Path: "a.sh"}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before triage runs

	got := s.applyTriage(ctx, findings, files)
	if got[0].IsSuppressed() {
		t.Fatal("cancelled context must not suppress (fail-safe)")
	}
	if got[0].Triage == nil || got[0].Triage.Source != "unavailable" {
		t.Fatalf("want unavailable marker, got %+v", got[0].Triage)
	}
}

func TestApplyTriage_FailSafeOnUnmatchedVerdict(t *testing.T) {
	// Verifier returns a verdict for the WRONG line → no match for the real finding.
	s := New(nil, Options{
		Verifier: triage.ScriptedVerifier{Verdicts: map[triage.VerdictKey]triage.Verdict{
			{RuleID: "SD-009", Line: 999}: {RuleID: "SD-009", Line: 999, Classification: triage.ClassBenign, Confidence: 0.9},
		}},
	})
	findings := []model.Finding{
		{RuleID: "SD-009", FilePath: "a.sh", Line: 1, Axis: axes.Security, Severity: model.SeverityCritical},
	}
	files := []model.FileContext{{Path: "a.sh"}}

	got := s.applyTriage(context.Background(), findings, files)
	if got[0].IsSuppressed() {
		t.Fatal("unmatched verdict must not suppress (fail-safe)")
	}
	if got[0].Triage == nil || got[0].Triage.Classification != "uncertain" {
		t.Fatalf("want uncertain classification, got %+v", got[0].Triage)
	}
	if got[0].Triage.Source != "scripted" {
		t.Fatalf("want scripted source (ScriptedVerifier default), got %q", got[0].Triage.Source)
	}
}
