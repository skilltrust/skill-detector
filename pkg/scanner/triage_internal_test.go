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

// perFindingVerifier returns one verdict per finding, in input order, taking the
// classification from the parallel slice. It models a verifier that judges every
// finding on its own merits — including two findings that share (RuleID, Line).
type perFindingVerifier struct {
	classes  []triage.Classification
	setIndex bool
}

func (v perFindingVerifier) Classify(_ context.Context, _ model.FileContext, findings []model.Finding) ([]triage.Verdict, error) {
	out := make([]triage.Verdict, len(findings))
	for i, f := range findings {
		out[i] = triage.Verdict{
			RuleID:         f.RuleID,
			Line:           f.Line,
			Classification: v.classes[i],
			Confidence:     0.9,
			Rationale:      f.Description,
			Source:         "double",
		}
		if v.setIndex {
			out[i].Index = i + 1
		}
	}
	return out, nil
}

// Two SD-021 findings on the same line (one per MCP server) are indistinguishable
// by VerdictKey. Without a tiebreaker the engine must not guess: applying one
// verdict to both can suppress a finding the verifier called a real threat.
func TestApplyTriage_FailSafeOnCollidingKeys(t *testing.T) {
	s := New(nil, Options{Verifier: perFindingVerifier{
		classes: []triage.Classification{triage.ClassReal, triage.ClassBenign},
	}})
	findings := []model.Finding{
		{RuleID: "SD-021", FilePath: ".mcp.json", Line: 1, Description: "alpha", Axis: axes.PermissionHygiene, Severity: model.SeverityMedium},
		{RuleID: "SD-021", FilePath: ".mcp.json", Line: 1, Description: "bravo", Axis: axes.PermissionHygiene, Severity: model.SeverityMedium},
	}
	files := []model.FileContext{{Path: ".mcp.json"}}

	got := s.applyTriage(context.Background(), findings, files)
	for i, f := range got {
		if f.IsSuppressed() {
			t.Errorf("finding %d (%s) suppressed on an ambiguous verdict match", i, f.Description)
		}
		if f.Triage == nil || f.Triage.Source != "unavailable" {
			t.Errorf("finding %d (%s): want unavailable marker, got %+v", i, f.Description, f.Triage)
		}
	}
}

// A verifier that stamps Verdict.Index resolves the ambiguity: each finding gets
// its own verdict even when the keys collide.
func TestApplyTriage_IndexDisambiguatesCollidingKeys(t *testing.T) {
	s := New(nil, Options{Verifier: perFindingVerifier{
		classes:  []triage.Classification{triage.ClassReal, triage.ClassBenign},
		setIndex: true,
	}})
	findings := []model.Finding{
		{RuleID: "SD-021", FilePath: ".mcp.json", Line: 1, Description: "alpha", Axis: axes.PermissionHygiene, Severity: model.SeverityMedium},
		{RuleID: "SD-021", FilePath: ".mcp.json", Line: 1, Description: "bravo", Axis: axes.PermissionHygiene, Severity: model.SeverityMedium},
	}
	files := []model.FileContext{{Path: ".mcp.json"}}

	got := s.applyTriage(context.Background(), findings, files)
	if got[0].IsSuppressed() {
		t.Errorf("alpha was classified real_threat, must not be suppressed: %+v", got[0].Triage)
	}
	if !got[1].IsSuppressed() {
		t.Errorf("bravo was classified benign_example@0.9, must be suppressed: %+v", got[1].Triage)
	}
	if got[0].Triage.Rationale != "alpha" || got[1].Triage.Rationale != "bravo" {
		t.Errorf("rationales crossed over: [0]=%q [1]=%q", got[0].Triage.Rationale, got[1].Triage.Rationale)
	}
}

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
