package triage

import (
	"context"

	"github.com/velzepooz/skill-detector/pkg/model"
)

// ScriptedVerifier is a deterministic Verifier double for tests. It returns the
// verdict registered for a finding's (RuleID, Line); unregistered findings get
// an uncertain verdict. A non-nil Err simulates an LLM failure.
type ScriptedVerifier struct {
	Verdicts map[VerdictKey]Verdict
	Err      error
}

func (s ScriptedVerifier) Classify(_ context.Context, _ model.FileContext, findings []model.Finding) ([]Verdict, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	out := make([]Verdict, len(findings))
	for i, f := range findings {
		if v, ok := s.Verdicts[VerdictKey{RuleID: f.RuleID, Line: f.Line}]; ok {
			v.Index = i + 1
			out[i] = v
			continue
		}
		out[i] = Verdict{RuleID: f.RuleID, Line: f.Line, Index: i + 1, Classification: ClassUncertain, Source: "scripted"}
	}
	return out, nil
}
