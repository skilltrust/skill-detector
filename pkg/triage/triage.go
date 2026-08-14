// Package triage defines the pluggable Verifier seam the scanner uses to
// classify findings as real threats or benign examples. The engine ships an
// inert NoopVerifier; the LLM-backed verifier lives in the hosted scanner.
package triage

import (
	"context"

	"github.com/velzepooz/skill-detector/pkg/model"
)

// Classification is the triage verdict for a single finding.
type Classification string

const (
	ClassReal      Classification = "real_threat"
	ClassBenign    Classification = "benign_example"
	ClassUncertain Classification = "uncertain"
)

// Verdict is the triage result for one finding, matched back to the finding by
// Index when set, otherwise by (RuleID, Line).
type Verdict struct {
	RuleID         string
	Line           int
	Classification Classification
	Confidence     float64 // 0.0–1.0
	Rationale      string
	Source         string // e.g. "noop", "scripted", "llm:<model>", "cache"

	// Index is the 1-based position of the finding this verdict applies to in
	// the slice passed to Classify. 0 means unset, which falls back to
	// (RuleID, Line) matching. Set it whenever a batch can contain two findings
	// with the same rule and line — one MCP server per finding on line 1
	// (SD-021), several prompt-injection signals on one line (SD-002) — because
	// the key alone cannot tell them apart and the engine then refuses to apply
	// either verdict.
	Index int
}

// VerdictKey identifies the finding a Verdict applies to.
type VerdictKey struct {
	RuleID string
	Line   int
}

// Verifier classifies findings for one file. Implementations MUST be
// deterministic for the scanner's contract: the same (file, findings) input
// should yield the same verdicts (the hosted impl achieves this via caching).
// Return one verdict per finding and stamp Verdict.Index; verdicts may come back
// in any order. Verdicts left unindexed are matched by (RuleID, Line), and any
// such key claimed by two findings — or by two verdicts — is discarded in favour
// of the deterministic floor, since the engine cannot tell which finding the
// verifier meant.
type Verifier interface {
	Classify(ctx context.Context, file model.FileContext, findings []model.Finding) ([]Verdict, error)
}

// NoopVerifier returns an "uncertain" verdict for every finding, leaving the
// deterministic floor untouched. It is the default when no verifier is injected.
type NoopVerifier struct{}

func (NoopVerifier) Classify(_ context.Context, _ model.FileContext, findings []model.Finding) ([]Verdict, error) {
	out := make([]Verdict, len(findings))
	for i, f := range findings {
		out[i] = Verdict{
			RuleID:         f.RuleID,
			Line:           f.Line,
			Index:          i + 1,
			Classification: ClassUncertain,
			Source:         "noop",
		}
	}
	return out, nil
}
