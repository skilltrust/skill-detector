// Package grade computes per-axis A–F grades from a list of findings using
// the worst-finding-wins algorithm with per-axis caps.
package grade

import (
	"sort"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// Grade computes the AxisResult for one axis given a slice of findings
// (the function filters internally — caller may pass all findings).
func Grade(axis axes.Axis, findings []model.Finding) model.AxisResult {
	// Filter to this axis.
	axisFindings := findings[:0:0]
	for _, f := range findings {
		if f.Axis == axis {
			axisFindings = append(axisFindings, f)
		}
	}

	if len(axisFindings) == 0 {
		return model.AxisResult{
			Grade:           axes.GradeA,
			Rationale:       "no findings on this axis",
			DrivingFindings: nil,
		}
	}

	// Find max severity (numerically smallest — SeverityCritical = 0).
	maxSev := axisFindings[0].Severity
	for _, f := range axisFindings[1:] {
		if f.Severity < maxSev {
			maxSev = f.Severity
		}
	}

	// Collect findings at max severity.
	var top []model.Finding
	for _, f := range axisFindings {
		if f.Severity == maxSev {
			top = append(top, f)
		}
	}

	// Aggregate by rule id.
	byRule := map[string]int{}
	for _, f := range top {
		byRule[f.RuleID]++
	}
	driving := make([]model.DrivingFinding, 0, len(byRule))
	for id, count := range byRule {
		driving = append(driving, model.DrivingFinding{RuleID: id, Count: count})
	}
	sort.Slice(driving, func(i, j int) bool {
		return driving[i].RuleID < driving[j].RuleID
	})

	// Pick grade.
	g, ok := caps[axis][maxSev]
	if !ok {
		g = axes.GradeA
	}

	// Pick template using top finding description.
	desc := top[0].Description
	if desc == "" {
		desc = top[0].RuleID
	}
	return model.AxisResult{
		Grade:           g,
		Rationale:       rationaleTemplate(axis, maxSev, desc),
		DrivingFindings: driving,
	}
}

// CanonicalMetadata returns a stable string form of caps + templates used by
// the registry checksum to detect tampering with grade calculation rules.
func CanonicalMetadata() string {
	var out string
	for _, a := range axes.Order {
		for _, s := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
			out += string(a) + ":" + s.String() + "=" + string(caps[a][s]) + ";"
		}
	}
	out += "|" + canonicalTemplateString()
	return out
}
