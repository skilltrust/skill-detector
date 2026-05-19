package grade_test

import (
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/grade"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestGradeNoFindings(t *testing.T) {
	res := grade.Grade(axes.Security, nil)
	if res.Grade != axes.GradeA {
		t.Errorf("no findings: grade = %q, want A", res.Grade)
	}
	if res.Rationale != "no findings on this axis" {
		t.Errorf("rationale = %q, want %q", res.Rationale, "no findings on this axis")
	}
	if len(res.DrivingFindings) != 0 {
		t.Errorf("driving findings = %d, want 0", len(res.DrivingFindings))
	}
}

func TestGradeFiltersByAxis(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "a", Severity: model.SeverityCritical, Axis: axes.Security},
		{RuleID: "b", Severity: model.SeverityCritical, Axis: axes.Quality},
	}
	res := grade.Grade(axes.Security, findings)
	if res.Grade != axes.GradeF {
		t.Errorf("security with critical: grade = %q, want F", res.Grade)
	}
	if len(res.DrivingFindings) != 1 || res.DrivingFindings[0].RuleID != "a" {
		t.Errorf("driving findings should only include security findings, got %+v", res.DrivingFindings)
	}
}

func TestGradeWorstFindingWins(t *testing.T) {
	tests := []struct {
		name     string
		axis     axes.Axis
		severity model.Severity
		want     axes.Grade
	}{
		{"security critical", axes.Security, model.SeverityCritical, axes.GradeF},
		{"security high", axes.Security, model.SeverityHigh, axes.GradeD},
		{"security medium", axes.Security, model.SeverityMedium, axes.GradeC},
		{"security low", axes.Security, model.SeverityLow, axes.GradeB},
		{"permission critical", axes.PermissionHygiene, model.SeverityCritical, axes.GradeF},
		{"permission high", axes.PermissionHygiene, model.SeverityHigh, axes.GradeD},
		{"transparency critical", axes.Transparency, model.SeverityCritical, axes.GradeD},
		{"transparency medium", axes.Transparency, model.SeverityMedium, axes.GradeB},
		{"quality critical", axes.Quality, model.SeverityCritical, axes.GradeC},
		{"quality low", axes.Quality, model.SeverityLow, axes.GradeA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := grade.Grade(tt.axis, []model.Finding{
				{RuleID: "x", Severity: tt.severity, Axis: tt.axis},
			})
			if res.Grade != tt.want {
				t.Errorf("got %q, want %q", res.Grade, tt.want)
			}
		})
	}
}

func TestGradeMultipleSameSeverity(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "a", Severity: model.SeverityHigh, Axis: axes.Security},
		{RuleID: "b", Severity: model.SeverityHigh, Axis: axes.Security},
		{RuleID: "a", Severity: model.SeverityHigh, Axis: axes.Security},
	}
	res := grade.Grade(axes.Security, findings)
	if res.Grade != axes.GradeD {
		t.Errorf("3 high findings: grade = %q, want D", res.Grade)
	}
	if len(res.DrivingFindings) != 2 {
		t.Fatalf("driving findings = %d, want 2", len(res.DrivingFindings))
	}
	var aCount, bCount int
	for _, d := range res.DrivingFindings {
		switch d.RuleID {
		case "a":
			aCount = d.Count
		case "b":
			bCount = d.Count
		}
	}
	if aCount != 2 || bCount != 1 {
		t.Errorf("aggregation = a:%d b:%d, want a:2 b:1", aCount, bCount)
	}
}

func TestGradeMixedSeveritiesWorstWins(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "low", Severity: model.SeverityLow, Axis: axes.Security},
		{RuleID: "crit", Severity: model.SeverityCritical, Axis: axes.Security},
		{RuleID: "med", Severity: model.SeverityMedium, Axis: axes.Security},
	}
	res := grade.Grade(axes.Security, findings)
	if res.Grade != axes.GradeF {
		t.Errorf("mixed with critical: grade = %q, want F", res.Grade)
	}
	if len(res.DrivingFindings) != 1 || res.DrivingFindings[0].RuleID != "crit" {
		t.Errorf("driving findings should only include critical, got %+v", res.DrivingFindings)
	}
}

func TestRationaleIncludesRuleID(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "claude_md.comment_and_control", Severity: model.SeverityCritical, Axis: axes.Security, Description: "Comment-and-Control pattern"},
	}
	res := grade.Grade(axes.Security, findings)
	if res.Rationale == "" {
		t.Error("rationale should not be empty for a Critical finding")
	}
}
