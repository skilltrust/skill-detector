package grade

import (
	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// caps maps (axis, severity) → grade. Worst-finding-wins algorithm uses
// this directly: the max-severity finding on an axis determines the grade.
// Stricter axes (security, permission_hygiene) cap harder.
var caps = map[axes.Axis]map[model.Severity]axes.Grade{
	axes.Security: {
		model.SeverityCritical: axes.GradeF,
		model.SeverityHigh:     axes.GradeD,
		model.SeverityMedium:   axes.GradeC,
		model.SeverityLow:      axes.GradeB,
		model.SeverityInfo:     axes.GradeA,
	},
	axes.PermissionHygiene: {
		model.SeverityCritical: axes.GradeF,
		model.SeverityHigh:     axes.GradeD,
		model.SeverityMedium:   axes.GradeC,
		model.SeverityLow:      axes.GradeB,
		model.SeverityInfo:     axes.GradeA,
	},
	axes.Transparency: {
		model.SeverityCritical: axes.GradeD,
		model.SeverityHigh:     axes.GradeC,
		model.SeverityMedium:   axes.GradeB,
		model.SeverityLow:      axes.GradeB,
		model.SeverityInfo:     axes.GradeA,
	},
	axes.Quality: {
		model.SeverityCritical: axes.GradeC,
		model.SeverityHigh:     axes.GradeB,
		model.SeverityMedium:   axes.GradeB,
		model.SeverityLow:      axes.GradeA,
		model.SeverityInfo:     axes.GradeA,
	},
}

// rationaleTemplate produces a per-grade rationale for a given (axis, severity)
// using the top rule description. Wire-stable strings — change requires
// a checksum bump (Plan Task 22).
func rationaleTemplate(axis axes.Axis, sev model.Severity, topDescription string) string {
	switch sev {
	case model.SeverityCritical:
		return "Critical: " + topDescription
	case model.SeverityHigh:
		return "High-severity issue: " + topDescription
	case model.SeverityMedium:
		return "Medium-severity issue: " + topDescription
	case model.SeverityLow:
		return "Low-severity issue: " + topDescription
	case model.SeverityInfo:
		return "Informational: " + topDescription
	default:
		return topDescription
	}
}

// canonicalTemplateString returns a stable string form of templates used by
// the registry checksum. Any change to template text changes this string and
// therefore invalidates a pinned ldflag checksum.
func canonicalTemplateString() string {
	return "v1:critical=Critical: %s;high=High-severity issue: %s;medium=Medium-severity issue: %s;low=Low-severity issue: %s;info=Informational: %s"
}
