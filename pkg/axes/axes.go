// Package axes defines the trust-score axis taxonomy used by skill-detector.
// String values are wire-stable: they appear in JSON output, badge URLs,
// and downstream DB columns. Change requires a major version bump.
package axes

// Axis identifies one of the four trust-score dimensions.
type Axis string

const (
	Security          Axis = "security"
	PermissionHygiene Axis = "permission_hygiene"
	Transparency      Axis = "transparency"
	Quality           Axis = "quality"
)

// Order is the canonical display order for the four axes.
var Order = []Axis{Security, PermissionHygiene, Transparency, Quality}

// Grade is an A–F letter grade per axis.
type Grade string

const (
	GradeA Grade = "A"
	GradeB Grade = "B"
	GradeC Grade = "C"
	GradeD Grade = "D"
	GradeF Grade = "F"
)
