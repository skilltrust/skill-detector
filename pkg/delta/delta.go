package delta

import (
	"fmt"
	"hash/fnv"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// GradeDelta represents per-axis grade movement.
type GradeDelta struct {
	Old, New  axes.Grade
	Direction string // "up" | "down" | "same"
}

// Delta is the diff between two ScanResults.
type Delta struct {
	PerAxis          map[axes.Axis]GradeDelta
	NewFindings      []model.Finding
	ResolvedFindings []model.Finding
	AxisExplanations map[axes.Axis]string // one-line WHY per downgraded axis
}

// findingKey identifies a finding stably across runs for diff bucketing.
// FNV-1a is used deliberately: this is content addressing, not security —
// a crypto hash would mislead readers into thinking the key carries
// integrity guarantees. The 64-bit FNV space is more than enough to
// disambiguate findings within a single scan.
func findingKey(f model.Finding) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(f.Description))
	return fmt.Sprintf("%s|%s|%d|%016x", f.RuleID, f.FilePath, f.Line, h.Sum64())
}

// gradeRank returns higher-is-better integer rank. Returns -1 for unknown.
// Accepts "A", "A+", "A-", through "F".
//
// The engine itself only ever emits bare A–F (pkg/grade picks cap-table cells),
// so the suffix arithmetic is deliberate input tolerance, not a planned feature:
// Compute runs on two JSON files the caller supplies, which are unvalidated and
// may come from another producer or a hand edit. Suffixed input then ranks
// sensibly instead of degrading to "unknown". Do not "simplify" it to a 5-value
// rank without also constraining that input (engine review F-09).
func gradeRank(g axes.Grade) int {
	if g == "" {
		return -1
	}
	s := string(g)
	tier := map[byte]int{'A': 4, 'B': 3, 'C': 2, 'D': 1, 'F': 0}
	t, ok := tier[s[0]]
	if !ok {
		return -1
	}
	base := t * 3
	if len(s) > 1 {
		switch s[1] {
		case '+':
			base++
		case '-':
			base--
		}
	}
	return base
}

// GradeArrow renders a delta as "↑ B → A" or "↓ B → D".
func GradeArrow(d GradeDelta) string {
	arrow := "↓"
	if d.Direction == "up" {
		arrow = "↑"
	}
	return fmt.Sprintf("%s %s → %s", arrow, d.Old, d.New)
}

// Compute produces a Delta between base and head. base may be nil (caller
// should detect and skip delta rendering). Direction is "same" when grades
// equal OR when base lacks the axis (best-effort — don't pretend an axis
// appeared).
func Compute(base, head *model.ScanResult) Delta {
	d := Delta{
		PerAxis:          map[axes.Axis]GradeDelta{},
		AxisExplanations: map[axes.Axis]string{},
	}

	baseAxes := map[axes.Axis]axes.Grade{}
	if base != nil {
		for k, v := range base.Axes {
			baseAxes[k] = v.Grade
		}
	}
	if head != nil {
		for k, v := range head.Axes {
			old := baseAxes[k]
			dir := "same"
			if old != "" {
				rank := gradeRank(v.Grade) - gradeRank(old)
				if rank > 0 {
					dir = "up"
				} else if rank < 0 {
					dir = "down"
				}
			}
			d.PerAxis[k] = GradeDelta{Old: old, New: v.Grade, Direction: dir}
		}
	}

	baseKeys := map[string]model.Finding{}
	if base != nil {
		for _, f := range base.Findings {
			baseKeys[findingKey(f)] = f
		}
	}
	headKeys := map[string]model.Finding{}
	if head != nil {
		for _, f := range head.Findings {
			headKeys[findingKey(f)] = f
		}
	}
	for k, f := range headKeys {
		if _, ok := baseKeys[k]; !ok {
			d.NewFindings = append(d.NewFindings, f)
		}
	}
	for k, f := range baseKeys {
		if _, ok := headKeys[k]; !ok {
			d.ResolvedFindings = append(d.ResolvedFindings, f)
		}
	}

	for axis, gd := range d.PerAxis {
		if gd.Direction != "down" {
			continue
		}
		for _, f := range d.NewFindings {
			if f.Axis == axis {
				d.AxisExplanations[axis] = fmt.Sprintf("%s — %s _(%s, %s:%d)_",
					GradeArrow(gd), f.Description, f.RuleID, f.FilePath, f.Line)
				break
			}
		}
	}
	return d
}
