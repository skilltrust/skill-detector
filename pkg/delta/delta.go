package delta

import (
	"fmt"
	"hash/fnv"
	"maps"

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

// softKey is findingKey without the line number. An edit above a finding shifts
// its line and would otherwise make it a resolved+new pair on every unrelated
// refactor; leftovers that agree on the soft key are the same finding at a new
// line, so they are paired off before the diff is reported.
func softKey(f model.Finding) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(f.Description))
	return fmt.Sprintf("%s|%s|%016x", f.RuleID, f.FilePath, h.Sum64())
}

// pairShifted counts, per soft key, how many leftovers appear on both sides.
// A rule firing twice in one file with the same description is paired one for
// one, so a real deletion still surfaces as the residue.
func pairShifted(newLeft, resolvedLeft []model.Finding) map[string]int {
	newCount := map[string]int{}
	for _, f := range newLeft {
		newCount[softKey(f)]++
	}
	pairs := map[string]int{}
	for _, f := range resolvedLeft {
		if k := softKey(f); newCount[k] > pairs[k] {
			pairs[k]++
		}
	}
	return pairs
}

// dropPaired removes the first pairs[softKey] occurrences of each soft key,
// preserving scan order for the rest.
func dropPaired(findings []model.Finding, pairs map[string]int) []model.Finding {
	budget := maps.Clone(pairs)
	var out []model.Finding
	for _, f := range findings {
		k := softKey(f)
		if budget[k] > 0 {
			budget[k]--
			continue
		}
		out = append(out, f)
	}
	return out
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

	var baseFindings, headFindings []model.Finding
	if base != nil {
		baseFindings = base.Findings
	}
	if head != nil {
		headFindings = head.Findings
	}

	baseKeys := map[string]struct{}{}
	for _, f := range baseFindings {
		baseKeys[findingKey(f)] = struct{}{}
	}
	headKeys := map[string]struct{}{}
	for _, f := range headFindings {
		headKeys[findingKey(f)] = struct{}{}
	}

	// First pass: exact match on the line-sensitive key. Iterate the scan
	// slices, not the maps, so the diff is deterministic.
	var newLeft, resolvedLeft []model.Finding
	for _, f := range headFindings {
		if _, ok := baseKeys[findingKey(f)]; !ok {
			newLeft = append(newLeft, f)
		}
	}
	for _, f := range baseFindings {
		if _, ok := headKeys[findingKey(f)]; !ok {
			resolvedLeft = append(resolvedLeft, f)
		}
	}

	// Second pass: leftovers that differ only by line number are the same
	// finding moved by an unrelated edit — report only the residue.
	pairs := pairShifted(newLeft, resolvedLeft)
	d.NewFindings = dropPaired(newLeft, pairs)
	d.ResolvedFindings = dropPaired(resolvedLeft, pairs)

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
