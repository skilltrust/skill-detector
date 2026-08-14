package delta_test

import (
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/delta"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func sr(grades map[axes.Axis]axes.Grade, findings ...model.Finding) *model.ScanResult {
	r := &model.ScanResult{
		Axes:     map[axes.Axis]model.AxisResult{},
		Findings: findings,
	}
	for k, v := range grades {
		r.Axes[k] = model.AxisResult{Grade: v}
	}
	return r
}

func TestCompute_GradeMovement(t *testing.T) {
	base := sr(map[axes.Axis]axes.Grade{
		axes.PermissionHygiene: axes.GradeB,
		axes.Security:          axes.GradeA,
	})
	head := sr(map[axes.Axis]axes.Grade{
		axes.PermissionHygiene: axes.GradeD,
		axes.Security:          axes.GradeA,
	})
	d := delta.Compute(base, head)
	if d.PerAxis[axes.PermissionHygiene].Direction != "down" {
		t.Errorf("permission_hygiene direction=%q", d.PerAxis[axes.PermissionHygiene].Direction)
	}
	if d.PerAxis[axes.Security].Direction != "same" {
		t.Errorf("security direction=%q", d.PerAxis[axes.Security].Direction)
	}
}

func TestCompute_FindingDiff(t *testing.T) {
	base := sr(nil,
		model.Finding{RuleID: "SD-001", FilePath: "a.go", Line: 1, Description: "old", Axis: axes.PermissionHygiene},
	)
	head := sr(nil,
		model.Finding{RuleID: "SD-002", FilePath: "b.go", Line: 5, Description: "new", Axis: axes.PermissionHygiene},
	)
	d := delta.Compute(base, head)
	if len(d.NewFindings) != 1 || d.NewFindings[0].RuleID != "SD-002" {
		t.Errorf("new=%v", d.NewFindings)
	}
	if len(d.ResolvedFindings) != 1 || d.ResolvedFindings[0].RuleID != "SD-001" {
		t.Errorf("resolved=%v", d.ResolvedFindings)
	}
}

func TestCompute_StableMatchKey(t *testing.T) {
	f := model.Finding{RuleID: "X", FilePath: "x.go", Line: 10, Description: "msg", Axis: axes.PermissionHygiene}
	r := sr(nil, f)
	d := delta.Compute(r, r)
	if len(d.NewFindings) != 0 || len(d.ResolvedFindings) != 0 {
		t.Errorf("identical scans should have empty diff; new=%v resolved=%v", d.NewFindings, d.ResolvedFindings)
	}
}

func TestCompute_LineShiftIsNotChurn(t *testing.T) {
	base := sr(nil,
		model.Finding{RuleID: "SD-007", FilePath: "a.sh", Line: 3, Description: "outbound call to evil.example.com", Axis: axes.Security},
	)
	head := sr(nil,
		model.Finding{RuleID: "SD-007", FilePath: "a.sh", Line: 4, Description: "outbound call to evil.example.com", Axis: axes.Security},
	)
	d := delta.Compute(base, head)
	if len(d.NewFindings) != 0 || len(d.ResolvedFindings) != 0 {
		t.Errorf("a pure line shift must not churn; new=%v resolved=%v", d.NewFindings, d.ResolvedFindings)
	}
}

func TestCompute_LineShiftKeepsGenuineNewFinding(t *testing.T) {
	base := sr(nil,
		model.Finding{RuleID: "SD-007", FilePath: "a.sh", Line: 3, Description: "outbound call", Axis: axes.Security},
	)
	head := sr(nil,
		model.Finding{RuleID: "SD-007", FilePath: "a.sh", Line: 4, Description: "outbound call", Axis: axes.Security},
		model.Finding{RuleID: "SD-006", FilePath: "a.sh", Line: 9, Description: "hardcoded key", Axis: axes.Security},
	)
	d := delta.Compute(base, head)
	if len(d.NewFindings) != 1 || d.NewFindings[0].RuleID != "SD-006" {
		t.Errorf("genuine new finding must survive the shift pairing; new=%v", d.NewFindings)
	}
	if len(d.ResolvedFindings) != 0 {
		t.Errorf("nothing was resolved; resolved=%v", d.ResolvedFindings)
	}
}

func TestCompute_LineShiftPairsDuplicateDescriptionsOneForOne(t *testing.T) {
	// Same rule, same file, identical description twice — one occurrence is
	// deleted in head, the other shifts. Exactly one resolved, no new.
	base := sr(nil,
		model.Finding{RuleID: "SD-008", FilePath: "a.sh", Line: 5, Description: "base64 decode", Axis: axes.Security},
		model.Finding{RuleID: "SD-008", FilePath: "a.sh", Line: 9, Description: "base64 decode", Axis: axes.Security},
	)
	head := sr(nil,
		model.Finding{RuleID: "SD-008", FilePath: "a.sh", Line: 10, Description: "base64 decode", Axis: axes.Security},
	)
	d := delta.Compute(base, head)
	if len(d.NewFindings) != 0 {
		t.Errorf("shifted duplicate must not read as new; new=%v", d.NewFindings)
	}
	if len(d.ResolvedFindings) != 1 {
		t.Errorf("exactly one occurrence disappeared; resolved=%v", d.ResolvedFindings)
	}
}

func TestCompute_FindingOrderFollowsInput(t *testing.T) {
	// Deterministic output: the residue must keep scan order, not map order.
	base := sr(nil,
		model.Finding{RuleID: "SD-001", FilePath: "a.sh", Line: 1, Description: "one", Axis: axes.Security},
		model.Finding{RuleID: "SD-002", FilePath: "a.sh", Line: 2, Description: "two", Axis: axes.Security},
		model.Finding{RuleID: "SD-003", FilePath: "a.sh", Line: 3, Description: "three", Axis: axes.Security},
	)
	head := sr(nil,
		model.Finding{RuleID: "SD-011", FilePath: "b.sh", Line: 1, Description: "eleven", Axis: axes.Security},
		model.Finding{RuleID: "SD-012", FilePath: "b.sh", Line: 2, Description: "twelve", Axis: axes.Security},
		model.Finding{RuleID: "SD-013", FilePath: "b.sh", Line: 3, Description: "thirteen", Axis: axes.Security},
	)
	for i := 0; i < 20; i++ {
		d := delta.Compute(base, head)
		got := []string{d.NewFindings[0].RuleID, d.NewFindings[1].RuleID, d.NewFindings[2].RuleID}
		if got[0] != "SD-011" || got[1] != "SD-012" || got[2] != "SD-013" {
			t.Fatalf("new findings out of head order: %v", got)
		}
		gotRes := []string{d.ResolvedFindings[0].RuleID, d.ResolvedFindings[1].RuleID, d.ResolvedFindings[2].RuleID}
		if gotRes[0] != "SD-001" || gotRes[1] != "SD-002" || gotRes[2] != "SD-003" {
			t.Fatalf("resolved findings out of base order: %v", gotRes)
		}
	}
}

func TestCompute_AxisExplanationOnDowngrade(t *testing.T) {
	base := sr(map[axes.Axis]axes.Grade{axes.PermissionHygiene: axes.GradeB})
	head := sr(map[axes.Axis]axes.Grade{axes.PermissionHygiene: axes.GradeD},
		model.Finding{RuleID: "SD-014", Axis: axes.PermissionHygiene, FilePath: ".claude/settings.json", Line: 42, Description: "wildcard"},
	)
	d := delta.Compute(base, head)
	exp := d.AxisExplanations[axes.PermissionHygiene]
	if exp == "" {
		t.Fatalf("expected explanation for permission_hygiene downgrade; got: %v", d.AxisExplanations)
	}
	if !strings.Contains(exp, "SD-014") || !strings.Contains(exp, ".claude/settings.json:42") {
		t.Errorf("explanation lacks expected rule/path/line; got %q", exp)
	}
}

func TestCompute_AxisOnlyInHead(t *testing.T) {
	base := sr(nil)
	head := sr(map[axes.Axis]axes.Grade{axes.Security: axes.GradeB})
	d := delta.Compute(base, head)
	gd := d.PerAxis[axes.Security]
	if gd.New != axes.GradeB || gd.Old != "" || gd.Direction != "same" {
		t.Errorf("axis-only-in-head should report new grade with empty old + same direction; got %+v", gd)
	}
}

func TestCompute_NilBase(t *testing.T) {
	head := sr(map[axes.Axis]axes.Grade{axes.Security: axes.GradeC})
	d := delta.Compute(nil, head)
	if d.PerAxis[axes.Security].New != axes.GradeC {
		t.Errorf("nil base: head grade not surfaced")
	}
	if d.PerAxis[axes.Security].Direction != "same" {
		t.Errorf("nil base: direction should be same, got %q", d.PerAxis[axes.Security].Direction)
	}
}
