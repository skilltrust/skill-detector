package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/grade"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/rules"
)

// Grade-scale reachability.
//
// The published claim is that the A-F scale is not fully used: security and
// permission_hygiene produce A/C/D/F, transparency produces A/B, and quality
// produces A and nothing else. docs/architecture.md and docs/STATUS.md state
// that claim to readers; this test is what stops it rotting.
//
// WHY THIS LIVES IN cmd/skill-detector AND NOT IN pkg/grade
//
//   - pkg/rules imports pkg/grade (pkg/rules/registry.go), so a test inside
//     pkg/grade that needs DefaultRegistry() would be an import cycle.
//   - applyStrictMCP is unexported in package main and is one of the places an
//     emitted (severity, axis) pair differs from the registered one. This is
//     the only package that sees both it and the registry.
//
// WHY IT ENUMERATES EMITTED PAIRS AND NOT REGISTERED ONES
//
// A rule's registered severity is a CEILING and the thing registry.Checksum()
// hashes. The cap table is indexed by what a finding actually CARRIES, which
// can differ in three places:
//
//  1. baseRule.newFindingAs (pkg/rules/rule.go) — a rule overrides severity and
//     axis at match time. SD-007's two demotion sites are the reason grade B
//     exists at all, and a registry-only enumeration cannot see them.
//  2. applyStrictMCP (main.go) — --strict-mcp upgrades SD-021 Medium->High
//     without touching the registry, deliberately, so the checksum stays put.
//  3. A hand-built model.Finding literal inside a rule would bypass both
//     constructors. None exists today; the test fails if one appears.
//
// Grade() reads Finding.Severity. Finding.EffSeverity is a different field
// (config overrides, triage) consumed by the --fail-on severity threshold, not
// by grading — pinned separately by TestGradeReadsSeverityNotEffSeverity.

// emitted is one (severity, axis) pair a finding can carry when it reaches
// grade.Grade.
type emitted struct {
	sev  model.Severity
	axis axes.Axis
}

// wantReachable is the published claim, one entry per axis, sorted A..F.
// Changing this map means the product's documented grade scale changed:
// docs/architecture.md, docs/STATUS.md and the hosted methodology page all
// state it. Update them in the same commit.
var wantReachable = map[axes.Axis][]axes.Grade{
	axes.Security:          {axes.GradeA, axes.GradeC, axes.GradeD, axes.GradeF},
	axes.PermissionHygiene: {axes.GradeA, axes.GradeC, axes.GradeD, axes.GradeF},
	axes.Transparency:      {axes.GradeA, axes.GradeB},
	axes.Quality:           {axes.GradeA},
}

// gradeOrder is display order, used only to make failure output readable.
var gradeOrder = map[axes.Grade]int{
	axes.GradeA: 0, axes.GradeB: 1, axes.GradeC: 2, axes.GradeD: 3, axes.GradeF: 4,
}

func TestGradeScaleReachability(t *testing.T) {
	pairs := map[emitted][]string{}
	for p, src := range registeredPairs(t) {
		pairs[p] = append(pairs[p], src)
	}
	for p, src := range overridePairs(t) {
		pairs[p] = append(pairs[p], src...)
	}
	for p, src := range strictMCPPairs(t) {
		pairs[p] = append(pairs[p], src)
	}

	// Run every emitted pair through the real grader rather than restating the
	// cap table here: a cap-table edit must show up as a reachability change.
	reach := map[axes.Axis]map[axes.Grade][]string{}
	for _, a := range axes.Order {
		reach[a] = map[axes.Grade][]string{}
		// A is reached through the "no findings on this axis" branch, on every
		// axis, always.
		reach[a][grade.Grade(a, nil).Grade] = []string{"no findings on this axis"}
	}
	for p, srcs := range pairs {
		g := grade.Grade(p.axis, []model.Finding{{
			RuleID:      "REACHABILITY",
			Description: "reachability probe",
			Severity:    p.sev,
			EffSeverity: p.sev,
			Axis:        p.axis,
		}}).Grade
		reach[p.axis][g] = append(reach[p.axis][g], srcs...)
	}

	for _, a := range axes.Order {
		var have []axes.Grade
		for g := range reach[a] {
			have = append(have, g)
		}
		sort.Slice(have, func(i, j int) bool { return gradeOrder[have[i]] < gradeOrder[have[j]] })

		want := wantReachable[a]
		if !sameGrades(have, want) {
			t.Errorf("axis %s: reachable grades %v, documented %v\n%s",
				a, have, want, explain(reach[a]))
		}
	}
}

func sameGrades(a, b []axes.Grade) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func explain(m map[axes.Grade][]string) string {
	var keys []axes.Grade
	for g := range m {
		keys = append(keys, g)
	}
	sort.Slice(keys, func(i, j int) bool { return gradeOrder[keys[i]] < gradeOrder[keys[j]] })
	var b strings.Builder
	for _, g := range keys {
		srcs := append([]string(nil), m[g]...)
		sort.Strings(srcs)
		fmt.Fprintf(&b, "  %s <- %s\n", g, strings.Join(srcs, ", "))
	}
	return b.String()
}

// registeredPairs reads the ceiling pair of every rule in the shipped registry.
func registeredPairs(t *testing.T) map[emitted]string {
	t.Helper()
	reg := rules.DefaultRegistry()
	if reg.Count() == 0 {
		t.Fatal("DefaultRegistry() is empty — enumeration would prove nothing")
	}
	out := map[emitted]string{}
	for _, r := range reg.All() {
		out[emitted{sev: r.Severity(), axis: r.Axis()}] = "registry:" + r.ID()
	}
	return out
}

// strictMCPPairs executes applyStrictMCP on a finding built from SD-021's own
// registered metadata and records what comes out. Executed, not read: the
// upgrade is deliberately absent from the registry so the checksum stays put,
// which means only running it tells the truth about what it emits.
func strictMCPPairs(t *testing.T) map[emitted]string {
	t.Helper()
	var sd021 rules.Rule
	for _, r := range rules.DefaultRegistry().All() {
		if r.ID() == "SD-021" {
			sd021 = r
		}
	}
	if sd021 == nil {
		t.Fatal("SD-021 is not registered; applyStrictMCP targets it by ID and would now be dead code")
	}
	res := &model.ScanResult{
		Findings: []model.Finding{{
			RuleID:      sd021.ID(),
			Description: "strict-mcp probe",
			Severity:    sd021.Severity(),
			EffSeverity: sd021.Severity(),
			Axis:        sd021.Axis(),
		}},
		Axes: map[axes.Axis]model.AxisResult{},
	}
	applyStrictMCP(res)
	f := res.Findings[0]
	return map[emitted]string{
		{sev: f.Severity, axis: f.Axis}: "applyStrictMCP:SD-021 --strict-mcp",
	}
}

var severityByName = map[string]model.Severity{
	"model.SeverityCritical": model.SeverityCritical,
	"model.SeverityHigh":     model.SeverityHigh,
	"model.SeverityMedium":   model.SeverityMedium,
	"model.SeverityLow":      model.SeverityLow,
	"model.SeverityInfo":     model.SeverityInfo,
}

var axisByName = map[string]axes.Axis{
	"axes.Security":          axes.Security,
	"axes.PermissionHygiene": axes.PermissionHygiene,
	"axes.Transparency":      axes.Transparency,
	"axes.Quality":           axes.Quality,
}

// overridePairs parses pkg/rules and returns the (severity, axis) pair of every
// newFindingAs call site. Source parsing, not execution: a call site that no
// corpus sample happens to reach still widens the scale, and the claim in the
// docs is about what the code CAN emit.
//
// It also fails on a hand-built model.Finding literal outside rule.go, which
// would be a third way to emit a pair neither collector sees.
func overridePairs(t *testing.T) map[emitted][]string {
	t.Helper()
	dir := filepath.Join("..", "..", "pkg", "rules")
	fset := token.NewFileSet()
	// parser.ParseDir is deprecated since Go 1.25 in favor of
	// golang.org/x/tools/go/packages, which considers build tags. Not
	// applicable here: pkg/rules carries no build-tagged files, and adding
	// a new module dependency for a single directory scan is out of
	// proportion to what this test needs.
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool { //nolint:staticcheck // see comment above
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}

	out := map[emitted][]string{}
	sites := 0
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			base := filepath.Base(path)
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					sel, ok := node.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "newFindingAs" {
						return true
					}
					sites++
					pos := fset.Position(node.Pos())
					if len(node.Args) < 4 {
						t.Fatalf("%s:%d: newFindingAs call has %d args; this test reads args[2] (severity) and args[3] (axis) — the signature changed",
							base, pos.Line, len(node.Args))
					}
					sevName := exprString(fset, node.Args[2])
					axisName := exprString(fset, node.Args[3])
					sev, ok := severityByName[sevName]
					if !ok {
						t.Fatalf("%s:%d: newFindingAs severity argument %q is not a model.Severity constant; this test can no longer enumerate what the call emits",
							base, pos.Line, sevName)
					}
					axis, ok := axisByName[axisName]
					if !ok {
						t.Fatalf("%s:%d: newFindingAs axis argument %q is not an axes.Axis constant; this test can no longer enumerate what the call emits",
							base, pos.Line, axisName)
					}
					p := emitted{sev: sev, axis: axis}
					out[p] = append(out[p], fmt.Sprintf("newFindingAs:%s:%d", base, pos.Line))
				case *ast.CompositeLit:
					if base == "rule.go" {
						return true
					}
					sel, ok := node.Type.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Finding" {
						return true
					}
					if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "model" {
						return true
					}
					pos := fset.Position(node.Pos())
					t.Fatalf("%s:%d: a model.Finding is constructed directly, bypassing newFinding/newFindingAs; "+
						"the severity and axis it carries are invisible to this test — route it through a constructor or teach this test to read it",
						base, pos.Line)
				}
				return true
			})
		}
	}
	if sites == 0 {
		t.Fatalf("no newFindingAs call sites found under %s — either the helper was renamed or the scan is looking in the wrong place; either way this test is no longer guarding anything", dir)
	}
	return out
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, e); err != nil {
		return ""
	}
	return b.String()
}

// TestGradeReadsSeverityNotEffSeverity pins the field the cap table is indexed
// by. EffSeverity is written by scorer.ApplyOverrides from user config and read
// by the --fail-on severity threshold (main.go); if grading ever switched to
// it, a user config override would silently move published grades and the
// reachability claim above would be about the wrong field.
func TestGradeReadsSeverityNotEffSeverity(t *testing.T) {
	res := grade.Grade(axes.Security, []model.Finding{{
		RuleID:      "PROBE",
		Description: "probe",
		Severity:    model.SeverityMedium,
		EffSeverity: model.SeverityCritical,
		Axis:        axes.Security,
	}})
	if res.Grade != axes.GradeC {
		t.Fatalf("grade = %s, want C: grading must key on Severity (Medium->C), not EffSeverity (Critical->F)", res.Grade)
	}
}
