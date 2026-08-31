package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
// can differ in four places:
//
//  1. baseRule.newFindingAs (pkg/rules/rule.go) — a rule overrides severity and
//     axis at match time. SD-007's two demotion sites are the reason grade B
//     exists at all, and a registry-only enumeration cannot see them.
//  2. applyStrictMCP (main.go) — --strict-mcp upgrades SD-021 Medium->High
//     without touching the registry, deliberately, so the checksum stays put.
//     assertStrictMCPIsSoleMutator pins it as the ONE function in
//     cmd/skill-detector allowed to mutate a Finding's Severity/EffSeverity/
//     Axis after construction — a second mutator elsewhere in the package
//     would otherwise emit a pair no collector here ever executes.
//  3. A hand-built model.Finding literal inside pkg/rules would bypass both
//     constructors — either a bare composite literal, or, less obviously, an
//     element inside a []model.Finding{...} slice literal with its type
//     elided (Go permits that; the AST records a nil Type on the element, so
//     matching only on "a *ast.SelectorExpr named Finding" misses it).
//  4. A post-hoc field mutation on a value already built by a constructor —
//     `f := r.newFinding(...); f.Severity = X` — is structurally identical to
//     what newFindingAs does internally, but outside newFinding/newFindingAs
//     it is invisible to every collector above.
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

// wantEmittedSeverities is the published PREMISE wantReachable's letter set
// is derived from: which severities each axis's collectors actually emit,
// as a set, independent of what letter each one caps to. It is not
// redundant with wantReachable — see the comment at its call site in
// TestGradeScaleReachability for why both assertions have to stay.
//
// docs/architecture.md states this as prose ("no rule anywhere emits Low or
// Info", "nothing assigns the quality axis", "transparency only ever
// carries Medium"); update it in the same commit as this map.
var wantEmittedSeverities = map[axes.Axis]map[model.Severity]bool{
	axes.Security:          {model.SeverityCritical: true, model.SeverityHigh: true, model.SeverityMedium: true},
	axes.PermissionHygiene: {model.SeverityCritical: true, model.SeverityHigh: true, model.SeverityMedium: true},
	axes.Transparency:      {model.SeverityMedium: true},
	axes.Quality:           {},
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
	// Not a pair collector: fails on its own if a second severity/axis
	// mutator appears in cmd/skill-detector alongside applyStrictMCP. See
	// point 2 in the package doc comment above.
	assertStrictMCPIsSoleMutator(t)

	// Two assertions follow that guard DIFFERENT things — do not delete
	// either as redundant with the other:
	//
	//   - assertEmittedSeverities (below) pins the PREMISE: which
	//     severities each axis's collectors actually emit. A rule or
	//     newFindingAs site emitting (Low, Quality) or (Low, Transparency),
	//     or an Info-severity finding anywhere, changes that premise even
	//     though the cap table sends it to a letter the axis already
	//     reaches (Quality already reaches A, Transparency already reaches
	//     B) — the letter-set check two paragraphs down would pass it
	//     silently. This one does not.
	//   - the have/want comparison over `reach` (below) pins the SCALE:
	//     which letters the published table shows readers. A cap-table edit
	//     that keeps the same severities but changes what they cap to would
	//     pass assertEmittedSeverities (same pairs, same premise) and has to
	//     be caught here instead.
	assertEmittedSeverities(t, pairs)

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

// assertEmittedSeverities pins the set of severities each axis's collectors
// actually emit against wantEmittedSeverities. Unlike the letter-set
// assertion in TestGradeScaleReachability, this fails on a new pair even
// when the cap table happens to send it to an already-reachable letter, and
// it names the new pair and its source(s) the same way the letter-set
// failure names the axis and its sources.
func assertEmittedSeverities(t *testing.T, pairs map[emitted][]string) {
	t.Helper()
	have := map[axes.Axis]map[model.Severity][]string{}
	for _, a := range axes.Order {
		have[a] = map[model.Severity][]string{}
	}
	for p, srcs := range pairs {
		have[p.axis][p.sev] = append(have[p.axis][p.sev], srcs...)
	}

	for _, a := range axes.Order {
		want := wantEmittedSeverities[a]
		for sev, srcs := range have[a] {
			if want[sev] {
				continue
			}
			sorted := append([]string(nil), srcs...)
			sort.Strings(sorted)
			t.Errorf("axis %s: severity %s is emitted but not documented — new pair (%s, %s) from: %s",
				a, sev, sev, a, strings.Join(sorted, ", "))
		}
		for sev := range want {
			if _, ok := have[a][sev]; !ok {
				t.Errorf("axis %s: severity %s is documented in wantEmittedSeverities but no collector emits it anymore — "+
					"update wantEmittedSeverities (and wantReachable, if the letter set changed too) in the same commit",
					a, sev)
			}
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

// modelImportPath and axesImportPath are the import paths whose local names
// (possibly aliased) the AST guards below need to resolve per file — see
// importedPkgName.
const (
	modelImportPath = "github.com/velzepooz/skill-detector/pkg/model"
	axesImportPath  = "github.com/velzepooz/skill-detector/pkg/axes"
)

// findingMutableFields are the model.Finding fields the cap table is indexed
// by. A direct assignment to any of them outside an allowed
// constructor/mutator is a route to emit a (severity, axis) pair no
// collector in this file executes.
var findingMutableFields = map[string]bool{
	"Severity":    true,
	"EffSeverity": true,
	"Axis":        true,
}

// importedPkgName resolves the local identifier a file uses for importPath —
// its explicit alias if the import declares one, otherwise the path's last
// segment (which is also what an unaliased import resolves to for every
// package under this module, since none of them renames itself). Hardcoding
// "model"/"axes" would let an aliased import (`m "…/pkg/model"`) slip a
// Finding literal or a newFindingAs argument past every check below.
func importedPkgName(file *ast.File, importPath string) string {
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != importPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		break
	}
	parts := strings.Split(importPath, "/")
	return parts[len(parts)-1]
}

// isFindingType reports whether e is a selector naming modelAlias.Finding —
// the type of a []model.Finding element or a bare model.Finding{...} literal.
func isFindingType(e ast.Expr, modelAlias string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Finding" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == modelAlias
}

// assignedFindingField reports the field name if lhs is a selector targeting
// Finding.Severity/EffSeverity/Axis, whatever the receiver expression looks
// like (a plain identifier, an index expression, a chained selector, ...).
// Purely structural — it does not type-check that the receiver is actually a
// model.Finding, matching how the review that requested this guard specified
// it: any such selector outside the allowed function is worth failing on.
func assignedFindingField(lhs ast.Expr) string {
	sel, ok := lhs.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if findingMutableFields[sel.Sel.Name] {
		return sel.Sel.Name
	}
	return ""
}

// parseNonTestGoFiles parses every non-test .go file directly inside dir and
// returns them keyed by base filename.
//
// This uses os.ReadDir + parser.ParseFile rather than parser.ParseDir:
// ParseDir is deprecated since Go 1.25 in favor of golang.org/x/tools/go/
// packages, which considers build tags — not applicable here (neither
// pkg/rules nor cmd/skill-detector carries build-tagged files), and adding a
// new module dependency for a single-directory scan is out of proportion to
// what this test needs. ReadDir+ParseFile finds the identical file set.
func parseNonTestGoFiles(t *testing.T, fset *token.FileSet, dir string) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	out := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		out[name] = file
	}
	return out
}

// overridePairs parses pkg/rules and returns the (severity, axis) pair of
// every newFindingAs call site. Source parsing, not execution: a call site
// that no corpus sample happens to reach still widens the scale, and the
// claim in the docs is about what the code CAN emit.
//
// It also fails (via t.Errorf, so a stray literal does not mask a concurrent
// reachability drift elsewhere) on:
//   - a hand-built model.Finding literal outside newFinding/newFindingAs,
//   - a []model.Finding{...} element with its type elided,
//   - a post-hoc assignment to .Severity/.EffSeverity/.Axis outside
//     newFinding/newFindingAs,
//
// each a way to emit a pair neither collector sees. newFinding and
// newFindingAs themselves are exempt — they are the routing this test wants
// everything else to go through — but nothing else in rule.go is; only those
// two function bodies are skipped.
func overridePairs(t *testing.T) map[emitted][]string {
	t.Helper()
	dir := filepath.Join("..", "..", "pkg", "rules")
	fset := token.NewFileSet()
	files := parseNonTestGoFiles(t, fset, dir)

	out := map[emitted][]string{}
	sites := 0
	for base, file := range files {
		modelAlias := importedPkgName(file, modelImportPath)
		axesAlias := importedPkgName(file, axesImportPath)
		severityByName := map[string]model.Severity{
			modelAlias + ".SeverityCritical": model.SeverityCritical,
			modelAlias + ".SeverityHigh":     model.SeverityHigh,
			modelAlias + ".SeverityMedium":   model.SeverityMedium,
			modelAlias + ".SeverityLow":      model.SeverityLow,
			modelAlias + ".SeverityInfo":     model.SeverityInfo,
		}
		axisByName := map[string]axes.Axis{
			axesAlias + ".Security":          axes.Security,
			axesAlias + ".PermissionHygiene": axes.PermissionHygiene,
			axesAlias + ".Transparency":      axes.Transparency,
			axesAlias + ".Quality":           axes.Quality,
		}

		for _, decl := range file.Decls {
			fd, isFunc := decl.(*ast.FuncDecl)
			exempt := isFunc && base == "rule.go" && (fd.Name.Name == "newFinding" || fd.Name.Name == "newFindingAs")

			ast.Inspect(decl, func(n ast.Node) bool {
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
					if exempt {
						return true
					}
					if isFindingType(node.Type, modelAlias) {
						pos := fset.Position(node.Pos())
						t.Errorf("%s:%d: a model.Finding is constructed directly, bypassing newFinding/newFindingAs; "+
							"the severity and axis it carries are invisible to this test — route it through a constructor or teach this test to read it",
							base, pos.Line)
						return true
					}
					// A []model.Finding{...} element can be written with its
					// own type elided ({Severity: X} rather than
					// model.Finding{Severity: X}) — the AST records a nil
					// Type on that element, so the check above never sees
					// it on the element's own visit. Catch it here, from the
					// slice literal that contains it. A legitimate element
					// (r.newFinding(...)) is a *ast.CallExpr, not a
					// composite literal, and is left alone.
					if arr, ok := node.Type.(*ast.ArrayType); ok && isFindingType(arr.Elt, modelAlias) {
						for _, elt := range node.Elts {
							lit, ok := elt.(*ast.CompositeLit)
							if !ok || lit.Type != nil {
								continue
							}
							pos := fset.Position(lit.Pos())
							t.Errorf("%s:%d: a []model.Finding element is constructed directly with its type elided, bypassing newFinding/newFindingAs; "+
								"the severity and axis it carries are invisible to this test — route it through a constructor or teach this test to read it",
								base, pos.Line)
						}
					}

				case *ast.AssignStmt:
					if exempt {
						return true
					}
					for _, lhs := range node.Lhs {
						field := assignedFindingField(lhs)
						if field == "" {
							continue
						}
						pos := fset.Position(lhs.Pos())
						t.Errorf("%s:%d: a Finding.%s field is assigned directly outside newFinding/newFindingAs; this is a fourth way to emit a "+
							"(severity, axis) pair no collector here sees — route the mutation through newFindingAs or teach this test to read it",
							base, pos.Line, field)
					}
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

// assertStrictMCPIsSoleMutator scans cmd/skill-detector's own non-test .go
// files for a direct assignment to Finding.Severity/EffSeverity/Axis outside
// applyStrictMCP. applyStrictMCP is pinned here as ONE function, not a class
// of functions identified by a naming convention: a second --strict-*-style
// mutator added anywhere else in this package would emit a pair
// strictMCPPairs never executes and registeredPairs never sees, and would
// pass this test silently without this guard.
func assertStrictMCPIsSoleMutator(t *testing.T) {
	t.Helper()
	fset := token.NewFileSet()
	files := parseNonTestGoFiles(t, fset, ".")
	for base, file := range files {
		for _, decl := range file.Decls {
			fd, isFunc := decl.(*ast.FuncDecl)
			exempt := isFunc && fd.Name.Name == "applyStrictMCP"

			ast.Inspect(decl, func(n ast.Node) bool {
				if exempt {
					return true
				}
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assign.Lhs {
					field := assignedFindingField(lhs)
					if field == "" {
						continue
					}
					pos := fset.Position(lhs.Pos())
					t.Errorf("%s:%d: a Finding.%s field is assigned directly outside applyStrictMCP; a second severity/axis mutator in "+
						"cmd/skill-detector would emit a pair this test never sees — teach TestGradeScaleReachability about it "+
						"(execute it, the way strictMCPPairs does for applyStrictMCP)",
						base, pos.Line, field)
				}
				return true
			})
		}
	}
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
