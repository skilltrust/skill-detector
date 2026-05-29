# LLM Triage Verifier — Engine (Plan A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pluggable `Verifier` seam to the `skill-detector` engine so findings can be triaged (benign examples demoted out of axis grading) without breaking the deterministic floor; default behavior (no verifier) is byte-for-byte identical to today.

**Architecture:** New `pkg/triage` package defines the `Verifier` interface + verdict types + a `NoopVerifier` and a test `ScriptedVerifier`. `model.Finding` gains an optional `Triage` field and an `IsSuppressed()` method. `pkg/grade.Grade` excludes suppressed findings from the worst-severity pool. `pkg/scanner` gains `Options.Verifier` + `Options.TriageTimeout` and an `applyTriage` step that runs between the deterministic sort and grading, failing safe (un-demoted + `unavailable`) on any verifier error or deadline. The LLM verifier itself and verdict caching live in `skilltrust` (Plan B), not here.

**Tech Stack:** Go (stdlib only — `context`, `slices`, `fmt`, `time`). Existing packages: `pkg/model`, `pkg/grade`, `pkg/scanner`, `pkg/axes`, `pkg/rules`.

---

## Scope note

The full design (`docs/specs/2026-05-29-llm-triage-verifier-design.md`) spans two subsystems. This is **Plan A — engine only** (`skill-detector` repo). **Plan B — SaaS** (`skilltrust`: LLM verifier impl, prompt + anti-injection, content-hash verdict cache in DB, deadline/concurrency wrapper, tier gating, UI states, PR-bot rendering, benchmark over SP-7) depends on the interface produced here and is written separately. Model selection is deferred to research task #5 and does not block this plan.

## File Structure

- **Create** `pkg/triage/triage.go` — `Verifier` interface, `Classification`, `Verdict`, `VerdictKey`, `NoopVerifier`. One responsibility: the triage contract + the inert default.
- **Create** `pkg/triage/scripted.go` — `ScriptedVerifier` deterministic double for tests across packages (exported, lives in the main package so `pkg/scanner` tests can import it).
- **Create** `pkg/triage/triage_test.go` — tests for `NoopVerifier` and `ScriptedVerifier`.
- **Modify** `pkg/model/model.go` — add `TriageVerdict` struct, `Finding.Triage` field, `TriageDemoteThreshold` const, `Finding.IsSuppressed()` method.
- **Modify** `pkg/model/model_test.go` — add `IsSuppressed` table test.
- **Modify** `pkg/grade/grade.go` — exclude suppressed findings from the axis pool; append suppressed count to the "no findings" rationale.
- **Modify** `pkg/grade/grade_test.go` — add suppression tests.
- **Modify** `pkg/scanner/scanner.go` — add `Options.Verifier`, `Options.TriageTimeout`, `applyTriage` step, bump `SchemaVersion` to `"1.3"`.
- **Modify** `pkg/scanner/scanner_test.go` — add `applyTriage` tests + schema-version assertion.

No import cycles: `model → axes`; `triage → model`; `scanner → triage, model, grade`; `grade → model`. `model` must NOT import `triage` (the threshold/classification string is duplicated as a literal there, by design).

---

## Task 1: triage package — interface, verdict types, NoopVerifier

**Files:**
- Create: `pkg/triage/triage.go`
- Test: `pkg/triage/triage_test.go`

- [ ] **Step 1: Write the failing test**

Create `pkg/triage/triage_test.go`:

```go
package triage_test

import (
	"context"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/triage"
)

func TestNoopVerifier_ReturnsUncertainPerFinding(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "SD-009", Line: 3},
		{RuleID: "SD-007", Line: 8},
	}
	got, err := triage.NoopVerifier{}.Classify(context.Background(), model.FileContext{}, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(findings) {
		t.Fatalf("want %d verdicts, got %d", len(findings), len(got))
	}
	for i, v := range got {
		if v.Classification != triage.ClassUncertain {
			t.Errorf("verdict %d: want uncertain, got %s", i, v.Classification)
		}
		if v.Source != "noop" {
			t.Errorf("verdict %d: want source noop, got %q", i, v.Source)
		}
		if v.RuleID != findings[i].RuleID || v.Line != findings[i].Line {
			t.Errorf("verdict %d: key mismatch %s/%d", i, v.RuleID, v.Line)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/triage/ -run TestNoopVerifier -v`
Expected: FAIL — package `pkg/triage` does not compile / does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `pkg/triage/triage.go`:

```go
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
// (RuleID, Line).
type Verdict struct {
	RuleID         string
	Line           int
	Classification Classification
	Confidence     float64 // 0.0–1.0
	Rationale      string
	Source         string // e.g. "noop", "scripted", "llm:<model>", "cache"
}

// VerdictKey identifies the finding a Verdict applies to.
type VerdictKey struct {
	RuleID string
	Line   int
}

// Verifier classifies findings for one file. Implementations MUST be
// deterministic for the scanner's contract: the same (file, findings) input
// should yield the same verdicts (the hosted impl achieves this via caching).
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
			Classification: ClassUncertain,
			Source:         "noop",
		}
	}
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/triage/ -run TestNoopVerifier -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/triage/triage.go pkg/triage/triage_test.go
git commit -m "feat(triage): add Verifier interface, Verdict types, NoopVerifier"
```

---

## Task 2: ScriptedVerifier test double

**Files:**
- Create: `pkg/triage/scripted.go`
- Test: `pkg/triage/triage_test.go` (append)

- [ ] **Step 1: Write the failing test**

Append to `pkg/triage/triage_test.go`:

```go
func TestScriptedVerifier_ReturnsRegisteredOrUncertain(t *testing.T) {
	sv := triage.ScriptedVerifier{Verdicts: map[triage.VerdictKey]triage.Verdict{
		{RuleID: "SD-009", Line: 3}: {
			RuleID: "SD-009", Line: 3,
			Classification: triage.ClassBenign, Confidence: 0.9,
			Rationale: "doc example", Source: "scripted",
		},
	}}
	findings := []model.Finding{
		{RuleID: "SD-009", Line: 3},
		{RuleID: "SD-007", Line: 8}, // unregistered → uncertain
	}
	got, err := sv.Classify(context.Background(), model.FileContext{}, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].Classification != triage.ClassBenign || got[0].Confidence != 0.9 {
		t.Errorf("finding 0: want benign/0.9, got %s/%v", got[0].Classification, got[0].Confidence)
	}
	if got[1].Classification != triage.ClassUncertain {
		t.Errorf("finding 1: want uncertain, got %s", got[1].Classification)
	}
}

func TestScriptedVerifier_ReturnsErr(t *testing.T) {
	sv := triage.ScriptedVerifier{Err: errTest}
	_, err := sv.Classify(context.Background(), model.FileContext{}, []model.Finding{{RuleID: "X"}})
	if err != errTest {
		t.Fatalf("want errTest, got %v", err)
	}
}

var errTest = errorsNew("simulated llm failure")

// errorsNew avoids importing errors at top just for one sentinel.
func errorsNew(s string) error { return simpleErr(s) }

type simpleErr string

func (e simpleErr) Error() string { return string(e) }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/triage/ -run TestScriptedVerifier -v`
Expected: FAIL — `triage.ScriptedVerifier` undefined.

- [ ] **Step 3: Write minimal implementation**

Create `pkg/triage/scripted.go`:

```go
package triage

import (
	"context"

	"github.com/velzepooz/skill-detector/pkg/model"
)

// ScriptedVerifier is a deterministic Verifier double for tests. It returns the
// verdict registered for a finding's (RuleID, Line); unregistered findings get
// an uncertain verdict. A non-nil Err simulates an LLM failure.
type ScriptedVerifier struct {
	Verdicts map[VerdictKey]Verdict
	Err      error
}

func (s ScriptedVerifier) Classify(_ context.Context, _ model.FileContext, findings []model.Finding) ([]Verdict, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	out := make([]Verdict, len(findings))
	for i, f := range findings {
		if v, ok := s.Verdicts[VerdictKey{RuleID: f.RuleID, Line: f.Line}]; ok {
			out[i] = v
			continue
		}
		out[i] = Verdict{RuleID: f.RuleID, Line: f.Line, Classification: ClassUncertain, Source: "scripted"}
	}
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/triage/ -v`
Expected: PASS (all triage tests)

- [ ] **Step 5: Commit**

```bash
git add pkg/triage/scripted.go pkg/triage/triage_test.go
git commit -m "test(triage): add ScriptedVerifier deterministic double"
```

---

## Task 3: model — Triage field, TriageVerdict, IsSuppressed

**Files:**
- Modify: `pkg/model/model.go` (Finding struct ~114-127; add types/method/const)
- Test: `pkg/model/model_test.go` (append)

- [ ] **Step 1: Write the failing test**

Append to `pkg/model/model_test.go`:

```go
func TestFinding_IsSuppressed(t *testing.T) {
	cases := []struct {
		name string
		tv   *model.TriageVerdict
		want bool
	}{
		{"nil triage", nil, false},
		{"benign high conf", &model.TriageVerdict{Classification: "benign_example", Confidence: 0.9}, true},
		{"benign at threshold", &model.TriageVerdict{Classification: "benign_example", Confidence: 0.85}, true},
		{"benign below threshold", &model.TriageVerdict{Classification: "benign_example", Confidence: 0.84}, false},
		{"real threat", &model.TriageVerdict{Classification: "real_threat", Confidence: 0.99}, false},
		{"uncertain", &model.TriageVerdict{Classification: "uncertain"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := model.Finding{Triage: c.tv}
			if got := f.IsSuppressed(); got != c.want {
				t.Errorf("IsSuppressed() = %v, want %v", got, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/model/ -run TestFinding_IsSuppressed -v`
Expected: FAIL — `model.TriageVerdict` / `Finding.Triage` / `IsSuppressed` undefined.

- [ ] **Step 3: Write minimal implementation**

In `pkg/model/model.go`, add the `Triage` field to the `Finding` struct (after the `Axis` field, line ~126):

```go
	Axis        axes.Axis      `json:"axis,omitempty"`
	Triage      *TriageVerdict `json:"triage,omitempty"`
```

Then add the following after the `Finding` struct's closing brace (after line ~127):

```go
// TriageVerdict enriches a Finding with an LLM-triage classification. It is nil
// when no verifier ran (the deterministic floor / CLI default), so it never
// appears in JSON for un-triaged scans.
type TriageVerdict struct {
	Classification string  `json:"classification"` // real_threat|benign_example|uncertain
	Confidence     float64 `json:"confidence"`     // 0.0–1.0
	Rationale      string  `json:"rationale"`
	Source         string  `json:"source"` // e.g. "noop", "llm:<model>", "cache", "unavailable"
}

// TriageDemoteThreshold is the minimum triage confidence to demote a
// benign_example finding out of axis grading. Tunable (see spec open questions).
const TriageDemoteThreshold = 0.85

// IsSuppressed reports whether triage has confidently classified this finding
// as a benign example, so it must be excluded from axis grading. The literal
// "benign_example" mirrors triage.ClassBenign (model cannot import triage —
// that would create an import cycle).
func (f Finding) IsSuppressed() bool {
	return f.Triage != nil &&
		f.Triage.Classification == "benign_example" &&
		f.Triage.Confidence >= TriageDemoteThreshold
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/model/ -v`
Expected: PASS (new test + existing model tests; nil-pointer `omitempty` keeps existing JSON golden tests unchanged)

- [ ] **Step 5: Commit**

```bash
git add pkg/model/model.go pkg/model/model_test.go
git commit -m "feat(model): add Triage verdict to Finding + IsSuppressed"
```

---

## Task 4: grade — exclude suppressed findings from the axis pool

**Files:**
- Modify: `pkg/grade/grade.go` (the `Grade` function, lines 14-76)
- Test: `pkg/grade/grade_test.go` (append)

- [ ] **Step 1: Write the failing test**

Append to `pkg/grade/grade_test.go`:

```go
func TestGrade_SuppressedFindingExcluded(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "SD-009", Axis: axes.Security, Severity: model.SeverityCritical,
			Triage: &model.TriageVerdict{Classification: "benign_example", Confidence: 0.9}},
	}
	got := grade.Grade(axes.Security, findings)
	if got.Grade != axes.GradeA {
		t.Errorf("grade = %s, want A", got.Grade)
	}
	if got.Rationale != "no findings on this axis (1 suppressed by triage)" {
		t.Errorf("rationale = %q", got.Rationale)
	}
	if len(got.DrivingFindings) != 0 {
		t.Errorf("want no driving findings, got %v", got.DrivingFindings)
	}
}

func TestGrade_SuppressedDoesNotDriveWorstSeverity(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "SD-009", Axis: axes.Security, Severity: model.SeverityCritical,
			Triage: &model.TriageVerdict{Classification: "benign_example", Confidence: 0.9}},
		{RuleID: "SD-008", Axis: axes.Security, Severity: model.SeverityMedium, Description: "base64"},
	}
	got := grade.Grade(axes.Security, findings)
	// Security MEDIUM caps to C; the suppressed CRITICAL must not force F.
	if got.Grade != axes.GradeC {
		t.Errorf("grade = %s, want C", got.Grade)
	}
}

func TestGrade_NilTriageUnchanged(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "SD-009", Axis: axes.Security, Severity: model.SeverityCritical, Description: "curl|bash"},
	}
	got := grade.Grade(axes.Security, findings)
	if got.Grade != axes.GradeF {
		t.Errorf("grade = %s, want F (deterministic floor, no triage)", got.Grade)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/grade/ -run TestGrade_Suppressed -v`
Expected: FAIL — suppressed CRITICAL still drives grade to F / rationale lacks the suppressed count.

- [ ] **Step 3: Write minimal implementation**

In `pkg/grade/grade.go`: add `"fmt"` to the imports, and replace the filter block + empty-pool block (lines 14-29) with:

```go
func Grade(axis axes.Axis, findings []model.Finding) model.AxisResult {
	// Filter to this axis, splitting triage-suppressed (benign-example)
	// findings out of the grading pool while still counting them.
	var axisFindings []model.Finding
	suppressed := 0
	for _, f := range findings {
		if f.Axis != axis {
			continue
		}
		if f.IsSuppressed() {
			suppressed++
			continue
		}
		axisFindings = append(axisFindings, f)
	}

	if len(axisFindings) == 0 {
		rationale := "no findings on this axis"
		if suppressed > 0 {
			rationale = fmt.Sprintf("no findings on this axis (%d suppressed by triage)", suppressed)
		}
		return model.AxisResult{
			Grade:           axes.GradeA,
			Rationale:       rationale,
			DrivingFindings: nil,
		}
	}
```

Leave the rest of the function (max-severity, driving findings, cap lookup, template) unchanged. The runtime "(N suppressed by triage)" string is NOT part of `canonicalTemplateString()`, so `CanonicalMetadata()` and the registry checksum are unaffected.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/grade/ -v`
Expected: PASS (new tests + existing grade tests; no-triage cases keep `suppressed == 0` and the original rationale)

- [ ] **Step 5: Commit**

```bash
git add pkg/grade/grade.go pkg/grade/grade_test.go
git commit -m "feat(grade): exclude triage-suppressed findings from axis pool"
```

---

## Task 5: scanner — Verifier option + applyTriage step (fail-safe)

**Files:**
- Modify: `pkg/scanner/scanner.go` (imports; `Options` ~27-32; `run` insert after sort ~123; bump SchemaVersion ~140; add `applyTriage`)
- Test: `pkg/scanner/scanner_test.go` (append — internal `package scanner` test)

- [ ] **Step 1: Write the failing test**

Append to `pkg/scanner/scanner_test.go` (confirm the file's first line is `package scanner`; these tests call the unexported `applyTriage`):

```go
func TestApplyTriage_DemotesBenignExample(t *testing.T) {
	s := New(nil, Options{
		Verifier: triage.ScriptedVerifier{Verdicts: map[triage.VerdictKey]triage.Verdict{
			{RuleID: "SD-009", Line: 3}: {
				RuleID: "SD-009", Line: 3,
				Classification: triage.ClassBenign, Confidence: 0.9,
				Rationale: "doc example", Source: "scripted",
			},
		}},
	})
	findings := []model.Finding{
		{RuleID: "SD-009", FilePath: "README.md", Line: 3, Axis: axes.Security, Severity: model.SeverityCritical},
	}
	files := []model.FileContext{{Path: "README.md", Content: []byte("curl x | bash")}}

	got := s.applyTriage(context.Background(), findings, files)
	if !got[0].IsSuppressed() {
		t.Fatalf("finding should be suppressed, triage=%+v", got[0].Triage)
	}
	if got[0].Triage.Source != "scripted" {
		t.Errorf("source = %q, want scripted", got[0].Triage.Source)
	}
}

func TestApplyTriage_FailSafeOnError(t *testing.T) {
	s := New(nil, Options{Verifier: triage.ScriptedVerifier{Err: errTriageDown}})
	findings := []model.Finding{
		{RuleID: "SD-009", FilePath: "a.sh", Line: 1, Axis: axes.Security, Severity: model.SeverityCritical},
	}
	files := []model.FileContext{{Path: "a.sh"}}

	got := s.applyTriage(context.Background(), findings, files)
	if got[0].IsSuppressed() {
		t.Fatal("must not suppress on verifier error")
	}
	if got[0].Triage == nil || got[0].Triage.Source != "unavailable" {
		t.Fatalf("want unavailable marker, got %+v", got[0].Triage)
	}
}

func TestApplyTriage_NilVerifierNoop(t *testing.T) {
	s := New(nil, Options{})
	findings := []model.Finding{{RuleID: "SD-009", FilePath: "a.sh", Line: 1}}
	got := s.applyTriage(context.Background(), findings, []model.FileContext{{Path: "a.sh"}})
	if got[0].Triage != nil {
		t.Fatalf("nil verifier must leave Triage nil, got %+v", got[0].Triage)
	}
}

var errTriageDown = simpleErr("llm down")

type simpleErr string

func (e simpleErr) Error() string { return string(e) }
```

If `scanner_test.go` already declares a `simpleErr` (it does not today), drop the local declaration and reuse the existing one.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/scanner/ -run TestApplyTriage -v`
Expected: FAIL — `Options.Verifier` / `applyTriage` / `triage` import undefined.

- [ ] **Step 3: Write minimal implementation**

In `pkg/scanner/scanner.go`:

(a) Add the triage import to the import block:

```go
	"github.com/velzepooz/skill-detector/pkg/triage"
```

(b) Add two fields to `Options` (after `ScanAll`, line ~31):

```go
	ScanAll bool          // disable .gitignore filtering; walk every scannable file
	Verifier triage.Verifier // nil = deterministic floor (no triage; CLI default)
	TriageTimeout time.Duration // bounds the triage phase; 0 = no extra deadline
```

(c) In `run`, insert the triage step between the sort block (ends line ~123) and `perms := permission.Extract(...)` (line ~125):

```go
	findings = s.applyTriage(ctx, findings, files)

	perms := permission.Extract(findings, files)
```

(d) Bump the schema version (line ~140):

```go
		SchemaVersion:   "1.3",
```

(e) Add the `applyTriage` method (place it after `run`, before `filterConfigOverrides`):

```go
// applyTriage runs the configured verifier over findings grouped by file and
// writes a TriageVerdict into each Finding. It fails safe: on any verifier
// error or deadline the affected findings are left un-demoted and stamped
// "unavailable", so the grade stays conservative (never weaker than the
// deterministic floor). No-op when no verifier is configured.
func (s *Scanner) applyTriage(ctx context.Context, findings []model.Finding, files []model.FileContext) []model.Finding {
	if s.opts.Verifier == nil || len(findings) == 0 {
		return findings
	}

	tctx := ctx
	if s.opts.TriageTimeout > 0 {
		var cancel context.CancelFunc
		tctx, cancel = context.WithTimeout(ctx, s.opts.TriageTimeout)
		defer cancel()
	}

	contentByPath := make(map[string]model.FileContext, len(files))
	for _, f := range files {
		contentByPath[f.Path] = f
	}

	idxByPath := make(map[string][]int)
	for i := range findings {
		idxByPath[findings[i].FilePath] = append(idxByPath[findings[i].FilePath], i)
	}
	paths := make([]string, 0, len(idxByPath))
	for p := range idxByPath {
		paths = append(paths, p)
	}
	slices.Sort(paths) // deterministic file iteration

	markUnavailable := func(idxs []int) {
		for _, i := range idxs {
			findings[i].Triage = &model.TriageVerdict{Classification: "uncertain", Source: "unavailable"}
		}
	}

	for _, p := range paths {
		idxs := idxByPath[p]
		if err := tctx.Err(); err != nil {
			markUnavailable(idxs)
			continue
		}

		batch := make([]model.Finding, len(idxs))
		for j, i := range idxs {
			batch[j] = findings[i]
		}

		verdicts, err := s.opts.Verifier.Classify(tctx, contentByPath[p], batch)
		if err != nil {
			markUnavailable(idxs)
			continue
		}

		byKey := make(map[triage.VerdictKey]triage.Verdict, len(verdicts))
		for _, v := range verdicts {
			byKey[triage.VerdictKey{RuleID: v.RuleID, Line: v.Line}] = v
		}
		for _, i := range idxs {
			f := &findings[i]
			v, ok := byKey[triage.VerdictKey{RuleID: f.RuleID, Line: f.Line}]
			if !ok {
				// Hallucinated/missing verdict → fail safe.
				f.Triage = &model.TriageVerdict{Classification: "uncertain", Source: "unavailable"}
				continue
			}
			f.Triage = &model.TriageVerdict{
				Classification: string(v.Classification),
				Confidence:     v.Confidence,
				Rationale:      v.Rationale,
				Source:         v.Source,
			}
		}
	}
	return findings
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/scanner/ -run TestApplyTriage -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/scanner.go pkg/scanner/scanner_test.go
git commit -m "feat(scanner): add pluggable triage Verifier step (fail-safe)"
```

---

## Task 6: schema version bump verification + full suite green

**Files:**
- Modify: `pkg/scanner/scanner_test.go` (append schema assertion)
- Verify: any existing assertion of `"1.2"` is updated to `"1.3"`.

- [ ] **Step 1: Find existing schema-version assertions**

Run: `grep -rn '"1\.2"' pkg/ cmd/ --include='*.go'`
Expected: a list of any test/golden files asserting the old schema version. Update each occurrence of the schema string from `"1.2"` to `"1.3"` (do NOT touch unrelated `1.2` literals — only `SchemaVersion`/`schema_version` assertions).

- [ ] **Step 2: Write the failing test**

Append to `pkg/scanner/scanner_test.go`:

```go
func TestScan_SchemaVersionIs13(t *testing.T) {
	dir := t.TempDir()
	s := New(rules.DefaultRegistry(), Options{})
	res, err := s.Scan(context.Background(), schemaTestInput(dir))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.SchemaVersion != "1.3" {
		t.Errorf("SchemaVersion = %q, want 1.3", res.SchemaVersion)
	}
}

type schemaTestInput string

func (p schemaTestInput) Path() string { return string(p) }
```

If `scanner_test.go` already defines an `Input` test double (e.g. a `pathInput`/`testInput` type), reuse it instead of `schemaTestInput` and delete the local type.

- [ ] **Step 3: Run test to verify it fails (if not yet bumped) or passes**

Run: `go test ./pkg/scanner/ -run TestScan_SchemaVersionIs13 -v`
Expected: PASS (Task 5 already bumped the constant). If it FAILS asserting `"1.2"`, the bump in Task 5(d) was missed — fix it.

- [ ] **Step 4: Run the entire suite**

Run: `go test ./... -p 1`
Expected: PASS — all packages. If any golden JSON test fails because of an added `triage` key, confirm it is only failing on triaged inputs; un-triaged scans must be byte-identical (the `omitempty` nil pointer emits nothing). Fix any stale `"1.2"` assertion surfaced here.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/scanner_test.go
git commit -m "test(scanner): assert schema_version 1.3; bump stale assertions"
```

---

## Self-Review

**Spec coverage (engine portion of `2026-05-29-llm-triage-verifier-design.md`):**
- Architecture — `pkg/triage` + `NoopVerifier` + injected via `Options.Verifier`: Tasks 1, 5. ✔
- `Finding.Triage` schema + `SchemaVersion` 1.3: Tasks 3, 6. ✔
- LLM context per finding (window, file class) — produced by the *caller* (`skilltrust`, Plan B); the engine passes the full `FileContext` to `Classify`, leaving window-trimming to the verifier. ✔ (engine seam only)
- Grading: demote-only, effective pool, all-suppressed → A with "N suppressed": Task 4. ✔
- Determinism: `NoopVerifier`/nil path byte-identical (omitempty), deterministic file iteration in `applyTriage`, `ScriptedVerifier` for repeatable tests: Tasks 1, 4, 5, 6. ✔ (content-hash verdict cache is Plan B — out of scope here)
- Fail-safe (error/deadline/hallucinated verdict → un-demoted + `unavailable`): Task 5. ✔
- Confidence threshold `TriageDemoteThreshold` (0.85): Task 3. ✔
- Single adjusted grade collapsing to deterministic with no verifier: implicit — same code path, nil verifier ⇒ no suppression: Tasks 4, 5. ✔
- Monetization / UI states / PR-bot / cache / prompt / anti-injection / benchmark: **Plan B (SaaS)** — intentionally not in this plan.

**Placeholder scan:** No TBD/TODO; every code step shows full code; commands have expected output. ✔

**Type consistency:** `Verdict`/`VerdictKey`/`Classification`/`Verifier`/`NoopVerifier`/`ScriptedVerifier` consistent across Tasks 1, 2, 5. `TriageVerdict`/`Triage`/`IsSuppressed`/`TriageDemoteThreshold` consistent across Tasks 3, 4, 5. `Options.Verifier`/`TriageTimeout` and `applyTriage` signature consistent in Task 5. The literal `"benign_example"` in `model.IsSuppressed` (Task 3) intentionally mirrors `triage.ClassBenign` (Task 1) — documented, no import cycle. ✔

## Follow-on: Plan B (SaaS, `skilltrust`)

Not in this plan. Depends on this seam. Scope: LLM verifier implementing `triage.Verifier` (prompt with rule description + ±8-line window + file class; untrusted-data wrapping / anti-injection); content-hash verdict cache in the `skilltrust` DB keyed by `hash(rule_id + content_window + rule_version + registry_checksum)`; concurrency + `TriageTimeout` (≈15s) wiring under the <60s budget; tier gating (inject verifier only for Team workspaces); UI states (Confirmed / Suppressed / Needs-review) + badge/landing "M suppressed" line + PR-bot `<details>` fold; benchmark harness measuring FP-suppression and `real_threat` recall over the SP-7 corpus. Model choice from research task #5.
