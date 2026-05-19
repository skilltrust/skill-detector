package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/scanner"
)

// dirInputCVE satisfies scanner.Input for CVE fixture directories.
type dirInputCVE string

func (d dirInputCVE) Path() string { return string(d) }

func TestCVEReproducers(t *testing.T) {
	cases := []struct {
		dir        string
		wantRuleID string
		wantAxis   axes.Axis
	}{
		{"cve-2025-59536", "SD-020", axes.Security},
		{"comment-and-control", "SD-016", axes.Security},
		{"claude-md-sql", "SD-015", axes.Security},
		{"subcommand-limit-bypass", "SD-018", axes.PermissionHygiene},
		{"bash-curl-wildcard", "SD-017", axes.PermissionHygiene},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			fixture := filepath.Join("..", "..", "testdata", "cve", tc.dir)
			registry := rules.DefaultRegistry()
			s := scanner.New(registry, scanner.Options{Version: "test"})
			res, err := s.Scan(context.Background(), dirInputCVE(fixture))
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			var got bool
			for _, f := range res.Findings {
				if f.RuleID == tc.wantRuleID && f.Axis == tc.wantAxis {
					got = true
					break
				}
			}
			if !got {
				t.Errorf("CVE %s: expected %s on axis %s, findings: %+v",
					tc.dir, tc.wantRuleID, tc.wantAxis, res.Findings)
			}
		})
	}
}

func TestCVEReproducers_BinaryE2E(t *testing.T) {
	bin := buildBinaryCVE(t)
	cases := []struct {
		dir        string
		wantRuleID string
		axis       string
		wantGrade  string
	}{
		{"cve-2025-59536", "SD-020", "security", "F"},
		{"comment-and-control", "SD-016", "security", "F"},
		{"claude-md-sql", "SD-015", "security", "D"},
		{"subcommand-limit-bypass", "SD-018", "permission_hygiene", "D"},
		{"bash-curl-wildcard", "SD-017", "permission_hygiene", "D"},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			fixture := filepath.Join("..", "..", "testdata", "cve", tc.dir)
			out, exitCode := runBinaryCVE(t, bin, "scan", "--format=json", fixture)
			if exitCode != 0 && exitCode != 1 && exitCode != 2 {
				t.Fatalf("unexpected exit code %d; output: %s", exitCode, out)
			}
			var parsed struct {
				Axes map[string]struct {
					Grade string `json:"grade"`
				} `json:"axes"`
				Findings []struct {
					RuleID string `json:"rule_id"`
					Axis   string `json:"axis"`
				} `json:"findings"`
			}
			if err := json.Unmarshal([]byte(out), &parsed); err != nil {
				t.Fatalf("parse JSON: %v\noutput: %s", err, out)
			}
			if parsed.Axes[tc.axis].Grade != tc.wantGrade {
				t.Errorf("axes[%s].grade = %q, want %q", tc.axis, parsed.Axes[tc.axis].Grade, tc.wantGrade)
			}
			var found bool
			for _, f := range parsed.Findings {
				if f.RuleID == tc.wantRuleID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected rule %s in findings, got: %+v", tc.wantRuleID, parsed.Findings)
			}
		})
	}
}

func buildBinaryCVE(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "skill-detector")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return out
}

func runBinaryCVE(t *testing.T, bin string, args ...string) (stdout string, exitCode int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return buf.String(), exitErr.ExitCode()
	}
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return buf.String(), 0
}
