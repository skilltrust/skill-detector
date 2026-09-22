package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

var st126JSONCases = []struct {
	name, input string
	want        int
}{
	{"escaped_benign", `{"command":"printf \"ready\"\n"}`, 0},
	{"escaped_npm_read", `{"command":"cat \u007e\/.npmrc"}`, 1},
	{"escaped_codex_read", `{"command":"cat $HOME\/.codex\/auth.json"}`, 1},
	{"escaped_benign_mention", `{"command":"stat \u007e\/.npmrc"}`, 0},
	{"mixed_read_last", `{"metadata":"stat ~/.npmrc", "command":"cat \u007e\/.npmrc"}`, 1},
	{"mixed_read_first", `{"command":"cat \u007e\/.npmrc", "metadata":"stat ~/.npmrc"}`, 1},
	{"mixed_unrelated_strings", `{"verb":"cat", "path":"\u007e\/.npmrc"}`, 0},
	{"escaped_newline_read", `{"command":"printf ready\ncat \u007e\/.npmrc"}`, 1},
}

// Candidate-only correctness test; baseline benchmark runs use -run '^$'.
func TestST126JSONEscapes(t *testing.T) {
	r := findRule(t, "SD-004")
	for _, tc := range st126JSONCases {
		t.Run(tc.name, func(t *testing.T) {
			fs := r.Match([]byte(tc.input), model.FileContext{Path: ".claude/settings.json", Ext: ".json"})
			if len(fs) != tc.want {
				t.Fatalf("got %+v, want %d findings", fs, tc.want)
			}
			if tc.want != 0 && (fs[0].Line != 1 || fs[0].RuleID != "SD-004") {
				t.Fatalf("wrong finding identity/location: %+v", fs[0])
			}
		})
	}
}

// Identical baseline/candidate harness. All content is inert synthetic text.
// Input construction and rule registration are outside the measured loop.
func BenchmarkST126Comparison(b *testing.B) {
	var rule Rule
	for _, r := range DefaultRegistry().All() {
		if r.ID() == "SD-004" {
			rule = r
		}
	}
	if rule == nil {
		b.Fatal("SD-004 missing")
	}
	run := func(name, input, path, ext string) {
		b.Run(fmt.Sprintf("%s/bytes=%d", name, len(input)), func(b *testing.B) {
			content := []byte(input)
			ctx := model.FileContext{Path: path, Ext: ext}
			b.SetBytes(int64(len(content)))
			b.ReportAllocs()
			count := len(rule.Match(content, ctx))
			for b.Loop() {
				if got := len(rule.Match(content, ctx)); got != count {
					b.Fatalf("unstable result: %d vs %d", got, count)
				}
			}
			b.ReportMetric(float64(count), "findings/op")
		})
	}
	run("normal_markdown", strings.Repeat("# Development\nUse Go tests before proposing a change. Keep patches small.\n", 30), "AGENTS.md", ".md")
	run("normal_hook", "#!/bin/sh\nset -eu\nprintf '%s\\n' 'Checking project'\ngo test ./...\n", ".claude/hooks/check.sh", ".sh")
	run("normal_json", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"printf ready"}]}]}}`, ".claude/settings.json", ".json")
	run("normal_json_new_mention", `{"metadata":"Credentials may be stored at ~/.npmrc","command":"printf ready"}`, ".claude/settings.json", ".json")
	run("legacy_read", "cat ~/.aws/credentials\n", "SKILL.md", ".md")
	run("new_read", "cat ~/.npmrc\n", "SKILL.md", ".md")
	for _, tc := range st126JSONCases {
		run("json_"+tc.name, tc.input, ".claude/settings.json", ".json")
	}
	for _, n := range []int{1024, 16384, 262144, 1048576} {
		run("benign_single", strings.Repeat("x", n), "SKILL.md", ".md")
		run("benign_lines", strings.Repeat("Review the patch and run the unit tests before writing a concise report.\n", n/72), "SKILL.md", ".md")
		run("benign_json", `{"documentation":"`+strings.Repeat("x", n)+`"}`, ".claude/settings.json", ".json")
		run("json_sparse_escape", `{"documentation":"`+strings.Repeat("x", n)+`\n"}`, ".claude/settings.json", ".json")
		run("json_dense_escape", `{"documentation":"`+strings.Repeat(`\u0078`, n/6)+`"}`, ".claude/settings.json", ".json")
	}
	for _, n := range []int{500, 1000, 2000, 8000, 50000} {
		for _, tail := range []string{"", "; cat ~/.npmrc"} {
			run(fmt.Sprintf("mentions/n=%d/read=%t", n, tail != ""), strings.Repeat("stat ~/.npmrc ", n)+tail, "SKILL.md", ".md")
		}
	}
	for _, depth := range []int{100, 200, 400, 1000, 4000} {
		for _, leaf := range []string{"basename ~/.npmrc", "cat ~/.npmrc"} {
			run(fmt.Sprintf("nested_grep/depth=%d/read=%t", depth, strings.HasPrefix(leaf, "cat")), strings.Repeat(`grep "$(`, depth)+leaf+strings.Repeat(`)" README.md`, depth), "SKILL.md", ".md")
		}
		run(fmt.Sprintf("nested_sed/depth=%d", depth), `sed 'e `+strings.Repeat("echo $(", depth)+"basename ~/.npmrc"+strings.Repeat(")", depth)+`' README.md`, "SKILL.md", ".md")
	}
}
