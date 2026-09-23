package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/rules"
)

func TestClaudeDiagnosticsSurviveScoringAndKeepProtectiveDeny(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := `{"permissions":{"defaultMode":"bypassPermissions","allow":["Bash(*)"],"deny":["Bash(rm -rf *)"]},"sandbox":{"excludedCommands":["docker *"]}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	analysis := model.AnalysisContext{
		Version:           model.ContextValue{State: model.ContextKnown, Value: "2.1.277", Evidence: "test"},
		DeclarationOrigin: model.ContextValue{State: model.ContextKnown, Value: "project", Evidence: "test"},
	}
	result, err := New(rules.DefaultRegistry(), Options{}).run(context.Background(), root, analysis)
	if err != nil {
		t.Fatal(err)
	}
	joinedWarnings := strings.Join(result.Warnings, "\n")
	if !strings.Contains(joinedWarnings, "does not activate") || !strings.Contains(joinedWarnings, "every component") {
		t.Fatalf("diagnostics lost after full scanner path: %v", result.Warnings)
	}
	var found bool
	for _, finding := range result.Findings {
		if finding.RuleID != "SD-018" {
			continue
		}
		found = true
		combined := finding.Description + "\n" + finding.Remediation + "\n" + finding.Diagnosis
		for _, want := range []string{"protective deny", "when both rules apply", "Keep the protective deny", "deny precedence protects the overlapping subset"} {
			if !strings.Contains(combined, want) {
				t.Errorf("SD-018 lost %q after scoring: %+v", want, finding)
			}
		}
		if strings.Contains(strings.ToLower(combined), "deny is redundant") || strings.HasPrefix(finding.Remediation, "Remove the deny") {
			t.Errorf("SD-018 recommends weakening protection: %+v", finding)
		}
	}
	if !found {
		t.Fatalf("SD-018 missing: %+v", result.Findings)
	}
}

func TestMalformedClaudeSettingsCannotReturnGradedResult(t *testing.T) {
	deep := `{"x":` + strings.Repeat(`[`, 12_000) + `0` + strings.Repeat(`]`, 12_000) + `}`
	for _, invalid := range []struct {
		name, content string
	}{
		{"invalid-type", `{"permissions":{"defaultMode":"bypassPermissions"},"sandbox":{"excludedCommands":true}}`},
		{"null-settings", `null`},
		{"null-array-element", `{"permissions":{"deny":[null]}}`},
		{"null-scalar", `{"allowManagedPermissionRulesOnly":null}`},
		{"duplicate-analyzed-object", `{"permissions":{"deny":[null]},"permissions":{}}`},
		{"case-colliding-analyzed-field", `{"sandbox":{"excludedCommands":["*"],"EXCLUDEDCOMMANDS":[]}}`},
		{"case-folded-null", `{"PERMISSIONS":{"DENY":[null]}}`},
		{"excessive-nesting", deep},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, ".claude", "settings.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(invalid.content), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, registry := range []struct {
				name string
				reg  *rules.RuleRegistry
			}{
				{"default-registry", rules.DefaultRegistry()},
				{"empty-registry", rules.NewRegistry()},
			} {
				t.Run(registry.name, func(t *testing.T) {
					result, err := New(registry.reg, Options{}).Scan(context.Background(), contextInput(root))
					if err == nil || result != nil {
						t.Fatalf("result=%+v error=%v; want error and no graded result", result, err)
					}
					if !strings.Contains(err.Error(), "configuration was not assessed") || strings.Contains(err.Error(), "bypassPermissions") {
						t.Fatalf("unsanitized or unclear error: %v", err)
					}
				})
			}
		})
	}
}

func TestClaudeSettingsCaseSensitiveDataKeysCanBeGraded(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := `{"env":{"HTTP_PROXY":"http://proxy.example:8080","http_proxy":"http://proxy.example:8080"}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, registry := range []*rules.RuleRegistry{rules.DefaultRegistry(), rules.NewRegistry()} {
		result, err := New(registry, Options{}).Scan(context.Background(), contextInput(root))
		if err != nil || result == nil || len(result.Axes) == 0 {
			t.Fatalf("result=%+v error=%v; want graded result", result, err)
		}
	}
}

func TestClaudeSettingsIgnoredLargeNumberCanBeGraded(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := `{"extensionData":{"large":1e1000},"permissions":{"deny":["Read(**/.env)"]}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, registry := range []*rules.RuleRegistry{rules.DefaultRegistry(), rules.NewRegistry()} {
		result, err := New(registry, Options{}).Scan(context.Background(), contextInput(root))
		if err != nil || result == nil || len(result.Axes) == 0 {
			t.Fatalf("result=%+v error=%v; want graded result", result, err)
		}
	}
}

func TestAllowedDomainsSurviveIgnoredLargeNumber(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".claude", "tool-calls.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := `{"extensionData":{"large":1e1000},"name":"Bash","input":{"command":"curl https://api.example.test/resource","allowed_domains":["other.example.test:443"]}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, registry := range []*rules.RuleRegistry{rules.DefaultRegistry(), rules.NewRegistry()} {
		result, err := New(registry, Options{}).Scan(context.Background(), contextInput(root))
		if err != nil || result == nil || !strings.Contains(strings.Join(result.Warnings, "\n"), "does not cover") {
			t.Fatalf("result=%+v error=%v; want mismatched-domain diagnostic", result, err)
		}
	}
}

func TestAllowedDomainsLargeInputSurvivesRegistries(t *testing.T) {
	var content strings.Builder
	content.WriteString(`{"name":"Bash","input":{"command":"curl`)
	for i := range 20_000 {
		content.WriteString(` https://host` + strconv.Itoa(i) + `.example.test/resource`)
	}
	content.WriteString(`","allowed_domains":[`)
	for i := range 20_000 {
		if i > 0 {
			content.WriteByte(',')
		}
		content.WriteString(`"host` + strconv.Itoa(i) + `.example.test:443"`)
	}
	content.WriteString(`]}}`)

	root := t.TempDir()
	path := filepath.Join(root, ".claude", "tool-calls.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, registry := range []*rules.RuleRegistry{rules.DefaultRegistry(), rules.NewRegistry()} {
		result, err := New(registry, Options{}).Scan(context.Background(), contextInput(root))
		if err != nil || result == nil || !strings.Contains(strings.Join(result.Warnings, "\n"), "narrowly names") {
			t.Fatalf("result=%+v error=%v; want narrow domain diagnostic", result, err)
		}
	}
}

func TestAllowedDomainsLongHostnameIsUnresolved(t *testing.T) {
	host := strings.Repeat("a.", 200) + "example.test"
	content := `{"name":"Bash","input":{"command":"curl https://` + host + `/resource","allowed_domains":["` + host + `:443"]}}`
	root := t.TempDir()
	path := filepath.Join(root, ".claude", "tool-calls.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, registry := range []*rules.RuleRegistry{rules.DefaultRegistry(), rules.NewRegistry()} {
		result, err := New(registry, Options{}).Scan(context.Background(), contextInput(root))
		if err != nil || result == nil || !strings.Contains(strings.Join(result.Warnings, "\n"), "cannot be compared") {
			t.Fatalf("result=%+v error=%v; want unresolved domain diagnostic", result, err)
		}
	}
}

func TestAllowedDomainsUnsupportedHostsAreUnresolved(t *testing.T) {
	for _, content := range []string{
		`{"name":"Bash","input":{"command":"curl https://$HOST/resource","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl https://api.example.test\"$SUFFIX\"/resource","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl \"https://api.example.test\"$SUFFIX/resource","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl \"$PREFIX\"\"https://api.example.test/resource\"","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl ${PREFIX}https://api.example.test/resource","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl $(get_prefix)\"https://api.example.test/resource\"","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl \"$PREFIX\"\\\n\"https://api.example.test/resource\"","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl ${PREFIX}\\\nhttps://api.example.test/resource","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl \"https://$PREFIX@api.example.test/resource\"","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"PowerShell","input":{"command":"Invoke-WebRequest ${PREFIX}` + "`" + `\nhttps://api.example.test/resource","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl \"https://api.example.test/resource","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl \"$PREFIX https://api.example.test/resource \"","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl \"$PREFIX https://api.example.test/resource","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl \"$URL\" # https://api.example.test/resource","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"cat <<EOF\nhttps://api.example.test/resource\nEOF","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"cat <(printf https://api.example.test/resource)","allowed_domains":["api.example.test:443"]}}`,
		`{"name":"Bash","input":{"command":"curl https://api.example.test/resource","allowed_domains":["$HOST:443"]}}`,
		`{"name":"Bash","input":{"command":"curl https://api.example.test/resource","allowed_domains":["api.*.example.test:443"]}}`,
	} {
		root := t.TempDir()
		path := filepath.Join(root, ".claude", "tool-calls.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, registry := range []*rules.RuleRegistry{rules.DefaultRegistry(), rules.NewRegistry()} {
			result, err := New(registry, Options{}).Scan(context.Background(), contextInput(root))
			if err != nil || result == nil || !strings.Contains(strings.Join(result.Warnings, "\n"), "cannot be compared") {
				t.Fatalf("result=%+v error=%v; want unresolved domain diagnostic", result, err)
			}
		}
	}
}

func TestClaudeDiagnosticsSurviveEmptyRegistry(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".claude", "skills", "audit", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("!`printf ready`\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := New(rules.NewRegistry(), Options{}).Scan(context.Background(), contextInput(root))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 || result.RuleCount != 0 || !strings.Contains(strings.Join(result.Warnings, "\n"), "executable inline shell") {
		t.Fatalf("diagnostics did not survive disabled semantic rules/scoring: %+v", result)
	}
}

func TestClaudePermissionContextFixtures(t *testing.T) {
	s := New(rules.DefaultRegistry(), Options{})

	clean, err := s.Scan(context.Background(), contextInput("../../testdata/clean/claude-permission-context"))
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.Findings) != 0 {
		t.Fatalf("clean fixture findings = %+v", clean.Findings)
	}
	cleanWarnings := strings.Join(clean.Warnings, "\n")
	for _, want := range []string{"Read/Edit/Write path rule", "narrow exclusion", "narrowly names"} {
		if !strings.Contains(cleanWarnings, want) {
			t.Errorf("clean fixture missing %q in %q", want, cleanWarnings)
		}
	}
	if strings.Contains(cleanWarnings, "executable inline shell") {
		t.Errorf("prose treated as executable: %q", cleanWarnings)
	}

	malicious, err := s.Scan(context.Background(), contextInput("../../testdata/malicious/claude-permission-context"))
	if err != nil {
		t.Fatal(err)
	}
	var foundSD018 bool
	for _, finding := range malicious.Findings {
		foundSD018 = foundSD018 || finding.RuleID == "SD-018"
	}
	if !foundSD018 {
		t.Fatalf("malicious fixture missing SD-018: %+v", malicious.Findings)
	}
	maliciousWarnings := strings.Join(malicious.Warnings, "\n")
	for _, want := range []string{
		"executable inline shell", "broader than", "defaultMode=bypassPermissions",
		"path-scoped Write", "negated path rule", "scoped Bash/PowerShell deny", "broad or wildcard exclusion",
	} {
		if !strings.Contains(maliciousWarnings, want) {
			t.Errorf("malicious fixture missing %q in %q", want, maliciousWarnings)
		}
	}
}
