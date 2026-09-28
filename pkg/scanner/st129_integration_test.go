package scanner_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/scanner"
)

// Dropping one parser or the post-score warning path must fail this mixed scan.
func TestST129MixedDeclarationsPreserveWarningsAndFindings(t *testing.T) {
	s := scanner.New(rules.DefaultRegistry(), scanner.Options{Version: "integration-test"})
	input := dirInput("../../testdata/malicious/st129-integration")
	first, err := s.Scan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Scan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if first.NoAgentSurface || first.SchemaVersion != model.SchemaVersion || first.FileCount != 3 {
		t.Fatalf("coverage/schema lost: %+v", first)
	}
	if first.Axes[axes.PermissionHygiene].Grade == axes.GradeA || first.Axes[axes.Transparency].Grade == axes.GradeA {
		t.Fatalf("credential-read and external endpoint did not lower axes: %+v", first.Axes)
	}
	for _, pair := range []struct{ path, id string }{
		{".github/hooks/session.json", "SD-004"},
		{".codex/config.toml", "SD-026"},
		{".claude/settings.json", "SD-018"},
		{".claude/settings.json", "SD-007"},
	} {
		found := false
		for _, f := range first.Findings {
			if f.FilePath == pair.path && f.RuleID == pair.id {
				found = true
			}
			if f.RuleID == "SD-018" && !strings.Contains(f.Remediation, "Keep the protective deny") {
				t.Errorf("scoring lost protective-deny advice: %+v", f)
			}
		}
		if !found {
			t.Errorf("missing %s on %s: %+v", pair.id, pair.path, first.Findings)
		}
	}
	text := strings.Join(first.Warnings, "\n")
	for _, want := range []string{"HTTP hook event PreToolUse", "event and matcher activation are unresolved", "strictKnownMarketplaces is empty", "declaration-only", "unknown"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing conditional warning %q: %s", want, text)
		}
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"INTEGRATION_URL_SECRET", "INTEGRATION_QUERY_SECRET", "INTEGRATION_HEADER_SECRET"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("serialized result leaked %s", secret)
		}
	}
	filesystem := false
	for _, permission := range first.Permissions {
		filesystem = filesystem || permission.Type == "filesystem"
	}
	if !filesystem {
		t.Errorf("credential-read permission lost: %+v", first.Permissions)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Errorf("same submitted bytes produced different scan outputs:\n%s\n%s", a, b)
	}
}
