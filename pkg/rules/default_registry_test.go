package rules_test

import (
	"testing"

	"github.com/velzepooz/skill-detector/pkg/rules"
)

func TestDefaultRegistryWiresAllRuleGroups(t *testing.T) {
	r := rules.DefaultRegistry()
	if r == nil {
		t.Fatal("DefaultRegistry() returned nil")
	}
	got := len(r.All())
	if got < 6 {
		t.Fatalf("DefaultRegistry() registered %d rules, want >= 6 (one per group)", got)
	}
}
