package rules

import (
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// fakeRule is a minimal Rule implementation for testing the registry.
type fakeRule struct {
	baseRule
}

func (f *fakeRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	return nil
}

func TestRegistryRegisterAndRulesFor(t *testing.T) {
	reg := NewRegistry()

	r1 := &fakeRule{baseRule{
		id:    "TEST-001",
		name:  "test rule sh",
		types: []string{".sh", ".bash"},
	}}
	r2 := &fakeRule{baseRule{
		id:    "TEST-002",
		name:  "test rule py",
		types: []string{".py"},
	}}
	r3 := &fakeRule{baseRule{
		id:    "TEST-003",
		name:  "test rule multi",
		types: []string{".sh", ".py"},
	}}

	reg.Register(r1)
	reg.Register(r2)
	reg.Register(r3)

	shRules := reg.RulesFor(".sh")
	if len(shRules) != 2 {
		t.Errorf("RulesFor(.sh) returned %d rules, want 2", len(shRules))
	}

	pyRules := reg.RulesFor(".py")
	if len(pyRules) != 2 {
		t.Errorf("RulesFor(.py) returned %d rules, want 2", len(pyRules))
	}

	yamlRules := reg.RulesFor(".yaml")
	if len(yamlRules) != 0 {
		t.Errorf("RulesFor(.yaml) returned %d rules, want 0", len(yamlRules))
	}
}

func TestRegistryEmpty(t *testing.T) {
	reg := NewRegistry()
	rules := reg.RulesFor(".sh")
	if len(rules) != 0 {
		t.Errorf("empty registry returned %d rules, want 0", len(rules))
	}
}

func TestChecksum_Deterministic(t *testing.T) {
	makeRegistry := func() *RuleRegistry {
		reg := NewRegistry()
		reg.Register(&fakeRule{baseRule{id: "T-001", name: "rule a", severity: model.SeverityHigh, category: "cat-a", types: []string{".sh"}}})
		reg.Register(&fakeRule{baseRule{id: "T-002", name: "rule b", severity: model.SeverityMedium, category: "cat-b", types: []string{".py"}}})
		return reg
	}

	c1 := makeRegistry().Checksum()
	c2 := makeRegistry().Checksum()
	if c1 != c2 {
		t.Errorf("checksums differ: %s vs %s", c1, c2)
	}
}

func TestChecksum_OrderIndependent(t *testing.T) {
	rA := &fakeRule{baseRule{id: "T-001", name: "rule a", severity: model.SeverityHigh, category: "cat-a", types: []string{".sh"}}}
	rB := &fakeRule{baseRule{id: "T-002", name: "rule b", severity: model.SeverityMedium, category: "cat-b", types: []string{".py"}}}

	reg1 := NewRegistry()
	reg1.Register(rA)
	reg1.Register(rB)

	reg2 := NewRegistry()
	reg2.Register(rB)
	reg2.Register(rA)

	if reg1.Checksum() != reg2.Checksum() {
		t.Errorf("checksums should be order-independent: %s vs %s", reg1.Checksum(), reg2.Checksum())
	}
}

func TestChecksum_ChangesWithRules(t *testing.T) {
	reg1 := NewRegistry()
	reg1.Register(&fakeRule{baseRule{id: "T-001", name: "rule a", severity: model.SeverityHigh, category: "cat-a", types: []string{".sh"}}})
	reg1.Register(&fakeRule{baseRule{id: "T-002", name: "rule b", severity: model.SeverityMedium, category: "cat-b", types: []string{".py"}}})

	reg2 := NewRegistry()
	reg2.Register(&fakeRule{baseRule{id: "T-001", name: "rule a", severity: model.SeverityHigh, category: "cat-a", types: []string{".sh"}}})
	reg2.Register(&fakeRule{baseRule{id: "T-002", name: "rule b", severity: model.SeverityMedium, category: "cat-b", types: []string{".py"}}})
	reg2.Register(&fakeRule{baseRule{id: "T-003", name: "rule c", severity: model.SeverityLow, category: "cat-c", types: []string{".js"}}})

	if reg1.Checksum() == reg2.Checksum() {
		t.Error("checksums should differ when different rules are registered")
	}
}

func TestChecksum_NonEmpty(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&fakeRule{baseRule{id: "T-001", name: "rule a", severity: model.SeverityHigh, category: "cat-a", types: []string{".sh"}}})
	cs := reg.Checksum()
	if cs == "" {
		t.Error("checksum should not be empty")
	}
	if len(cs) != 16 {
		t.Errorf("checksum should be 16 chars, got %d: %s", len(cs), cs)
	}
}

func TestChecksumChangesOnAxisFlip(t *testing.T) {
	r1 := NewRegistry()
	r1.Register(&shellInjectionRule{baseRule: baseRule{
		id: "X", name: "X", severity: model.SeverityHigh, category: "C",
		types: []string{".sh"}, axis: axes.Security,
	}})

	r2 := NewRegistry()
	r2.Register(&shellInjectionRule{baseRule: baseRule{
		id: "X", name: "X", severity: model.SeverityHigh, category: "C",
		types: []string{".sh"}, axis: axes.Quality, // flipped
	}})

	if r1.Checksum() == r2.Checksum() {
		t.Error("checksum should differ when axis is flipped")
	}
}

func TestChecksumStableOnUnchangedRegistry(t *testing.T) {
	r1 := DefaultRegistry()
	r2 := DefaultRegistry()
	if r1.Checksum() != r2.Checksum() {
		t.Errorf("checksum should be stable, got %s vs %s", r1.Checksum(), r2.Checksum())
	}
}
