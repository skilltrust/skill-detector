package rules

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"sort"

	"github.com/velzepooz/skill-detector/pkg/grade"
)

// RuleRegistry holds registered rules and supports lookup by file type.
type RuleRegistry struct {
	rules []Rule
}

// NewRegistry creates an empty RuleRegistry.
func NewRegistry() *RuleRegistry {
	return &RuleRegistry{}
}

// Register adds a rule to the registry.
func (r *RuleRegistry) Register(rule Rule) {
	r.rules = append(r.rules, rule)
}

// Count returns the total number of registered rules.
func (r *RuleRegistry) Count() int {
	return len(r.rules)
}

// Checksum computes a deterministic hash of all registered rules.
// The hash is based on sorted rule metadata (ID, Name, Severity, Category, Axis)
// plus the canonical form of the grade package's cap table + rationale
// templates. Any tampering with rule registration, axis assignment, cap-table
// thresholds, or template strings changes the checksum.
func (r *RuleRegistry) Checksum() string {
	entries := make([]string, len(r.rules))
	for i, rule := range r.rules {
		entries[i] = fmt.Sprintf("%s:%s:%d:%s:%s",
			rule.ID(), rule.Name(), rule.Severity(), rule.Category(), rule.Axis())
	}
	sort.Strings(entries)

	h := sha256.New()
	for _, entry := range entries {
		h.Write([]byte(entry + "\n"))
	}
	h.Write([]byte("\nGRADE:" + grade.CanonicalMetadata()))
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// RulesFor returns all rules that apply to the given file extension.
func (r *RuleRegistry) RulesFor(ext string) []Rule {
	var matched []Rule
	for _, rule := range r.rules {
		if slices.Contains(rule.FileTypes(), ext) {
			matched = append(matched, rule)
		}
	}
	return matched
}

// All returns all registered rules.
func (r *RuleRegistry) All() []Rule { return r.rules }

// DefaultRegistry returns a RuleRegistry pre-loaded with all built-in rule groups.
func DefaultRegistry() *RuleRegistry {
	r := NewRegistry()
	RegisterInjectionRules(r)
	RegisterAccessControlRules(r)
	RegisterMisconfigurationRules(r)
	RegisterExfiltrationRules(r)
	RegisterSupplyChainRules(r)
	RegisterIntegrityRules(r)
	RegisterClaudeMDRules(r)
	RegisterSettingsJSONRules(r)
	RegisterHooksRules(r)
	RegisterMCPRules(r)
	RegisterReverseShellRules(r)
	return r
}
