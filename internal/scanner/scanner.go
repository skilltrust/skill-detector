package scanner

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/config"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/permission"
	"github.com/velzepooz/skill-detector/internal/rules"
	"github.com/velzepooz/skill-detector/pkg/scorer"
)

// Scanner orchestrates the scan pipeline.
type Scanner struct {
	root     string
	registry *rules.RuleRegistry
	cfg      *config.Config
	version  string
}

// New creates a Scanner for the given root path.
// cfg may be nil for backward compatibility (all rules enabled, no overrides).
func New(root string, registry *rules.RuleRegistry, cfg *config.Config, version string) *Scanner {
	return &Scanner{root: root, registry: registry, cfg: cfg, version: version}
}

// isRuleDisabled reports whether ruleID is explicitly disabled in config.
func (s *Scanner) isRuleDisabled(ruleID string) bool {
	if s.cfg == nil || len(s.cfg.Rules) == 0 {
		return false
	}
	if rcfg, ok := s.cfg.Rules[ruleID]; ok {
		if rcfg.Enabled != nil && !*rcfg.Enabled {
			return true
		}
	}
	return false
}

// Run executes the full scan pipeline and returns a ScanResult.
func (s *Scanner) Run() (model.ScanResult, error) {
	files, err := Discover(s.root)
	if err != nil {
		return model.ScanResult{}, fmt.Errorf("scanner: %w", err)
	}

	var findings []model.Finding
	activeRules := make(map[string]bool)
	for _, file := range files {
		matched := s.registry.RulesFor(file.Ext)
		for _, rule := range matched {
			if s.isRuleDisabled(rule.ID()) {
				continue
			}
			activeRules[rule.ID()] = true
			results := rule.Match(file.Content, file)
			findings = append(findings, results...)
		}
	}

	findings = scorer.Score(findings)
	findings, overrides := scorer.ApplyOverrides(findings, s.cfg)

	if s.cfg != nil {
		findings = ApplyAllowlists(findings, s.cfg.Allow)
		overrides = filterConfigOverrides(findings, overrides)
	}

	// Sort deterministically: by file path, then line, then rule ID.
	slices.SortStableFunc(findings, func(a, b model.Finding) int {
		if a.FilePath != b.FilePath {
			return strings.Compare(a.FilePath, b.FilePath)
		}
		if a.Line != b.Line {
			return cmp.Compare(a.Line, b.Line)
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})

	perms := permission.Extract(findings, files)

	return model.ScanResult{
		Findings:        findings,
		Permissions:     perms,
		ConfigOverrides: overrides,
		FileCount:       len(files),
		RuleCount:       len(activeRules),
		Version:         s.version,
		Checksum:        s.registry.Checksum(),
		SchemaVersion:   "1.1",
	}, nil
}

func filterConfigOverrides(findings []model.Finding, overrides []model.ConfigOverride) []model.ConfigOverride {
	if len(findings) == 0 || len(overrides) == 0 {
		return nil
	}

	activeRules := make(map[string]bool, len(findings))
	for _, finding := range findings {
		activeRules[finding.RuleID] = true
	}

	filtered := make([]model.ConfigOverride, 0, len(overrides))
	for _, override := range overrides {
		if activeRules[override.RuleID] {
			filtered = append(filtered, override)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}
