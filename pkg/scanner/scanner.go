package scanner

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/config"
	"github.com/velzepooz/skill-detector/pkg/grade"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/permission"
	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/scorer"
	"github.com/velzepooz/skill-detector/pkg/triage"
)

// Input is anything that can be resolved to a local directory path.
// The caller owns the lifecycle of that path (create + clean up).
type Input interface {
	Path() string
}

// Options configures a Scanner instance.
type Options struct {
	Config        *config.Config  // nil = defaults
	Version       string          // recorded in result metadata
	Timeout       time.Duration   // 0 = no per-scan timeout
	ScanAll       bool            // disable .gitignore filtering; walk every scannable file
	Verifier      triage.Verifier // nil = deterministic floor (no triage; CLI default)
	TriageTimeout time.Duration   // bounds the triage phase; 0 = no extra deadline
}

// Scanner runs the rule registry against an Input.
type Scanner struct {
	reg  *rules.RuleRegistry
	opts Options
}

// New constructs a Scanner.
func New(reg *rules.RuleRegistry, opts Options) *Scanner {
	return &Scanner{reg: reg, opts: opts}
}

// Scan runs every rule in the registry against in.Path().
// It must not write outside in.Path() and must not make network calls.
// Cancel via ctx; if opts.Timeout > 0, an inner ctx with that deadline is used.
func (s *Scanner) Scan(ctx context.Context, in Input) (*model.ScanResult, error) {
	if s.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.opts.Timeout)
		defer cancel()
	}
	return s.run(ctx, in.Path())
}

// isRuleDisabled reports whether ruleID is explicitly disabled in config.
func (s *Scanner) isRuleDisabled(ruleID string) bool {
	cfg := s.opts.Config
	if cfg == nil || len(cfg.Rules) == 0 {
		return false
	}
	if rcfg, ok := cfg.Rules[ruleID]; ok {
		if rcfg.Enabled != nil && !*rcfg.Enabled {
			return true
		}
	}
	return false
}

// run executes the full scan pipeline against root and returns a ScanResult.
// It is the unexported core invoked by Scan after ctx/timeout setup.
func (s *Scanner) run(ctx context.Context, root string) (*model.ScanResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	files, discoverStats, err := DiscoverWithOptions(root, DiscoverOptions{ScanAll: s.opts.ScanAll})
	if err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}

	var findings []model.Finding
	activeRules := make(map[string]bool)
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		matched := s.reg.RulesFor(file.Ext)
		for _, rule := range matched {
			if s.isRuleDisabled(rule.ID()) {
				continue
			}
			activeRules[rule.ID()] = true
			results := rule.Match(file.Content, file)
			findings = append(findings, results...)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cfg := s.opts.Config

	findings = scorer.Score(findings)
	findings, overrides := scorer.ApplyOverrides(findings, cfg)

	if cfg != nil {
		findings = ApplyAllowlists(findings, cfg.Allow)
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

	findings = s.applyTriage(ctx, findings, files)

	perms := permission.Extract(findings, files)

	axesResult := make(map[axes.Axis]model.AxisResult, len(axes.Order))
	for _, a := range axes.Order {
		axesResult[a] = grade.Grade(a, findings)
	}

	var warnings []string
	if discoverStats.GitignoredAgentPaths > 0 {
		warnings = append(warnings,
			fmt.Sprintf("%d agent config path(s) were skipped because they are gitignored; the scan may be blind to the primary attack surface. Re-run with --scan-all to include them.", discoverStats.GitignoredAgentPaths))
	}

	return &model.ScanResult{
		Findings:        findings,
		Permissions:     perms,
		ConfigOverrides: overrides,
		FileCount:       len(files),
		RuleCount:       len(activeRules),
		Version:         s.opts.Version,
		Checksum:        s.reg.Checksum(),
		SchemaVersion:   model.SchemaVersion,
		Axes:            axesResult,
		Warnings:        warnings,
	}, nil
}

// applyTriage runs the configured verifier over findings grouped by file and
// writes a TriageVerdict into each Finding. It fails safe: on any verifier
// error or deadline the affected findings are left un-demoted and stamped
// "unavailable", so the grade stays conservative (never weaker than the
// deterministic floor). No-op when no verifier is configured.
func (s *Scanner) applyTriage(ctx context.Context, findings []model.Finding, files []model.FileContext) []model.Finding {
	if s.opts.Verifier == nil || len(findings) == 0 {
		return findings
	}

	tctx := ctx
	if s.opts.TriageTimeout > 0 {
		var cancel context.CancelFunc
		tctx, cancel = context.WithTimeout(ctx, s.opts.TriageTimeout)
		defer cancel()
	}

	contentByPath := make(map[string]model.FileContext, len(files))
	for _, f := range files {
		contentByPath[f.Path] = f
	}

	idxByPath := make(map[string][]int)
	for i := range findings {
		idxByPath[findings[i].FilePath] = append(idxByPath[findings[i].FilePath], i)
	}
	paths := make([]string, 0, len(idxByPath))
	for p := range idxByPath {
		paths = append(paths, p)
	}
	slices.Sort(paths) // deterministic file iteration

	markUnavailable := func(idxs []int) {
		for _, i := range idxs {
			findings[i].Triage = &model.TriageVerdict{Classification: "uncertain", Source: "unavailable"}
		}
	}

	for _, p := range paths {
		idxs := idxByPath[p]
		if err := tctx.Err(); err != nil {
			markUnavailable(idxs)
			continue
		}

		batch := make([]model.Finding, len(idxs))
		for j, i := range idxs {
			batch[j] = findings[i]
		}

		verdicts, err := s.opts.Verifier.Classify(tctx, contentByPath[p], batch)
		if err != nil {
			markUnavailable(idxs)
			continue
		}

		byKey := make(map[triage.VerdictKey]triage.Verdict, len(verdicts))
		for _, v := range verdicts {
			byKey[triage.VerdictKey{RuleID: v.RuleID, Line: v.Line}] = v
		}
		for _, i := range idxs {
			f := &findings[i]
			v, ok := byKey[triage.VerdictKey{RuleID: f.RuleID, Line: f.Line}]
			if !ok {
				// Hallucinated/missing verdict → fail safe.
				f.Triage = &model.TriageVerdict{Classification: "uncertain", Source: "unavailable"}
				continue
			}
			f.Triage = &model.TriageVerdict{
				Classification: string(v.Classification),
				Confidence:     v.Confidence,
				Rationale:      v.Rationale,
				Source:         v.Source,
			}
		}
	}
	return findings
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
