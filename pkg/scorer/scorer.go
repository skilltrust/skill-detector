package scorer

import (
	"fmt"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/config"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// diagnosisEntry maps a rule ID to its threat hypothesis and benign alternative.
var diagnosisTable = map[string]struct {
	threat string
	benign string
}{
	"SD-001": {"shell injection via unsanitized input", "intentional dynamic script execution"},
	"SD-002": {"hidden prompt injection to manipulate AI behavior", "formatting artifact or template syntax marker"},
	"SD-003": {"directory traversal to access files outside skill scope", "legitimate relative path or resource reference"},
	"SD-004": {"credential theft attempt", "legitimate configuration file access"},
	"SD-005": {"weakening file permissions for exploitation", "development convenience setting"},
	"SD-006": {"exposed production credential or API key", "example placeholder or documentation value"},
	"SD-007": {"data exfiltration to external service", "legitimate API call"},
	"SD-008": {"obfuscated malicious payload", "legitimate data encoding"},
	"SD-009": {"remote code execution via piped script", "documented software installation procedure"},
	"SD-010": {"supply chain attack via runtime download", "legitimate dependency fetch"},
	"SD-011": {"targeted use of vulnerable dependency version", "outdated but non-malicious dependency"},
	"SD-012": {"malicious post-install action", "legitimate setup automation"},
	"SD-013": {"persistence backdoor mechanism", "legitimate service or scheduled task configuration"},
	"SD-014": {"git hook hijacking for code execution", "development workflow automation tool"},
}

// corroboratingPairs defines rules whose co-occurrence in the same file boosts confidence.
var corroboratingPairs = map[string][]string{
	"SD-001": {"SD-009", "SD-010"},           // shell injection + supply chain
	"SD-004": {"SD-007"},                     // credential access + network → exfiltration
	"SD-006": {"SD-007"},                     // hardcoded secret + network → API key abuse
	"SD-007": {"SD-004", "SD-006", "SD-009"}, // network + credential/secret/curl-bash
	"SD-009": {"SD-007", "SD-001"},           // curl|bash + network or injection
	"SD-012": {"SD-013", "SD-014"},           // post-install + persistence/git hooks
	"SD-013": {"SD-004", "SD-012", "SD-014"}, // persistence + credential/post-install/git
	"SD-014": {"SD-012", "SD-013"},           // git hooks + post-install/persistence
}

// Score adjusts Confidence and generates Diagnosis for each finding
// based on cross-signal heuristic analysis.
func Score(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return findings
	}

	// Build per-file rule sets: file path → set of distinct rule IDs.
	fileRules := make(map[string]map[string]bool)
	for _, f := range findings {
		if fileRules[f.FilePath] == nil {
			fileRules[f.FilePath] = make(map[string]bool)
		}
		fileRules[f.FilePath][f.RuleID] = true
	}

	for i := range findings {
		f := &findings[i]
		rulesInFile := fileRules[f.FilePath]
		distinctRuleCount := len(rulesInFile)

		// Check for specific corroborating signals.
		hasCorroboration := false
		var corroboratedBy []string
		if partners, ok := corroboratingPairs[f.RuleID]; ok {
			for _, partner := range partners {
				if rulesInFile[partner] {
					hasCorroboration = true
					corroboratedBy = append(corroboratedBy, partner)
				}
			}
		}

		// Adjust confidence.
		if hasCorroboration || distinctRuleCount >= 3 {
			f.Confidence = model.ConfidenceHigh
		} else if distinctRuleCount == 1 {
			f.Confidence = model.ConfidenceLow
		}
		// else: keep default ConfidenceMedium (2 distinct rules, no specific corroboration)

		// Generate differential diagnosis.
		f.Diagnosis = buildDiagnosis(f.RuleID, f.Confidence, corroboratedBy)
	}

	return findings
}

// ApplyOverrides sets EffSeverity on each finding based on config rule overrides.
// It must be called AFTER Score() to preserve scoring semantics.
// If cfg is nil or has no Rules, findings are returned unchanged.
// The second return value records which rules had severity adjustments.
func ApplyOverrides(findings []model.Finding, cfg *config.Config) ([]model.Finding, []model.ConfigOverride) {
	if cfg == nil || len(cfg.Rules) == 0 {
		return findings, nil
	}
	var overrides []model.ConfigOverride
	seenSeverity := make(map[string]bool)
	seenContext := make(map[string]bool)
	for i := range findings {
		if rcfg, ok := cfg.Rules[findings[i].RuleID]; ok {
			// Severity override (applied first).
			if rcfg.Severity != "" {
				original := findings[i].EffSeverity
				sev, err := model.ParseSeverity(rcfg.Severity)
				if err == nil {
					findings[i].EffSeverity = sev
					if sev != original && !seenSeverity[findings[i].RuleID] {
						overrides = append(overrides, model.ConfigOverride{
							RuleID:   findings[i].RuleID,
							Field:    "severity",
							Original: original.String(),
							Override: sev.String(),
						})
						seenSeverity[findings[i].RuleID] = true
					}
				}
			}
			// Context: expected overrides EffSeverity to Info (below any normal threshold).
			// Applied AFTER severity override, so context takes precedence.
			if rcfg.Context == "expected" {
				findings[i].EffSeverity = model.SeverityInfo
				if !seenContext[findings[i].RuleID] {
					overrides = append(overrides, model.ConfigOverride{
						RuleID:   findings[i].RuleID,
						Field:    "context",
						Original: "",
						Override: "expected",
					})
					seenContext[findings[i].RuleID] = true
				}
			}
		}
	}
	return findings, overrides
}

// buildDiagnosis generates a differential diagnosis string for a finding.
func buildDiagnosis(ruleID string, confidence model.Confidence, corroboratedBy []string) string {
	entry, ok := diagnosisTable[ruleID]
	if !ok {
		return ""
	}

	var b strings.Builder

	switch confidence {
	case model.ConfidenceHigh:
		fmt.Fprintf(&b, "Likely %s", entry.threat)
		if len(corroboratedBy) > 0 {
			fmt.Fprintf(&b, " (corroborated by %s)", strings.Join(corroboratedBy, ", "))
		}
		fmt.Fprintf(&b, ". Alternative: %s.", entry.benign)
	case model.ConfidenceLow:
		fmt.Fprintf(&b, "Possible %s, but may be %s. No corroborating signals found.", entry.threat, entry.benign)
	default: // ConfidenceMedium
		fmt.Fprintf(&b, "Possible %s. Alternative: %s.", entry.threat, entry.benign)
	}

	return b.String()
}
