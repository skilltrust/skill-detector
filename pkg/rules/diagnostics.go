package rules

import "github.com/velzepooz/skill-detector/pkg/model"

// ConfigurationDiagnostics runs validation and limitation diagnostics that
// must survive disabled rules and finding scoring. Add bounded configuration
// analyzers here; rules remain responsible only for findings.
func ConfigurationDiagnostics(content []byte, ctx model.FileContext) ([]string, error) {
	return CodexConfigDiagnostics(content, ctx)
}
