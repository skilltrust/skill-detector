package rules

import "github.com/velzepooz/skill-detector/pkg/model"

// ConfigurationDiagnostics runs validation and limitation diagnostics that
// must survive disabled rules and finding scoring. Add bounded configuration
// analyzers here; rules remain responsible only for findings.
func ConfigurationDiagnostics(content []byte, ctx model.FileContext) ([]string, error) {
	gitWarnings, err := NestedBareGitDiagnostics(content, ctx)
	if err != nil {
		return nil, err
	}
	warnings, err := CodexConfigDiagnostics(content, ctx)
	if err != nil {
		return nil, err
	}
	claudeWarnings, err := ClaudeConfigurationDiagnostics(content, ctx)
	if err != nil {
		return nil, err
	}
	pluginWarnings, err := PluginMCPDiagnostics(content, ctx)
	if err != nil {
		return nil, err
	}
	copilotWarnings := CopilotContextDiagnostics(ctx)
	return append(append(append(append(gitWarnings, warnings...), claudeWarnings...), pluginWarnings...), copilotWarnings...), nil
}
