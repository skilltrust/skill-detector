package rules

import (
	"fmt"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/model"
)

// CopilotContextDiagnostics interprets supplied process/session facts, never
// environment variables from the scanner process or declarations in a hook.
func CopilotContextDiagnostics(ctx model.FileContext) []string {
	if !IsCopilotHookConfig(ctx.Path) && (!strings.HasPrefix(ctx.Path, ".github/agents/") || !strings.HasSuffix(ctx.Path, ".agent.md")) {
		return nil
	}
	var warnings []string
	if state := ctx.Analysis.Conditions["copilot_config_state"]; state.State == model.ContextKnown {
		switch state.Value {
		case "missing", "removed":
			warnings = append(warnings, ctx.Path+": supplied "+state.Value+" config is not a read/validation failure; active plugin state remains unknown without prior runtime evidence (Copilot 1.0.86 anchor)")
		case "invalid", "unreadable":
			warnings = append(warnings, ctx.Path+": supplied config read/validation failure leaves active plugin state unknown; Copilot 1.0.86 does not discard existing plugins, but prior runtime state is unavailable")
		}
	}
	value := ctx.Analysis.Conditions["copilot_allow_all"]
	if value.State != model.ContextKnown {
		return warnings
	}
	var effect string
	switch strings.ToLower(strings.TrimSpace(value.Value)) {
	case "true", "1", "yes", "on", "y":
		if value.Value == "true" {
			effect = "auto-approval and working-directory trust"
		} else {
			effect = "auto-approval only; no trust inference"
		}
	case "false", "0", "no", "off", "n", "":
		effect = "explicitly off for this switch; other approval sources unknown"
	default:
		effect = "unrecognized; no approval or trust inference"
	}
	return append(warnings, fmt.Sprintf("%s: supplied COPILOT_ALLOW_ALL is %s (current GitHub Copilot CLI command reference; applicability to installed version and session unknown)", ctx.Path, effect))
}
