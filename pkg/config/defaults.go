package config

import "github.com/velzepooz/skill-detector/pkg/model"

// DefaultConfig returns a Config with bundled defaults:
// fail_on: critical, all rules enabled, empty allowlists.
func DefaultConfig() *Config {
	return &Config{
		FailOn: model.SeverityCritical,
		Rules:  map[string]RuleCfg{},
		Allow:  AllowLists{},
	}
}
