package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/velzepooz/skill-detector/pkg/model"
	"gopkg.in/yaml.v3"
)

// Config holds the scanning configuration loaded from file or defaults.
type Config struct {
	FailOn model.Severity     `yaml:"-"`
	Rules  map[string]RuleCfg `yaml:"rules"`
	Allow  AllowLists         `yaml:"allow"`
}

// rawConfig is the intermediate YAML representation before conversion.
type rawConfig struct {
	FailOn string             `yaml:"fail_on"`
	Rules  map[string]RuleCfg `yaml:"rules"`
	Allow  AllowLists         `yaml:"allow"`
}

// RuleCfg holds per-rule configuration overrides.
type RuleCfg struct {
	Enabled  *bool  `yaml:"enabled"`
	Severity string `yaml:"severity"`
	Context  string `yaml:"context"`
}

// AllowLists holds network and filesystem allowlist entries.
type AllowLists struct {
	Network    []string `yaml:"network"`
	Filesystem []string `yaml:"filesystem"`
}

// Load discovers and parses configuration using cascading lookup.
// If configFlag is set, only that file is loaded (no cascading).
// Otherwise: walk up from scanPath looking for .skill-detectorrc,
// then check ~/.config/skill-detector/config.yaml, then use defaults.
func Load(scanPath string, configFlag string) (*Config, error) {
	if configFlag != "" {
		return loadFile(configFlag)
	}

	// Resolve scanPath to absolute for reliable walk-up.
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return nil, fmt.Errorf("config: resolve path: %w", err)
	}

	// Walk up from scan target directory looking for .skill-detectorrc.
	dir := absPath
	for {
		candidate := filepath.Join(dir, ".skill-detectorrc")
		if _, err := os.Stat(candidate); err == nil {
			return loadFile(candidate)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached filesystem root
		}
		dir = parent
	}

	// Check user home config.
	home, err := os.UserHomeDir()
	if err == nil {
		candidate := filepath.Join(home, ".config", "skill-detector", "config.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return loadFile(candidate)
		}
	}

	// No config files found — use defaults.
	return DefaultConfig(), nil
}

// loadFile reads and parses a YAML config file.
func loadFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close()

	var raw rawConfig
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&raw); err != nil {
		if err == io.EOF {
			// Empty or comment-only file — use defaults.
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg := DefaultConfig()

	if raw.FailOn != "" {
		sev, err := model.ParseSeverity(raw.FailOn)
		if err != nil {
			return nil, fmt.Errorf("config: %s: invalid fail_on: %w", path, err)
		}
		cfg.FailOn = sev
	}

	if raw.Rules != nil {
		cfg.Rules = raw.Rules
	}
	if raw.Allow.Network != nil || raw.Allow.Filesystem != nil {
		cfg.Allow = raw.Allow
	}

	// Validate rule severity and context overrides.
	for ruleID, rcfg := range cfg.Rules {
		if rcfg.Severity != "" {
			if _, err := model.ParseSeverity(rcfg.Severity); err != nil {
				return nil, fmt.Errorf("config: invalid severity %q for rule %s: %w", rcfg.Severity, ruleID, err)
			}
		}
		if rcfg.Context != "" && rcfg.Context != "expected" {
			return nil, fmt.Errorf("config: invalid context %q for rule %s", rcfg.Context, ruleID)
		}
	}

	return cfg, nil
}
