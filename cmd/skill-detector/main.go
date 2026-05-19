package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/config"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/reporter"
	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/scanner"
)

var version = "0.1.0-dev"

// expectedChecksum is set via ldflags at build time:
//
//	go build -ldflags "-X main.expectedChecksum=abc123..."
//
// If empty (dev builds), checksum verification is skipped.
var expectedChecksum string

// scanExitCode captures the exit code from scan results (not tool errors).
var scanExitCode int

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "skill-detector",
		Short:         "Detect security threats in AI skill packages",
		Long:          "skill-detector scans AI skill/plugin packages for OWASP-aligned security threats.",
		SilenceErrors: true,
	}

	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newScanCmd())

	return rootCmd
}

func newRegistry() *rules.RuleRegistry {
	return rules.DefaultRegistry()
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of skill-detector",
		RunE: func(cmd *cobra.Command, args []string) error {
			registry := newRegistry()
			fmt.Fprintf(cmd.OutOrStdout(), "skill-detector version %s (%d rules, checksum %s)\n",
				version, registry.Count(), registry.Checksum())
			return nil
		},
	}
}

func newScanCmd() *cobra.Command {
	var noColor bool
	var verbose bool
	var format string
	var quiet bool
	var failOn string
	var failOnAxis []string
	var configFlag string

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a skill package for security threats",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			path := args[0]
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			if !info.IsDir() {
				return fmt.Errorf("scan: %s is not a directory", path)
			}

			// Load configuration (cascading lookup or explicit file).
			cfg, err := config.Load(path, configFlag)
			if err != nil {
				return err
			}

			// CLI --fail-on flag overrides config file.
			if failOn != "" {
				sev, err := model.ParseSeverity(failOn)
				if err != nil {
					return fmt.Errorf("scan: invalid --fail-on value: %w", err)
				}
				cfg.FailOn = sev
			}

			registry := newRegistry()

			// Verify ruleset integrity (AC3).
			checksum := registry.Checksum()
			if expectedChecksum != "" && checksum != expectedChecksum {
				return fmt.Errorf("scan: ruleset checksum mismatch: expected %s, got %s", expectedChecksum, checksum)
			}

			s := scanner.New(registry, scanner.Options{
				Config:  cfg,
				Version: version,
			})
			result, err := s.Scan(cmd.Context(), cliInput{p: path})
			if err != nil {
				return err
			}

			var rep reporter.Reporter
			if quiet {
				rep = &reporter.QuietReporter{}
			} else {
				switch format {
				case "text":
					if !noColor {
						if f, ok := cmd.OutOrStdout().(*os.File); ok {
							if fInfo, err := f.Stat(); err == nil {
								noColor = fInfo.Mode()&os.ModeCharDevice == 0
							}
						} else {
							noColor = true
						}
					}
					rep = &reporter.TextReporter{Theme: reporter.NewTheme(noColor), Verbose: verbose}
				case "json":
					rep = &reporter.JSONReporter{}
				default:
					return fmt.Errorf("scan: unsupported format %q (expected text or json)", format)
				}
			}

			if err := rep.Report(*result, cmd.OutOrStdout()); err != nil {
				return err
			}

			scanExitCode = exitCode(*result, cfg.FailOn)

			// --fail-on-axis: exit 2 if any axis grade is worse than its threshold.
			if axisExceeded, err := checkFailOnAxis(failOnAxis, result.Axes); err != nil {
				return err
			} else if axisExceeded && scanExitCode < 2 {
				scanExitCode = 2
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress output, exit code only")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show full finding details")
	cmd.Flags().StringVar(&format, "format", "text", "Output format (text, json)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Severity threshold for non-zero exit (critical, high, medium, low, info)")
	cmd.Flags().StringArrayVar(&failOnAxis, "fail-on-axis", nil,
		"Fail if axis grade is worse than threshold. Format: axis=grade (e.g. security=B). Repeatable.")
	cmd.Flags().StringVar(&configFlag, "config", "", "Path to config file (skip cascading lookup)")

	return cmd
}

// gradeRank maps letter grade to numeric rank (lower = better).
var gradeRank = map[string]int{"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

// checkFailOnAxis evaluates --fail-on-axis specs against axisResults.
// Returns (true, nil) if any axis grade is strictly worse than its threshold.
// Returns (false, error) if a spec is malformed.
func checkFailOnAxis(specs []string, axisResults map[axes.Axis]model.AxisResult) (bool, error) {
	for _, spec := range specs {
		parts := strings.SplitN(spec, "=", 2)
		if len(parts) != 2 {
			return false, fmt.Errorf("scan: invalid --fail-on-axis spec %q (want axis=grade)", spec)
		}
		threshold, ok := gradeRank[strings.ToUpper(parts[1])]
		if !ok {
			return false, fmt.Errorf("scan: invalid grade %q in --fail-on-axis (want A, B, C, D, or F)", parts[1])
		}
		a := axes.Axis(parts[0])
		res, ok := axisResults[a]
		if !ok {
			continue
		}
		actual, ok := gradeRank[string(res.Grade)]
		if !ok {
			continue
		}
		if actual > threshold {
			return true, nil
		}
	}
	return false, nil
}

func exitCode(result model.ScanResult, threshold model.Severity) int {
	if len(result.Findings) == 0 {
		return 0
	}
	for _, f := range result.Findings {
		if f.EffSeverity <= threshold {
			return 2
		}
	}
	return 1
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if scanExitCode != 0 {
		os.Exit(scanExitCode)
	}
}
