package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/delta"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func newDeltaCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "delta <base.json> <head.json>",
		Short: "Compute the trust-score delta between two scan result JSON files",
		Long: "Reads two `skill-detector scan --format json` output files (base + head) " +
			"and emits the per-axis grade movement + finding diff. Pure function — no IO " +
			"besides reading the two input files.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			base, err := loadScan(args[0])
			if err != nil {
				return fmt.Errorf("delta: base: %w", err)
			}
			head, err := loadScan(args[1])
			if err != nil {
				return fmt.Errorf("delta: head: %w", err)
			}
			d := delta.Compute(base, head)
			switch format {
			case "json":
				return writeDeltaJSON(cmd.OutOrStdout(), d)
			case "markdown":
				return writeDeltaMarkdown(cmd.OutOrStdout(), d)
			default:
				return fmt.Errorf("delta: unsupported --format %q (want json or markdown)", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "Output format: json | markdown")
	return cmd
}

func loadScan(path string) (*model.ScanResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r model.ScanResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &r, nil
}

// writeDeltaJSON emits a stable, sorted JSON shape.
func writeDeltaJSON(w io.Writer, d delta.Delta) error {
	type gd struct {
		Old, New, Direction string
	}
	perAxis := map[string]gd{}
	for axis, x := range d.PerAxis {
		perAxis[string(axis)] = gd{
			Old: string(x.Old), New: string(x.New), Direction: x.Direction,
		}
	}
	axisExplanations := map[string]string{}
	for axis, exp := range d.AxisExplanations {
		axisExplanations[string(axis)] = exp
	}
	out := map[string]any{
		"per_axis":          perAxis,
		"new_findings":      d.NewFindings,
		"resolved_findings": d.ResolvedFindings,
		"axis_explanations": axisExplanations,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// writeDeltaMarkdown emits a human-readable delta block. Stable axis order.
func writeDeltaMarkdown(w io.Writer, d delta.Delta) error {
	axesSorted := make([]axes.Axis, 0, len(d.PerAxis))
	for a := range d.PerAxis {
		axesSorted = append(axesSorted, a)
	}
	sort.Slice(axesSorted, func(i, j int) bool { return string(axesSorted[i]) < string(axesSorted[j]) })

	var lines []string
	lines = append(lines, "| Axis | Grade | Δ |", "|------|-------|---|")
	for _, a := range axesSorted {
		x := d.PerAxis[a]
		mark := "—"
		if x.Direction != "same" && x.Old != "" {
			mark = delta.GradeArrow(x)
		}
		lines = append(lines, fmt.Sprintf("| %s | %s | %s |", a, x.New, mark))
	}
	if len(d.AxisExplanations) > 0 {
		lines = append(lines, "", "**Why downgraded:**")
		expKeys := make([]axes.Axis, 0, len(d.AxisExplanations))
		for a := range d.AxisExplanations {
			expKeys = append(expKeys, a)
		}
		sort.Slice(expKeys, func(i, j int) bool { return string(expKeys[i]) < string(expKeys[j]) })
		for _, a := range expKeys {
			lines = append(lines, fmt.Sprintf("- **%s:** %s", a, d.AxisExplanations[a]))
		}
	}
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	_, err := w.Write([]byte(out))
	return err
}
