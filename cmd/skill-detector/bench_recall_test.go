package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/scanner"
)

type benchDir string

func (b benchDir) Path() string { return string(b) }

// Tripwire: the curated malicious slice must always be flagged (worst grade
// C/D/F). A drop here means a rule change reduced recall on a known attack.
func TestBenchRecall_CuratedSliceAllFlagged(t *testing.T) {
	cases := []string{"exfil-curl-env", "cnc-comment"}
	reg := rules.DefaultRegistry()
	for _, id := range cases {
		sc := scanner.New(reg, scanner.Options{Version: "test"})
		res, err := sc.Scan(context.Background(),
			benchDir(filepath.Join("..", "..", "testdata", "bench", id)))
		if err != nil {
			t.Fatalf("%s: scan: %v", id, err)
		}
		if !flagged(res.Axes) {
			t.Errorf("%s: NOT flagged — recall regression on a known attack", id)
		}
	}
}

func flagged(axesMap map[axes.Axis]model.AxisResult) bool {
	for _, ar := range axesMap {
		switch ar.Grade {
		case "C", "D", "F":
			return true
		}
	}
	return false
}
