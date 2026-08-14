package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

var updateSchemaGolden = flag.Bool("update-schema-golden", false, "rewrite the schema golden file")

// The JSON wire format is versioned by model.SchemaVersion. This golden holds
// real `scan --format json` output, so any change to the emitted shape shows up
// as a diff here; the version check below then forces the bump to be deliberate
// (engine review F-10).
func TestScanJSONOutputMatchesSchemaGolden(t *testing.T) {
	var stdout bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "--format", "json", "../../testdata/malicious/mcp-domain"})

	scanExitCode = 0
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Checksum, build version and rule count move with every rule edit and are
	// not part of the wire shape — normalize them so this test tracks the
	// schema rather than the ruleset.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal scan output: %v", err)
	}
	raw["ruleset_checksum"] = json.RawMessage(`"<checksum>"`)
	raw["version"] = json.RawMessage(`"<version>"`)
	raw["rules_applied"] = json.RawMessage(`0`)
	got, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal scan output: %v", err)
	}
	got = append(got, '\n')

	golden := filepath.Join("testdata", "schema_output.golden")
	if *updateSchemaGolden {
		if err := os.MkdirAll(filepath.Dir(golden), 0o750); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}

	want, err := os.ReadFile(golden) // #nosec G304 — fixed test path
	if err != nil {
		t.Fatalf("read golden: %v (run with -update-schema-golden to create)", err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("scan JSON shape changed.\n--- got ---\n%s\n--- want ---\n%s\n"+
			"If the change is intentional: bump model.SchemaVersion and re-run with -update-schema-golden.",
			got, want)
	}
}

// Each schema version is pinned to one output shape. Re-blessing the golden
// after a shape change without bumping model.SchemaVersion collides with the
// recorded fingerprint and fails here — that is the coupling F-10 found missing.
func TestSchemaShapeIsPinnedToVersion(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "schema_output.golden")) // #nosec G304 — fixed test path
	if err != nil {
		t.Fatalf("read golden: %v (run TestScanJSONOutputMatchesSchemaGolden with -update-schema-golden)", err)
	}

	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	got := shapeFingerprint(doc)

	var golden model.ScanResult
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatalf("unmarshal golden into ScanResult: %v", err)
	}
	if golden.SchemaVersion != model.SchemaVersion {
		t.Fatalf("golden schema_version %q != model.SchemaVersion %q — regenerate the golden",
			golden.SchemaVersion, model.SchemaVersion)
	}

	pinPath := filepath.Join("testdata", "schema_shapes.json")
	raw, err := os.ReadFile(pinPath) // #nosec G304 — fixed test path
	if err != nil {
		t.Fatalf("read %s: %v", pinPath, err)
	}
	pins := map[string]string{}
	if err := json.Unmarshal(raw, &pins); err != nil {
		t.Fatalf("unmarshal %s: %v", pinPath, err)
	}

	want, pinned := pins[model.SchemaVersion]
	if !pinned {
		t.Fatalf("schema version %s has no recorded shape — add %q: %q to %s",
			model.SchemaVersion, model.SchemaVersion, got, pinPath)
	}
	if got != want {
		t.Errorf("output shape changed but model.SchemaVersion is still %s.\n"+
			"recorded: %s\ncurrent:  %s\n"+
			"Bump model.SchemaVersion and record the new shape in %s.",
			model.SchemaVersion, want, got, pinPath)
	}
}

// shapeFingerprint hashes the set of JSON key paths and their value kinds,
// ignoring values, array length and key order.
func shapeFingerprint(v any) string {
	paths := map[string]bool{}
	collectShape("", v, paths)

	ordered := make([]string, 0, len(paths))
	for p := range paths {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)

	h := sha256.New()
	for _, p := range ordered {
		h.Write([]byte(p + "\n"))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}

func collectShape(path string, v any, out map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			out[p+":"+kindOf(child)] = true
			collectShape(p, child, out)
		}
	case []any:
		for _, child := range t {
			collectShape(path+"[]", child, out)
		}
	}
}

func kindOf(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}
