package reporter

import (
	"encoding/json"
	"io"

	"github.com/velzepooz/skill-detector/pkg/model"
)

// JSONReporter writes scan results as JSON.
type JSONReporter struct{}

// Report writes the scan result in JSON format.
func (j *JSONReporter) Report(result model.ScanResult, w io.Writer) error {
	// Normalize nil slices to empty slices for consumer-friendly JSON.
	if result.Findings == nil {
		result.Findings = []model.Finding{}
	}
	if result.Permissions == nil {
		result.Permissions = []model.Permission{}
	}
	if result.ConfigOverrides == nil {
		result.ConfigOverrides = []model.ConfigOverride{}
	}
	if result.Warnings == nil {
		result.Warnings = []string{}
	}
	for i := range result.Permissions {
		if result.Permissions[i].Details == nil {
			result.Permissions[i].Details = []string{}
		}
	}
	return json.NewEncoder(w).Encode(result)
}
