package reporter

import (
	"io"

	"github.com/velzepooz/skill-detector/internal/model"
)

// QuietReporter writes minimal scan result output (exit code only, no output).
type QuietReporter struct{}

// Report writes nothing; the caller uses the exit code to convey the result.
func (q *QuietReporter) Report(result model.ScanResult, w io.Writer) error {
	return nil
}
