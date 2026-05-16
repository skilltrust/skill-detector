package reporter

import (
	"io"

	"github.com/velzepooz/skill-detector/pkg/model"
)

// Reporter formats and writes a ScanResult.
type Reporter interface {
	Report(result model.ScanResult, w io.Writer) error
}
