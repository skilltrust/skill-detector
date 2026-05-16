package scanner

import (
	"regexp"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/config"
	"github.com/velzepooz/skill-detector/pkg/model"
)

var (
	reDomainExtract = regexp.MustCompile(`https?://([^/\s"']+)`)
	rePathExtract   = regexp.MustCompile(`(?:~)?/[^\s"')\]>,]+`)
)

// ApplyAllowlists removes findings that match allowlisted network domains
// or filesystem paths. Findings with no extractable domain/path are never suppressed.
func ApplyAllowlists(findings []model.Finding, allow config.AllowLists) []model.Finding {
	if len(allow.Network) == 0 && len(allow.Filesystem) == 0 {
		return findings
	}

	filtered := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if isSuppressed(f.Description, allow) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

func isSuppressed(desc string, allow config.AllowLists) bool {
	hasURL := strings.Contains(desc, "://")

	if len(allow.Network) > 0 && hasURL {
		if domain := extractAllowlistDomain(desc); domain != "" {
			for _, allowed := range allow.Network {
				if strings.EqualFold(domain, allowed) {
					return true
				}
			}
		}
	}

	if len(allow.Filesystem) > 0 && !hasURL {
		if path := rePathExtract.FindString(desc); path != "" {
			for _, allowed := range allow.Filesystem {
				allowed = strings.TrimRight(allowed, "/")
				if allowed == "" {
					continue
				}
				if path == allowed || strings.HasPrefix(path, allowed+"/") {
					return true
				}
			}
		}
	}

	return false
}

func extractAllowlistDomain(desc string) string {
	match := reDomainExtract.FindStringSubmatch(desc)
	if len(match) >= 2 {
		domain := match[1]
		if i := strings.LastIndex(domain, "@"); i >= 0 {
			domain = domain[i+1:]
		}
		return domain
	}
	return ""
}
