package rules

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/model"
)

// A `../` reference is only traversal if it actually leaves the skill. Since
// v0.8.0 discovery stamps every file with the skill root it belongs to
// (ADR-0010), so the rule can resolve the reference instead of pattern-matching
// it: a token that never takes the walk below its own skill root is an ordinary
// in-package reference, not an escape.
//
// Everything here is a pure function of the FileContext it is handed. It reads
// no files and resolves nothing against the real filesystem, which is what keeps
// pkg/rules embeddable (ADR-0010) and what keeps discovery's scoped os.Root the
// only thing that ever opens a path.
//
// The predicate is an ALLOW-list: a token is released only when every one of its
// segments is an ordinary, well-formed path segment and the running depth never
// goes negative. Anything it cannot resolve confidently — a variable prefix, a
// percent-encoded separator, a run of three or more dots, an empty segment — is
// left flagged. Filter-bypass spellings such as `....//` and `..././` are
// therefore untouched by design.

// reRelativePathToken matches a whitespace- and quote-delimited run containing
// `../`. It is deliberately its own pattern: widening rePathTraversal or any
// other shared regex to serve this predicate is how SD-004's widening once
// turned ordinary prose into Critical SD-013 findings.
var reRelativePathToken = regexp.MustCompile("[^\\s\"'`()\\[\\]<>,;|&*]*\\.\\./[^\\s\"'`()\\[\\]<>,;|&*]*")

// reOrdinarySegment is the allow-list charset for a single path segment.
// `+` is inert for path resolution (no shell or filesystem meaning here); it's
// allow-listed only because it's a legal filename character.
var reOrdinarySegment = regexp.MustCompile(`^[A-Za-z0-9._@+~-]+$`)

// unresolvableSegmentChars are the characters that make a token's target
// impossible to know statically. A token carrying any of them is never released.
const unresolvableSegmentChars = `${}%\`

// skillRelativeDirDepth reports how many directories deep the file sits below
// its own skill root, or -1 when that cannot be determined — no skill root was
// stamped, or the path does not lie under the root that was.
func skillRelativeDirDepth(ctx model.FileContext) int {
	if ctx.SkillRoot == "" {
		return -1
	}
	rel := ctx.Path
	if ctx.SkillRoot != "." {
		prefix := ctx.SkillRoot + "/"
		if !strings.HasPrefix(ctx.Path, prefix) {
			return -1
		}
		rel = strings.TrimPrefix(ctx.Path, prefix)
	}
	if rel == "" {
		return -1
	}
	return strings.Count(rel, "/")
}

// relativeRefStaysInSkill reports whether every `../`-bearing token on the line
// resolves to a location still inside the file's own skill root.
func relativeRefStaysInSkill(line []byte, ctx model.FileContext) bool {
	depth := skillRelativeDirDepth(ctx)
	if depth < 0 {
		return false
	}
	tokens := reRelativePathToken.FindAll(line, -1)
	if len(tokens) == 0 {
		return false
	}
	for _, tok := range tokens {
		if !tokenStaysInside(string(tok), depth) {
			return false
		}
	}
	return true
}

// tokenStaysInside walks one token segment by segment from `depth` levels below
// the skill root and reports whether it ends up still inside it.
func tokenStaysInside(tok string, depth int) bool {
	// `@` is Claude Code's file-reference sigil, not a path segment: `@./..`
	// is `./..`, one level up, and reading the `@.` as a directory name would
	// hide exactly one level of climb.
	tok = strings.TrimPrefix(tok, "@")
	if strings.HasPrefix(tok, "/") {
		return false // absolute — the other branch's business, never this one's
	}
	if strings.ContainsAny(tok, unresolvableSegmentChars) {
		return false
	}
	segs := strings.Split(tok, "/")
	if n := len(segs); n > 0 && segs[n-1] == "" {
		segs = segs[:n-1] // a trailing slash is not a segment
	}
	for _, seg := range segs {
		switch {
		case seg == "..":
			depth--
			if depth < 0 {
				return false
			}
		case seg == ".":
			// no-op
		case strings.HasPrefix(seg, "~"):
			// A leading `~` is shell home-directory expansion (`~` or
			// `~user`) — an absolute path to a home directory, not a
			// subdirectory of the current one — so it can never be pushed
			// as an ordinary segment. Same unresolvable-prefix class as
			// `$HOME` and `${ROOT}` above. A trailing `~` (e.g. a
			// `notes.md~` backup file) is unaffected — it falls through to
			// the ordinary-segment case below.
			return false
		case isDotRun(seg) || !reOrdinarySegment.MatchString(seg):
			return false
		default:
			depth++
		}
	}
	return true
}

// isDotRun reports whether a segment is three or more dots and nothing else —
// `...`, `....`. These are the building blocks of the traversal filter-bypass
// spellings (`....//`, `..././`), so a token containing one is never released.
func isDotRun(seg string) bool {
	return len(seg) > 2 && len(bytes.Trim([]byte(seg), ".")) == 0
}
