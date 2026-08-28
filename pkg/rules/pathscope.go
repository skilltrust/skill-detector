package rules

import (
	"bytes"
	stdpath "path"
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
// The predicate is an ALLOW-list: a reference is released only when every one of
// its segments is an ordinary, well-formed path segment and the running depth
// never goes negative. Anything it cannot resolve confidently — a variable
// prefix, a percent-encoded separator, a run of three or more dots, an empty
// segment, or a match that is only part of a longer reference — is left flagged.
// Filter-bypass spellings such as `....//` and `..././` are therefore untouched
// by design.
//
// AMBIGUITY IS REFUSED, NOT RESOLVED. Every character the tokeniser cuts a line
// on is a legal POSIX filename character, so a cut is never proof that a
// reference ended there. Rather than guess, the predicate refuses to release any
// line whose reference region carries such a character at all: only a single,
// unbroken, unambiguous reference is ever released. The cost is that a line
// naming two references, or one reference beside a glob, stays flagged; the
// alternative is handing the climb budget out once per fragment, which releases
// references that genuinely leave the skill root.
//
// ANCHOR ASSUMPTION. The walk starts at the file's own depth below the skill
// root, which assumes the reference resolves relative to the directory the file
// sits in. For a script that holds only if the agent `cd`s to it (or uses
// `$(dirname "$0")`); a shell invoked from the project root resolves the same
// string somewhere else. The consequence is deliberate and worth stating: a file
// one level below its skill root always gets exactly one free climb, whatever it
// names. From `.claude/skills/evil/scripts/run.sh` the reference
// `../victim-skill/SKILL.md` is released even though it reads a sibling skill.
// That is accepted rather than overlooked — the file-relative anchor is the only
// anchor a static scanner has, and benign in-package references are written
// against it too, so narrowing it would mean guessing the agent's working
// directory and would re-flag the whole class this predicate exists to release.
//
// POSIX SLASHES ONLY. Both FileContext.Path and FileContext.SkillRoot are read
// as `/`-separated strings. Discovery stamps SkillRoot through filepath.ToSlash
// but not Path, so on Windows the path arrives as `scripts\run.sh`, the depth
// comes out 0 (or -1 under a nested root) and every `../` stays flagged. The
// predicate goes inert there and SD-003 behaves exactly as it did before this
// release: the failure direction is over-flagging, never under-flagging, so it
// is left as a documented property rather than guessed at with a separator
// heuristic here.

// reRelativePathToken matches a run containing `../`, cut at the characters that
// can end a shell word. It is deliberately its own pattern: widening
// rePathTraversal or any other shared regex to serve this predicate is how
// SD-004's widening once turned ordinary prose into Critical SD-013 findings.
//
// Its terminator class is deliberately not reFullPath's (access_control.go:18),
// which ends a path on `#`, `$`, `{`, `}` and runs straight through `*`, `(`,
// `<`. The two answer different questions — reFullPath extracts a path to quote
// in a finding, this one cuts a line into candidate references — so this file
// and access_control.go hold two different opinions about what ends a path token
// on purpose. EVERY character cut on here is legal inside a POSIX filename —
// a space, a tab, `(`, `;`, `&`, `<`, `*` and the rest — so a cut is never
// proof that a reference ended. That is why the release decision does not trust
// the cut: referenceRegionIsUnambiguous refuses the whole line the moment one of
// these characters falls inside the region the references occupy, and
// isWholeReference refuses a match that abuts one on the outside.
var reRelativePathToken = regexp.MustCompile("[^\\s\"'`()\\[\\]<>,;|&*]*\\.\\./[^\\s\"'`()\\[\\]<>,;|&*]*")

// reOrdinarySegment is the allow-list charset for a single path segment.
// `+` is inert for path resolution (no shell or filesystem meaning here); it's
// allow-listed only because it's a legal filename character.
var reOrdinarySegment = regexp.MustCompile(`^[A-Za-z0-9._@+~-]+$`)

// unresolvableTokenChars are the characters that make a token's target
// impossible to know statically. Tested against the whole token, not per
// segment: a token carrying any of them anywhere is never released.
//
// This check is deliberately REDUNDANT today and no test can prove otherwise:
// every character in the set also falls outside reOrdinarySegment, so the
// segment walk below refuses the same tokens on its own — removing this `if`
// breaks nothing in the suite (verified by construction, not assumed). It is
// kept as a cheap early exit and as depth: it becomes load-bearing the moment
// reOrdinarySegment is widened, which is a live possibility (see ADR-0011's
// residual false positives, where the ASCII-only charset is the recorded cost).
// Widening that charset without keeping this guard would release `$HOME/../..`.
const unresolvableTokenChars = `${}%\`

// referenceBoundaryChars are the characters that may stand immediately OUTSIDE
// a complete reference without being part of it: shell word separators, quoting
// and grouping. Every one of them is also legal inside a filename, so this set
// alone can never establish that a match is whole — that job belongs to
// referenceRegionIsUnambiguous, which runs first and refuses the line whenever
// any of these appears *between* the references. What is left for this set is
// the outside edge: a match abutting a character that is NOT here — `*`, `[`,
// `]`, `,` — is visibly a fragment of something longer and is refused.
const referenceBoundaryChars = " \t\v\f\r\"'`()<>;|&"

// referenceAmbiguityChars is every character reRelativePathToken cuts on. Each
// one is a legal POSIX filename character, so each one can appear *inside* a
// real reference; when one does, the tokeniser cuts the reference into two
// fragments and each fragment is then walked from the file's own depth, handing
// out the climb budget twice. `../a(b)c/../../outside/x` from one level below
// the root is the shape: two fragments, both apparently in-package, one real
// reference that leaves the skill.
//
// So the predicate does not try to decide which side of the cut is real. It
// refuses to release a line whose reference region contains any of these at all
// (see referenceRegionIsUnambiguous). Only an unambiguous, single, unbroken
// reference is ever released, which is the direction this predicate must fail
// in: every ambiguous spelling stays flagged.
const referenceAmbiguityChars = " \t\n\v\f\r\"'`()[]<>,;|&*"

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
	// The depth is a climb budget, so every over-count is a free climb — a
	// false negative. pkg/rules is a published package: discovery hands us
	// clean filepath.Rel output, but an embedder (skilltrust, scan-action)
	// builds model.FileContext itself, and `./scripts/run.sh` or `a//b/run.sh`
	// would otherwise count one separator too many. Canonicalise first, with
	// path.Clean and not filepath.Clean, because these are POSIX-slash strings
	// on every platform (see the file header).
	rel = stdpath.Clean(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
		return -1 // not a relative location under the root at all
	}
	return strings.Count(rel, "/")
}

// relativeRefStaysInSkill reports whether every `../`-bearing reference on the
// line resolves to a location still inside the file's own skill root.
func relativeRefStaysInSkill(line []byte, ctx model.FileContext) bool {
	depth := skillRelativeDirDepth(ctx)
	if depth < 0 {
		return false
	}
	matches := reRelativePathToken.FindAllIndex(line, -1)
	if len(matches) == 0 {
		return false
	}
	// The release decision is about a whole reference. If the region the
	// references occupy is ambiguous — if it holds even one character that
	// could equally be a separator or a filename byte — no walk over the
	// fragments can be trusted, so nothing on the line is released.
	if !referenceRegionIsUnambiguous(line, matches) {
		return false
	}
	for _, m := range matches {
		if !isWholeReference(line, m[0], m[1]) {
			return false
		}
		if !tokenStaysInside(string(line[m[0]:m[1]]), depth) {
			return false
		}
	}
	return true
}

// referenceRegionIsUnambiguous reports whether the span of the line that carries
// the `../` references — from the first `../` on the line to the end of the last
// `../`-bearing match — is free of every character the tokeniser cuts on.
//
// A character from referenceAmbiguityChars inside that span means the line can
// be read two ways: as several separate references, or as one longer reference
// whose filename happens to contain that byte. The two readings resolve to
// different places, and only the first one is what the per-match walk below
// actually computes, so the span is refused outright rather than guessed at.
//
// With the current tokeniser this is equivalent to "release only a line carrying
// exactly one `../` match", because reRelativePathToken's matches are maximal
// runs of non-cut bytes and any gap between two of them therefore holds a cut
// byte. It is written as a region scan and not as a match count because that
// equivalence is a property of the cut set, not of the rule: widening or
// narrowing reRelativePathToken would silently break the short spelling and
// leave this one correct.
func referenceRegionIsUnambiguous(line []byte, matches [][]int) bool {
	first := bytes.Index(line, []byte("../"))
	if first < 0 {
		return false // no literal `../` to anchor the region on
	}
	end := matches[len(matches)-1][1]
	for _, c := range line[first:end] {
		if strings.IndexByte(referenceAmbiguityChars, c) >= 0 {
			return false
		}
	}
	return true
}

// isWholeReference reports whether the match at [start,end) is a complete
// delimited reference: the character on each side is either absent (a line
// boundary) or one of the separators that may stand outside a reference.
//
// This is the outside edge only. It cannot establish that a match is whole —
// every character in referenceBoundaryChars is legal in a filename too — and it
// is not asked to: referenceRegionIsUnambiguous has already refused the line if
// anything ambiguous sits between the references. What is left for this check is
// the narrower job of refusing a match that abuts a character the tokeniser cut
// on but which is *not* a plausible separator at all (`*`, `[`, `]`, `,`), i.e.
// a match that is visibly the head or tail of something longer. That keeps
// `cat ../data/*.json` flagged — a recorded, deliberate false positive.
func isWholeReference(line []byte, start, end int) bool {
	return isReferenceBoundary(line, start-1) && isReferenceBoundary(line, end)
}

// isReferenceBoundary reports whether the byte at index i may stand outside a
// reference.
func isReferenceBoundary(line []byte, i int) bool {
	if i < 0 || i >= len(line) {
		return true // the start or end of the line always ends a reference
	}
	return strings.IndexByte(referenceBoundaryChars, line[i]) >= 0
}

// tokenStaysInside walks one token segment by segment from `depth` levels below
// the skill root and reports whether it ends up still inside it.
func tokenStaysInside(tok string, depth int) bool {
	// `@` is Claude Code's file-reference sigil, not a path segment: `@./..`
	// is `./..`, one level up, and reading the `@.` as a directory name would
	// hide exactly one level of climb. Trim every leading sigil, not just one:
	// a doubled sigil (`@@~/..`) only ever exposes more of the token underneath
	// (a `..` or `~` that TrimPrefix would leave stuck to the `@` and read as an
	// ordinary segment), so trimming further can only push the result toward
	// flagged, never toward released. A directory genuinely named `@@foo` is
	// still an ordinary segment either way, so nothing legitimate is lost.
	tok = strings.TrimLeft(tok, "@")
	if strings.HasPrefix(tok, "/") {
		return false // absolute — the other branch's business, never this one's
	}
	if strings.ContainsAny(tok, unresolvableTokenChars) {
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
	return len(seg) > 2 && strings.Trim(seg, ".") == ""
}
