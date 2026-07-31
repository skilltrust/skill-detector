#!/usr/bin/env bash
# corpus-baseline.sh — scan a corpus of real skill packages and write a
# findings-per-rule histogram.
#
# Used to measure the noise floor before and after detection changes: run it on
# the base revision, run it again after the change, diff the two result files.
#
# Usage:
#   scripts/corpus-baseline.sh [CORPUS_DIR] [OUT_DIR]
#   scripts/corpus-baseline.sh --fetch [CORPUS_DIR]   # populate CORPUS_DIR first
#
# Defaults: CORPUS_DIR=.corpus  OUT_DIR=.corpus-results
# Neither default is in .gitignore yet — add both, or pass paths outside the
# repo, before the first run.
#
# A "package" is any directory containing a SKILL.md. If the corpus has none,
# every immediate subdirectory of CORPUS_DIR is treated as one package.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Corpus sources: the repositories behind the most-installed entries on
# skills.sh. Each is a monorepo holding many individual skill packages.
CORPUS_REPOS=(
	https://github.com/anthropics/skills
	https://github.com/vercel-labs/skills
	https://github.com/vercel-labs/agent-skills
	https://github.com/vercel-labs/agent-browser
	https://github.com/mattpocock/skills
	https://github.com/microsoft/azure-skills
	https://github.com/remotion-dev/skills
	https://github.com/juliusbrussee/caveman
	https://github.com/101-skills/skills
)

fetch_corpus() {
	local dest="$1"
	mkdir -p "$dest"
	for url in "${CORPUS_REPOS[@]}"; do
		local name="${url##*/}"
		local owner="${url%/*}"
		owner="${owner##*/}"
		local dir="$dest/${owner}__${name}"
		if [ -d "$dir/.git" ]; then
			echo "  have  ${owner}/${name}"
			continue
		fi
		echo "  clone ${owner}/${name}"
		git clone --depth=1 --quiet "$url" "$dir" || echo "  WARN: clone failed: $url" >&2
	done
}

if [ "${1:-}" = "--fetch" ]; then
	shift
	fetch_corpus "${1:-$REPO_ROOT/.corpus}"
	exit 0
fi

CORPUS_DIR="${1:-$REPO_ROOT/.corpus}"
OUT_DIR="${2:-$REPO_ROOT/.corpus-results}"

for tool in go jq; do
	command -v "$tool" >/dev/null || { echo "error: $tool not on PATH" >&2; exit 1; }
done
[ -d "$CORPUS_DIR" ] || { echo "error: corpus dir not found: $CORPUS_DIR (run --fetch first)" >&2; exit 1; }

BIN="$REPO_ROOT/bin/skill-detector"
REV="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "Building $BIN at $REV..."
(cd "$REPO_ROOT" && go build -ldflags "-X main.version=corpus-baseline" -o "$BIN" ./cmd/skill-detector)

# Enumerate packages: SKILL.md-bearing dirs, else immediate subdirs.
PKGS_FILE="$(mktemp)"
trap 'rm -f "$PKGS_FILE"' EXIT
find "$CORPUS_DIR" -type f -name SKILL.md -not -path '*/.git/*' -print0 2>/dev/null |
	xargs -0 -n1 dirname 2>/dev/null | sort -u >"$PKGS_FILE" || true
if [ ! -s "$PKGS_FILE" ]; then
	find "$CORPUS_DIR" -mindepth 1 -maxdepth 1 -type d -print | sort >"$PKGS_FILE"
fi
PKG_COUNT="$(wc -l <"$PKGS_FILE" | tr -d ' ')"
[ "$PKG_COUNT" -gt 0 ] || { echo "error: no packages found under $CORPUS_DIR" >&2; exit 1; }

STAMP="$(date +%Y-%m-%d)"
mkdir -p "$OUT_DIR"
RESULTS="$OUT_DIR/${STAMP}-${REV}.md"
RAW="$OUT_DIR/${STAMP}-${REV}.jsonl"
: >"$RAW"

echo "Scanning $PKG_COUNT packages..."
FAILED=0
while IFS= read -r pkg; do
	# Exit 1/2 mean "findings present", not an error; only a crash matters.
	if out="$("$BIN" scan --format json --scan-all "$pkg" 2>/dev/null)"; then :; else
		[ $? -le 2 ] || { FAILED=$((FAILED + 1)); continue; }
	fi
	printf '%s\n' "$out" | jq -c --arg pkg "$pkg" '{pkg: $pkg, findings: (.findings // [])}' >>"$RAW" 2>/dev/null ||
		FAILED=$((FAILED + 1))
done <"$PKGS_FILE"

TOTAL="$(jq -s '[.[].findings | length] | add // 0' "$RAW")"
AFFECTED="$(jq -s '[.[] | select((.findings | length) > 0)] | length' "$RAW")"

{
	echo "# Corpus baseline — $STAMP"
	echo
	echo "- Revision: \`$REV\`"
	echo "- Corpus: \`$CORPUS_DIR\` ($PKG_COUNT packages, $FAILED scan failures)"
	echo "- Command: \`skill-detector scan --format json --scan-all <pkg>\`"
	echo "- Total findings: **$TOTAL** across **$AFFECTED** packages"
	echo
	echo "## Findings per rule"
	echo
	echo "| Rule | Severity | Axis | Findings | Packages |"
	echo "|------|----------|------|---------:|---------:|"
	jq -s -r '
		[.[] | .pkg as $p | .findings[] | {rule: .rule_id, sev: .severity, axis: .axis, pkg: $p}]
		| group_by(.rule)
		| map({
			rule: .[0].rule,
			sev: .[0].sev,
			axis: (.[0].axis // "-"),
			n: length,
			pkgs: ([.[].pkg] | unique | length)
		  })
		| sort_by(-.n)
		| .[]
		| "| \(.rule) | \(.sev) | \(.axis) | \(.n) | \(.pkgs) |"
	' "$RAW"
	echo
	echo "## Top packages by finding count"
	echo
	jq -s -r '
		[.[] | select((.findings | length) > 0) | {pkg: .pkg, n: (.findings | length)}]
		| sort_by(-.n) | .[:15][]
		| "- `\(.pkg)` — \(.n)"
	' "$RAW"
} >"$RESULTS"

echo
cat "$RESULTS"
echo
echo "Wrote $RESULTS"
echo "Raw per-package JSON: $RAW"
