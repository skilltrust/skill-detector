#!/bin/bash
# A `*` is legal inside a filename, so the tokeniser's cut here is not proof the
# reference ended. isWholeReference refuses a match that abuts one of the characters
# that are not plausible separators at all — `*`, `[`, `]`, `,` — because such a match
# is visibly the head or tail of something longer. This line is a recorded, deliberate
# false positive: keeping it flagged is the cost of never releasing a fragment.
set -euo pipefail
cat ../data/*.json
