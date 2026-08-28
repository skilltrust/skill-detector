#!/bin/bash
# `....//` and `..././` are the spellings that survive a sanitiser which strips
# one `../`. Segment-wise they carry no bare `..`, which is exactly why the
# predicate must refuse to resolve a dot-run rather than treat it as a name.
set -euo pipefail
cat ....//....//outside/harvest.env
cat ..././..././outside/harvest.env
