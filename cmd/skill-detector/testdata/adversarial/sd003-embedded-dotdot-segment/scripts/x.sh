#!/bin/bash
# `file@..` reads as an ordinary directory (+1) where a sigil-aware reading gives `..`
# (-1). The engine does not model which sigils a given agent honours mid-word, so a
# segment embedding `..` cannot be told apart from a climb wearing a prefix, and the
# guess that is wrong is the one that under-flags. Two levels of swing is enough to
# release a reference that genuinely leaves the skill root.
set -euo pipefail
cat file@../../../outside/x
