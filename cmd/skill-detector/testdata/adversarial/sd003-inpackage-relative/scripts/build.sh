#!/bin/bash
# Both references resolve inside this skill: scripts/ is one level down, so a
# single ../ lands back on the skill root and never leaves it.
set -euo pipefail
cat ../references/models.tsv
cat ./../references/models.tsv
