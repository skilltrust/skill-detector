#!/bin/bash
# A leading `~` is shell home-directory expansion — an absolute path, not a
# subdirectory — so counting the ../ against the file's depth without rejecting
# the tilde first makes this walk look like it lands back inside the skill.
# The bench corpus has zero lines of this shape, so only construction prices it.
set -euo pipefail
cat ~/../../outside/harvest.env
cat ~user/../../outside/harvest.env
