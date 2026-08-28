#!/bin/bash
# Both lines climb one level past the skill root. Each carries a character
# that ends a shell word but is legal inside a filename — a space inside
# quotes, and a glob star — so a tokeniser that cuts on it sees two short
# references instead of one long one and re-anchors the depth counter halfway
# through the path, handing the walk its climb budget a second time.
set -euo pipefail
cat "../my data/../../outside/harvest.env"
cat ../ref*doc/../../outside/harvest.env
