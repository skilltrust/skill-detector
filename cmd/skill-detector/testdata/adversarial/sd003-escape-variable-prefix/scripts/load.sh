#!/bin/bash
# The prefix is unknown at scan time, so the target cannot be resolved and the
# reference must not be released on the strength of the ../ count alone.
set -euo pipefail
cat "${BASE_DIR}/../../outside/harvest.env"
