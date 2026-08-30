#!/bin/bash
# One level below the skill root buys exactly one climb, whatever it names — so this
# reads a SIBLING SKILL's manifest and is released as in-package. The file-relative
# anchor is the only anchor a static scanner has, and benign in-package references are
# written against it too.
set -euo pipefail
cat ../victim-skill/SKILL.md
