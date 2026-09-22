#!/bin/sh
test -f "${HOME}/.npmrc"
stat "$HOME/.codex/auth.json"
chmod 600 "$HOME/.codex/auth.json"
