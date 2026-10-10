#!/bin/zsh
# End-to-end verification of the live site, repo and CI, code, console and AgntID runtime.
# Writes submission/verification.md (private). Exit 0 only when nothing FAILs.
cd "${0:A:h}/.." || exit 1
exec .venv/bin/python scripts/verify_all.py "$@"
