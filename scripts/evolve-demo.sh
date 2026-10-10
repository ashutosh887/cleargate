#!/usr/bin/env bash
# Reproducible evolve demo on the local stand-in (simulation, no keys, about 10 s):
#   1. take policy.yaml and put back the earlier raw-string branch rule (branch in [main, master]);
#   2. evolve finds survivors (MAIN, refs/heads/main, ...), proposes one rule each with its reason,
#      keeps it only if the legit task still passes, and prunes any proposed rule no case needs;
#   3. re-run with the evolved policy as the base: 0 survivors.
# Writes only under .cleargate/evolve-demo/ (policy.yaml, attacks/evolved.json, docs/ untouched).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"; [ -x "$PY" ] || PY=python3
OUT="$ROOT/.cleargate/evolve-demo"
rm -rf "$OUT"; mkdir -p "$OUT"
cd "$ROOT"

"$PY" - "$OUT/policy.weak.yaml" <<'PY'
import re, sys
s = open("policy.yaml").read()
s, n = re.subn(r"where: \{ branch: \{ matches: '[^']*' \} \}", "where: { branch: { in: [main, master] } }", s, count=1)
assert n == 1, "never-write-to-main rule not found in policy.yaml"
open(sys.argv[1], "w").write(s)
PY

echo "== step 1: evolve against the raw-string branch rule (branch in [main, master])"
"$PY" -m cleargate.cli evolve --target stub --seed 7 --policy "$OUT/policy.weak.yaml" \
  --policy-out "$OUT/policy.evolved.yaml" --set "$OUT/evolved.json" --html "$OUT/evolution.html"

echo
echo "== step 2: re-run with the evolved policy as the base"
"$PY" -m cleargate.cli evolve --target stub --seed 7 --policy "$OUT/policy.evolved.yaml" \
  --policy-out "$OUT/policy.rerun.yaml" --set "$OUT/evolved.rerun.json" --html "$OUT/evolution.rerun.html"
