#!/usr/bin/env bash
# Re-measure every published number against the live AgntID runtime, in one go.
#
#   scripts/live_all.sh          live: needs runtime_proof.py ALL PASS (portal steps done)
#   scripts/live_all.sh --stub   dry run on the local stand-in; every number is labelled STUB
#
# Each step logs to records/live-<ts>/, every new signed record is checked with verify.py,
# and submission/live-numbers.md gets the command, exit code, key output and record path per step.
set -uo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
[ -x "$PY" ] || PY=python3

MODE=live
[ "${1:-}" = "--stub" ] && MODE=stub
TS=$(date +%Y%m%d-%H%M%S)
OUT=records/live-$TS
mkdir -p "$OUT"
STAMP=$OUT/.start
touch "$STAMP"
SUMMARY=submission/live-numbers.md
mkdir -p "$(dirname "$SUMMARY")"

if [ "$MODE" = live ]; then
  echo "== runtime_proof.py"
  if ! $PY scripts/runtime_proof.py --json "$OUT/runtime_proof.json" | tee "$OUT/runtime_proof.log"; then :; fi
  if ! grep -q '^ALL PASS' "$OUT/runtime_proof.log"; then
    echo
    echo "STOP: the runtime is not fully wired. Do the unchecked portal steps above"
    echo "(docs/RUNTIME_PROOF.md), then run scripts/live_all.sh again."
    exit 2
  fi
  export CLEARGATE_ENFORCER=agntid CLEARGATE_TOOLS=mcp
  $PY -m cleargate.mcp.seed || { echo "STOP: seeding Postgres failed"; exit 2; }
  TARGET=agntid; STUBFLAG=""; LABEL="LIVE AgntID runtime"
else
  export CLEARGATE_ENFORCER=local
  TARGET=stub; STUBFLAG="--stub"; LABEL="STUB DRY RUN (local stand-in, not AgntID)"
fi
export CLEARGATE_LLM=scripted PAYEE_CHECK=off

for port in 9101 9102; do
  if [ "$MODE" = live ] && ! (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null; then
    echo "MCP server on :$port is down; starting cleargate.mcp.serve"
    nohup $PY -m cleargate.mcp.serve > .cleargate/mcp-serve.log 2>&1 &
    sleep 3; break
  fi
done

{
  echo "# Live numbers: $LABEL"
  echo
  echo "Run $TS, $(date '+%H:%M IST %a %Y-%m-%d'). Env: CLEARGATE_ENFORCER=$CLEARGATE_ENFORCER, CLEARGATE_LLM=scripted, PAYEE_CHECK=off."
  [ "$MODE" = stub ] && echo && echo "**Stub dry run: these are local stand-in numbers, not AgntID. Do not publish them as live.**"
  echo
} > "$SUMMARY"

step() {  # step <name> <grep pattern for key lines> <command...>
  local name=$1 pat=$2; shift 2
  echo "== $name: $*"
  local start; start=$(date +%s)
  "$@" > "$OUT/$name.log" 2>&1
  local rc=$?
  local secs=$(( $(date +%s) - start ))
  echo "   exit $rc in ${secs}s, log $OUT/$name.log"
  {
    echo "## $name"
    echo
    echo "\`$*\` (exit $rc, ${secs}s, log \`$OUT/$name.log\`)"
    echo
    echo '```'
    grep -Ei "$pat" "$OUT/$name.log" | head -25 || true
    [ $rc -ne 0 ] && tail -5 "$OUT/$name.log"
    echo '```'
    echo
  } >> "$SUMMARY"
}

step check 'that reached a tool|visible|tokens|NO-GO|  GO|out-of-task attempts|record:' \
  $PY -m cleargate.cli check --mode both $STUBFLAG
step attack-suite 'reached|blocked|attacks|of [0-9]+|written|out' \
  $PY -m cleargate.cli attack-suite --target "$([ $MODE = live ] && echo both || echo stock)" --out "$OUT/attacks.json"
step gate 'GO|reached|attacks|need|PASS|FAIL' \
  $PY -m cleargate.cli gate --target $TARGET --json "$OUT/gate.json" --summary "$OUT/gate-summary.md"
step bank-demo 'attacks reached a tool|record:' \
  $PY -m cleargate.cli bank --demo all --mode both $STUBFLAG
step bank-campaign '₹|moved|calls|record:' \
  $PY -m cleargate.cli bank --campaign --seed 7 $STUBFLAG
step coverage 'cases|reach|intent|control|written|html' \
  $PY -m cleargate.cli coverage --target $TARGET --html "$OUT/coverage.html"
step bench '.' \
  $PY -m cleargate.cli bench --target $TARGET --n 30

echo "== verify every new record"
{
  echo "## Signed records from this run"
  echo
  echo '| record | verify.py |'
  echo '|---|---|'
} >> "$SUMMARY"
fails=0
while IFS= read -r rec; do
  res=$($PY verify.py "$rec" 2>&1 | head -1)
  case $res in MATCH*) ;; *) fails=$((fails + 1));; esac
  echo "   $rec: $res"
  echo "| \`$rec\` | ${res//|//} |" >> "$SUMMARY"
done < <(find records -name '*.jsonl' -newer "$STAMP" -type f | sort)
echo >> "$SUMMARY"
echo "Records not matching: $fails" >> "$SUMMARY"

echo
echo "Summary: $SUMMARY ($LABEL). Records not matching: $fails"
