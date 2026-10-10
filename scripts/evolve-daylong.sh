#!/usr/bin/env bash
# Start the all-day evolve loop in the background on the best available target.
#   scripts/evolve-daylong.sh [HH:MM]      (default 17:30)
# agntid when scripts/runtime_proof.py passes, else stub (a simulation on the local policy stand-in).
# Rerun it once the proof passes: a running stub loop is stopped and the loop restarts on agntid.
# Log: .cleargate/evolve/daylong.log. Totals: cleargate evolve --totals.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNTIL="${1:-17:30}"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY=python3
STATE="$ROOT/.cleargate/evolve"
LOG="$STATE/daylong.log"
LOCK="$STATE/daylong.pid"
mkdir -p "$STATE"
cd "$ROOT"

TARGET=stub
if [ "${CLEARGATE_DAYLONG_TARGET:-}" = "stub" ]; then
  echo "CLEARGATE_DAYLONG_TARGET=stub: skipping the runtime proof"
elif perl -e 'alarm shift; exec @ARGV' 180 "$PY" scripts/runtime_proof.py > "$STATE/runtime_proof.last.txt" 2>&1; then
  TARGET=agntid
else
  echo "runtime proof did not pass (exit $?); running on stub, labelled simulation"
fi

if [ -f "$LOCK" ]; then
  read -r HELD_PID HELD_TARGET < <("$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["pid"], d["target"])' "$LOCK" 2>/dev/null || echo "0 none")
  if [ "$HELD_PID" != "0" ] && kill -0 "$HELD_PID" 2>/dev/null; then
    if [ "$HELD_TARGET" = "$TARGET" ]; then
      echo "already running on $TARGET: pid $HELD_PID (log $LOG)"
      exit 0
    fi
    echo "stopping the $HELD_TARGET loop (pid $HELD_PID) to restart on $TARGET"
    kill "$HELD_PID"
    for _ in $(seq 1 30); do kill -0 "$HELD_PID" 2>/dev/null || break; sleep 1; done
  fi
fi

nohup "$PY" -m cleargate.cli evolve --target "$TARGET" --until "$UNTIL" >> "$LOG" 2>&1 &
PID=$!
sleep 2
if kill -0 "$PID" 2>/dev/null; then
  echo "evolve loop running on $TARGET until $UNTIL: pid $PID (log $LOG)"
else
  echo "evolve loop exited at once; see $LOG" >&2
  tail -5 "$LOG" >&2
  exit 1
fi
