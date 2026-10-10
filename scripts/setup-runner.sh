#!/usr/bin/env bash
# Register this Mac as the self-hosted GitHub Actions runner for the ClearGate gate.
#
# Why self-hosted: the gate must invoke the AgntID runtime (Docker, :8080/:8082) and the
# ClearGate MCP servers (:9101/:9102), which are customer-hosted on this machine. Nothing
# runs in GitHub's cloud except the check result.
#
# Usage:
#   1. GitHub -> ashutosh887/cleargate -> Settings -> Actions -> Runners -> New self-hosted runner
#      (macOS, ARM64). Copy the registration token shown there (valid ~1 hour).
#   2. RUNNER_TOKEN=<token> scripts/setup-runner.sh
#   3. Keep it running (./run.sh), or install as a service: ./svc.sh install && ./svc.sh start
#
# Before a PR runs, have the stack up on this machine:
#   docker compose -f scratch/agntid-runtime/docker-compose.yml up -d   # AgntID runtime
#   .venv/bin/python -m cleargate.cli mcp-serve                          # payments + comms MCP
#   curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8082/mcp    # expect 406/200, not 000
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/ashutosh887/cleargate}"
RUNNER_DIR="${RUNNER_DIR:-$HOME/actions-runner-cleargate}"
RUNNER_VERSION="${RUNNER_VERSION:-2.319.1}"   # check https://github.com/actions/runner/releases for the latest
LABELS="${LABELS:-cleargate}"
: "${RUNNER_TOKEN:?set RUNNER_TOKEN from Settings -> Actions -> Runners -> New self-hosted runner}"

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

TARBALL="actions-runner-osx-arm64-${RUNNER_VERSION}.tar.gz"
if [ ! -x ./config.sh ]; then
  curl -fsSL -o "$TARBALL" \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${TARBALL}"
  tar xzf "$TARBALL"
fi

./config.sh --url "$REPO_URL" --token "$RUNNER_TOKEN" \
  --name "$(hostname -s)-cleargate" --labels "$LABELS" --work _work --unattended --replace

echo "Registered. Start it with: cd $RUNNER_DIR && ./run.sh"
