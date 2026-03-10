#!/usr/bin/env bash
#
# Start a full test transaction environment:
# - Spark regtest
# - Self-signed eIDAS (demo mode)
# - Inline IVMS101 over UMA
# - Dashboard on a free localhost port (default 3080, or next available)
#
# Usage:
#   ./scripts/testing/start_test_transaction.sh
#
# Dashboard: http://localhost:<DASHBOARD_PORT>/index.html (or /)
# Sender:    http://localhost:<SENDER_PORT>
# Receiver:  http://localhost:<RECEIVER_PORT>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SENDER_PORT="${SENDER_PORT:-3001}"
RECEIVER_PORT="${RECEIVER_PORT:-3002}"
TRAVEL_RULE_STATE_DIR="${TRAVEL_RULE_STATE_DIR:-$REPO_ROOT/.demo-state}"
SENDER_TARGET_BALANCE_SATS="${SENDER_TARGET_BALANCE_SATS:-50000}"
SPARK_FUNDING_MINE_BLOCKS="${SPARK_FUNDING_MINE_BLOCKS:-6}"

find_free_port() {
  local start="${1:-3080}"
  local port="$start"
  while lsof -i ":$port" -sTCP:LISTEN -t >/dev/null 2>&1; do
    port=$((port + 1))
  done
  echo "$port"
}
DASHBOARD_PORT="${DASHBOARD_PORT:-$(find_free_port 3080)}"

export APP_ENV=development
export SPARK_NETWORK=REGTEST
export TRAVEL_RULE_THRESHOLD_EUR="${TRAVEL_RULE_THRESHOLD_EUR:-0}"
export EIDAS_ENABLED=true
export EIDAS_ISSUER_URL="https://issuer.demo.eudi.eu"
export RECEIVER_PORT="$RECEIVER_PORT"
export SENDER_PORT="$SENDER_PORT"
export RECEIVER_DOMAIN="localhost:$RECEIVER_PORT"
export SENDER_DOMAIN="localhost:$SENDER_PORT"
export RECEIVER_VASP_NAME="opago Receiver VASP (DE)"
export SENDER_VASP_NAME="opago Sender VASP (DE)"
export RECEIVER_EIDAS_ENABLED=true
export RECEIVER_MICA_LICENSE="EU-MICA-2024-DEMO-RECV-001"
export VASP_DOMAIN="localhost"
export VASP_JURISDICTION=DE
export TRAVEL_RULE_STATE_DIR
export SENDER_TARGET_BALANCE_SATS
export SPARK_FUNDING_MINE_BLOCKS

mkdir -p "$TRAVEL_RULE_STATE_DIR"

echo "Preparing Spark regtest wallets..."
eval "$(
  cd "$REPO_ROOT" &&
  uv run python scripts/testing/prepare_test_wallets.py \
    --format shell \
    --state-dir "$TRAVEL_RULE_STATE_DIR"
)"
export SENDER_SPARK_MNEMONIC
export RECEIVER_SPARK_MNEMONIC
export SENDER_SPARK_ADDRESS
export RECEIVER_SPARK_ADDRESS
export SENDER_SPARK_DEPOSIT_ADDRESS
export RECEIVER_SPARK_DEPOSIT_ADDRESS

if [[ -z "${UMA_SIGNING_KEY:-}" ]]; then
  echo "Generating UMA signing key..."
  UMA_SIGNING_KEY="$(cd "$REPO_ROOT" && uv run python -c "
from opago_mica.utils.crypto import generate_key_pair
print(generate_key_pair(use='sig').private_key_pem)
")"
  export UMA_SIGNING_KEY
fi
if [[ -z "${UMA_ENCRYPTION_KEY:-}" ]]; then
  echo "Generating UMA encryption key..."
  UMA_ENCRYPTION_KEY="$(cd "$REPO_ROOT" && uv run python -c "
from opago_mica.utils.crypto import generate_key_pair
print(generate_key_pair(use='enc').private_key_pem)
")"
  export UMA_ENCRYPTION_KEY
fi

CONFIG_JSON="$REPO_ROOT/frontend/config.json"
echo "{\"senderPort\":$SENDER_PORT,\"receiverPort\":$RECEIVER_PORT,\"dashboardPort\":$DASHBOARD_PORT}" > "$CONFIG_JSON"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " opago MiCA Test Transaction — Spark Regtest + eIDAS + UMA    "
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Dashboard:  http://localhost:$DASHBOARD_PORT/index.html"
echo "  Sender:     http://localhost:$SENDER_PORT"
echo "  Receiver:   http://localhost:$RECEIVER_PORT"
echo "  Sender Spark Address:   $SENDER_SPARK_ADDRESS"
echo "  Sender Deposit Address: $SENDER_SPARK_DEPOSIT_ADDRESS"
echo "  Receiver Spark Address: $RECEIVER_SPARK_ADDRESS"
echo "  Receiver Deposit Addr:  $RECEIVER_SPARK_DEPOSIT_ADDRESS"
echo "  Faucet: https://app.lightspark.com/regtest-faucet"
echo ""
echo "  SPARK_NETWORK=$SPARK_NETWORK  EIDAS_ENABLED=$EIDAS_ENABLED"
echo "  Demo state directory: $TRAVEL_RULE_STATE_DIR"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

cd "$REPO_ROOT"

uv run python -m opago_mica receiver &
RECEIVER_PID=$!

sleep 2
uv run python -m opago_mica sender &
SENDER_PID=$!

sleep 2
python3 -m http.server "$DASHBOARD_PORT" --directory "$REPO_ROOT/frontend" &
DASHBOARD_PID=$!

cleanup() {
  kill $RECEIVER_PID $SENDER_PID $DASHBOARD_PID 2>/dev/null || true
}
trap cleanup EXIT

echo "All services started. Press Ctrl+C to stop."
wait
