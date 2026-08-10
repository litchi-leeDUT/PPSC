#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ANVIL_PORT="${ANVIL_PORT:-8545}"
RPC_URL="http://127.0.0.1:${ANVIL_PORT}"
ANVIL_TEST_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_LOG="$(mktemp -t ppsc-swap-anvil.XXXXXX.log)"
ANVIL_PID=""

cleanup() {
    if [[ -n "$ANVIL_PID" ]] && kill -0 "$ANVIL_PID" 2>/dev/null; then
        kill "$ANVIL_PID" 2>/dev/null || true
        wait "$ANVIL_PID" 2>/dev/null || true
    fi
    rm -f "$ANVIL_LOG"
}
trap cleanup EXIT INT TERM

source "$HOME/.zshenv" 2>/dev/null || true
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}"
export no_proxy="$NO_PROXY"
cd "$PROJECT_DIR"

for required_command in forge cast anvil; do
    command -v "$required_command" >/dev/null 2>&1 || {
        echo "Missing command: $required_command" >&2
        exit 1
    }
done

echo "Starting Anvil at $RPC_URL"
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!

for _ in {1..50}; do
    cast block-number --rpc-url "$RPC_URL" >/dev/null 2>&1 && break
    sleep 0.1
done
cast chain-id --rpc-url "$RPC_URL" >/dev/null

echo "Broadcasting public-to-private and private-to-public swaps"
DEPLOYER_PRIVATE_KEY="$ANVIL_TEST_KEY" forge script \
    contracts/script/DemoLocalTokenSwap.s.sol:DemoLocalTokenSwap \
    --rpc-url "$RPC_URL" \
    --broadcast \
    -vvv

echo "Local token swap demo passed. The temporary Anvil chain will be stopped."

