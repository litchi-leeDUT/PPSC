#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANVIL_PORT="${ANVIL_PORT:-8545}"
RPC_URL="http://127.0.0.1:${ANVIL_PORT}"
ANVIL_TEST_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_LOG="$(mktemp -t ppsc-anvil.XXXXXX.log)"
ANVIL_PID=""

# Deterministic addresses on a fresh Anvil chain using its first account.
VERIFIER_ADDRESS="0x5FbDB2315678afecb367f032d93F642f64180aa3"
CONTROL_ADDRESS="0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
APP_ADDRESS="0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"

cleanup() {
    if [[ -n "$ANVIL_PID" ]] && kill -0 "$ANVIL_PID" 2>/dev/null; then
        kill "$ANVIL_PID" 2>/dev/null || true
        wait "$ANVIL_PID" 2>/dev/null || true
    fi
    rm -f "$ANVIL_LOG"
}
trap cleanup EXIT INT TERM

if [[ -f "$HOME/.zshenv" ]]; then
    # foundryup adds Foundry's bin directory here on macOS/zsh.
    # shellcheck disable=SC1090
    source "$HOME/.zshenv"
fi

for required_command in forge cast anvil; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        echo "Missing command: $required_command" >&2
        echo "Install Foundry first: https://getfoundry.sh/getting-started/installation" >&2
        exit 1
    fi
done

export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}"
export no_proxy="$NO_PROXY"

cd "$PROJECT_DIR"

echo "[1/5] Formatting and compiling contracts"
forge fmt --check
forge build

echo "[2/5] Running all Solidity tests"
forge test -vvv

echo "[3/5] Starting a temporary Anvil chain at $RPC_URL"
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!

for _ in {1..50}; do
    if cast block-number --rpc-url "$RPC_URL" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

if ! cast block-number --rpc-url "$RPC_URL" >/dev/null 2>&1; then
    echo "Anvil failed to start. Log:" >&2
    sed -n '1,120p' "$ANVIL_LOG" >&2
    exit 1
fi

echo "[4/5] Broadcasting the user privacy-contract demo"
DEPLOYER_PRIVATE_KEY="$ANVIL_TEST_KEY" forge script \
    contracts/script/DemoLocalPrivacyApp.s.sol:DemoLocalPrivacyApp \
    --rpc-url "$RPC_URL" \
    --broadcast \
    -vvv

echo "[5/5] Reading deployed state"
CONTRACT_ID="$(
    cast call "$APP_ADDRESS" 'confidentialContractId()(bytes32)' --rpc-url "$RPC_URL"
)"

APP_OWNER="$(cast call "$APP_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
STATE_ROOT="$(cast call "$APP_ADDRESS" 'privateStateRoot()(bytes32)' --rpc-url "$RPC_URL")"
FUNCTION_PUBLISHED="$(
    cast call "$APP_ADDRESS" 'privateTransferPublished()(bool)' --rpc-url "$RPC_URL"
)"

if [[ "$FUNCTION_PUBLISHED" != "true" ]]; then
    echo "privateTransfer was not published" >&2
    exit 1
fi

if [[ "$(cast code "$CONTROL_ADDRESS" --rpc-url "$RPC_URL")" == "0x" ]]; then
    echo "PpscControlPlane has no deployed bytecode" >&2
    exit 1
fi

if [[ "$(cast code "$VERIFIER_ADDRESS" --rpc-url "$RPC_URL")" == "0x" ]]; then
    echo "EcdsaSortitionVerifier has no deployed bytecode" >&2
    exit 1
fi

echo
echo "Local privacy-contract test passed"
echo "  verifier:       $VERIFIER_ADDRESS"
echo "  control plane:  $CONTROL_ADDRESS"
echo "  user app:       $APP_ADDRESS"
echo "  app owner:      $APP_OWNER"
echo "  contract id:    $CONTRACT_ID"
echo "  private root:   $STATE_ROOT"
echo "  function ready: $FUNCTION_PUBLISHED"
echo
echo "The temporary Anvil chain will now be stopped."

