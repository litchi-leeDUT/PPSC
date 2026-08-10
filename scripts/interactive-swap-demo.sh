#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
ANVIL_PORT="${ANVIL_PORT:-8545}"
USER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
MEMBER_KEYS=(0xB0B 0xCAFE 0xD00D)
ANVIL_LOG="$(mktemp -t ppsc-interactive.XXXXXX.log)"
ANVIL_PID=""
NONCE=1
STATE_VERSION=0

# Deterministic deployment addresses on a fresh Anvil chain.
CONTROL="0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
# finalizeCommittee is a separate nonce-2 transaction before these deployments.
TOKEN="0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
SWAP="0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"

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

for command_name in anvil cast forge; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "缺少命令: $command_name" >&2
    exit 1
  }
done

USER="$(cast wallet address --private-key "$USER_KEY")"

format_token() {
  cast from-wei "$1" ether
}

query_uint() {
  cast call "$1" "$2" "${@:3}" --rpc-url "$RPC_URL" | awk '{print $1}'
}

show_balances() {
  local user_balance reserve liability fees state_root solvent
  user_balance="$(query_uint "$TOKEN" 'balanceOf(address)(uint256)' "$USER")"
  reserve="$(query_uint "$TOKEN" 'balanceOf(address)(uint256)' "$SWAP")"
  liability="$(query_uint "$SWAP" 'privateLiabilities(address)(uint256)' "$TOKEN")"
  fees="$(query_uint "$SWAP" 'accruedFees(address)(uint256)' "$TOKEN")"
  state_root="$(cast call "$SWAP" 'privateStateRoots(address)(bytes32)' "$TOKEN" --rpc-url "$RPC_URL")"
  solvent="$(cast call "$SWAP" 'reserveIsSolvent(address)(bool)' "$TOKEN" --rpc-url "$RPC_URL")"

  echo
  echo "-------------------- 当前链上状态 --------------------"
  printf "用户明文 mUSD:             %s\n" "$(format_token "$user_balance")"
  printf "Swap 托管 mUSD:            %s\n" "$(format_token "$reserve")"
  printf "密态余额（单用户演示值）:  %s\n" "$(format_token "$liability")"
  printf "累计手续费:                 %s\n" "$(format_token "$fees")"
  printf "密态状态根:                 %s\n" "$state_root"
  printf "储备金充足:                 %s\n" "$solvent"
  echo "------------------------------------------------------"
}

sorted_signatures() {
  local digest="$1"
  local rows=()
  local key normalized_key address normalized_address signature
  for key in "${MEMBER_KEYS[@]}"; do
    normalized_key="$(printf '0x%064x' "$key")"
    address="$(cast wallet address --private-key "$normalized_key")"
    normalized_address="$(printf '%s' "$address" | tr 'A-F' 'a-f')"
    signature="$(cast wallet sign --no-hash --private-key "$normalized_key" "$digest")"
    rows+=("$normalized_address|$signature")
  done
  printf '%s\n' "${rows[@]}" | sort | head -n 2 | cut -d'|' -f2
}

deposit_flow() {
  local amount_tokens amount commitment encoded deposit_id old_root new_root data_id transcript
  local digest signature_output sig1 sig2 transaction
  read -r -p "输入存款数量 mUSD（默认 100）: " amount_tokens
  amount_tokens="${amount_tokens:-100}"
  amount="$(cast to-wei "$amount_tokens" ether)"
  commitment="$(cast keccak "interactive-private-account:$USER")"

  echo "授权 Swap 使用 $amount_tokens mUSD..."
  cast send "$TOKEN" 'approve(address,uint256)' "$SWAP" "$amount" \
    --private-key "$USER_KEY" --rpc-url "$RPC_URL" --quiet

  encoded="$(cast abi-encode \
    'f(string,uint256,address,address,address,uint256,bytes32,uint64)' \
    'PPSC_PUBLIC_TO_PRIVATE_V1' 31337 "$SWAP" "$TOKEN" "$USER" \
    "$amount" "$commitment" "$NONCE")"
  deposit_id="$(cast keccak "$encoded")"

  echo "发送 deposit 交易，明文代币进入 Swap 托管..."
  transaction="$(cast send "$SWAP" 'deposit(address,uint256,bytes32,uint64)' \
    "$TOKEN" "$amount" "$commitment" "$NONCE" \
    --private-key "$USER_KEY" --rpc-url "$RPC_URL" --json | \
    sed -n 's/.*"transactionHash":"\([^"]*\)".*/\1/p')"
  echo "depositId: $deposit_id"
  echo "交易哈希:  $transaction"
  show_balances

  echo
  read -r -p "按回车模拟 committee 计算并确认密态铸造..." _
  old_root="$(cast call "$SWAP" 'privateStateRoots(address)(bytes32)' "$TOKEN" --rpc-url "$RPC_URL")"
  STATE_VERSION=$((STATE_VERSION + 1))
  new_root="$(cast keccak "interactive-state:$STATE_VERSION:$deposit_id")"
  data_id="$(cast keccak "interactive-ciphertext:$STATE_VERSION:$deposit_id")"
  transcript="$(cast keccak "interactive-deposit-transcript:$deposit_id")"
  digest="$(cast call "$SWAP" \
    'depositDigest(bytes32,(bytes32,bytes32,bytes32,bytes32))(bytes32)' \
    "$deposit_id" "($old_root,$new_root,$data_id,$transcript)" --rpc-url "$RPC_URL")"
  signature_output="$(sorted_signatures "$digest")"
  sig1="$(printf '%s\n' "$signature_output" | sed -n '1p')"
  sig2="$(printf '%s\n' "$signature_output" | sed -n '2p')"
  cast send "$SWAP" \
    'finalizeDeposit(bytes32,(bytes32,bytes32,bytes32,bytes32),bytes[])' \
    "$deposit_id" "($old_root,$new_root,$data_id,$transcript)" "[$sig1,$sig2]" \
    --private-key "$USER_KEY" --rpc-url "$RPC_URL" --quiet
  NONCE=$((NONCE + 1))
  echo "committee 阈值签名验证通过，密态余额已更新。"
  show_balances
}

withdraw_flow() {
  local amount_tokens amount liability old_root new_root nullifier transcript digest
  local signature_output sig1 sig2
  read -r -p "输入从密态余额提现的数量 mUSD（默认 40）: " amount_tokens
  amount_tokens="${amount_tokens:-40}"
  amount="$(cast to-wei "$amount_tokens" ether)"
  liability="$(query_uint "$SWAP" 'privateLiabilities(address)(uint256)' "$TOKEN")"
  if (( amount > liability )); then
    echo "密态余额不足：当前为 $(format_token "$liability") mUSD"
    return
  fi
  old_root="$(cast call "$SWAP" 'privateStateRoots(address)(bytes32)' "$TOKEN" --rpc-url "$RPC_URL")"
  STATE_VERSION=$((STATE_VERSION + 1))
  nullifier="$(cast keccak "interactive-nullifier:$STATE_VERSION:$USER")"
  new_root="$(cast keccak "interactive-state:$STATE_VERSION:$nullifier")"
  transcript="$(cast keccak "interactive-withdraw-transcript:$nullifier")"
  digest="$(cast call "$SWAP" \
    'withdrawalDigest((address,address,uint256,bytes32,bytes32,bytes32,bytes32,uint64))(bytes32)' \
    "($TOKEN,$USER,$amount,$nullifier,$old_root,$new_root,$transcript,4102444800)" \
    --rpc-url "$RPC_URL")"
  signature_output="$(sorted_signatures "$digest")"
  sig1="$(printf '%s\n' "$signature_output" | sed -n '1p')"
  sig2="$(printf '%s\n' "$signature_output" | sed -n '2p')"

  echo "提交 committee 已签名的 withdrawal；合约收取 1% 手续费..."
  cast send "$SWAP" \
    'withdraw((address,address,uint256,bytes32,bytes32,bytes32,bytes32,uint64),bytes[])' \
    "($TOKEN,$USER,$amount,$nullifier,$old_root,$new_root,$transcript,4102444800)" \
    "[$sig1,$sig2]" --private-key "$USER_KEY" --rpc-url "$RPC_URL" --quiet
  echo "提现完成，nullifier: $nullifier"
  show_balances
}

echo "启动临时 Anvil 链: $RPC_URL"
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
for _ in {1..50}; do
  cast block-number --rpc-url "$RPC_URL" >/dev/null 2>&1 && break
  sleep 0.1
done
cast chain-id --rpc-url "$RPC_URL" >/dev/null

echo "部署 ControlPlane、Mock mUSD 和 ConfidentialTokenSwap..."
DEPLOYER_PRIVATE_KEY="$USER_KEY" forge script \
  contracts/script/DeployInteractiveSwap.s.sol:DeployInteractiveSwap \
  --rpc-url "$RPC_URL" --broadcast --quiet

for address in "$CONTROL" "$TOKEN" "$SWAP"; do
  [[ "$(cast code "$address" --rpc-url "$RPC_URL")" != "0x" ]] || {
    echo "部署地址没有代码: $address" >&2
    exit 1
  }
done

echo
echo "部署完成"
echo "用户:         $USER"
echo "ControlPlane: $CONTROL"
echo "mUSD:         $TOKEN"
echo "Swap:         $SWAP"
echo "说明: 当前为单用户开发演示，MPC/FHE 计算由 committee 签名步骤模拟。"
show_balances

while true; do
  echo
  echo "请选择操作："
  echo "  1) 查询余额"
  echo "  2) 明文 mUSD -> 密态余额（存款 + committee 确认）"
  echo "  3) 密态余额 -> 明文 mUSD（提现）"
  echo "  4) 退出"
  read -r -p "> " choice
  case "$choice" in
    1) show_balances ;;
    2) deposit_flow ;;
    3) withdraw_flow ;;
    4) echo "演示结束，临时 Anvil 链将关闭。"; break ;;
    *) echo "请输入 1、2、3 或 4" ;;
  esac
done
