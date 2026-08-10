#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

DEMOS=(
  scripts/demo/01-runtime-balance.sh
  scripts/demo/02-storage-handoff.sh
  scripts/demo/03-local-chain-contract.sh
  scripts/demo/04-token-swap.sh
)

for demo in "${DEMOS[@]}"; do
  echo
  "$demo"
done

echo
if [[ "${WITH_POSTGRES:-0}" == "1" ]]; then
  scripts/demo/05-postgres-persistence.sh
else
  echo "PostgreSQL demo skipped by default. Run it with:"
  echo "  WITH_POSTGRES=1 ./scripts/demo-all.sh"
fi

echo
echo "All selected PPSC demos passed"
