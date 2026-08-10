#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_DIR"

echo "============================================================"
echo "Demo 4: public/private token swap on temporary Anvil"
echo "Flow: public token -> mint request -> private token -> withdrawal"
echo "============================================================"

exec ./scripts/swap/demo-local.sh
