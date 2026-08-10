#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_DIR"

echo "============================================================"
echo "Demo 3: deploy a user privacy contract on temporary Anvil"
echo "Flow: deploy verifier/control plane/app -> publish private function"
echo "============================================================"

exec ./scripts/test-local.sh
