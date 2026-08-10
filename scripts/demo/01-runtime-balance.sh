#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_DIR"

echo "============================================================"
echo "Demo 1: confidential balance Runtime"
echo "Flow: deposit 100 -> encrypted balance -> withdraw 40 -> 60"
echo "Backend: development plaintext implementation of MPC/FHE ports"
echo "============================================================"

cargo run --quiet -p ppsc-runtime --bin ppsc-runtime

echo
echo "Running replay, stale-state-root and authorization checks"
cargo test --quiet -p ppsc-runtime tests:: -- --nocapture
echo "Demo 1 passed"
