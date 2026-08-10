#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$HOME/.cargo/env" 2>/dev/null || true
source "$HOME/.zshenv" 2>/dev/null || true
cd "$PROJECT_DIR"

echo "[1/3] Running Rust SS/FHE storage and handoff workflow"
cargo test -p ppsc-runtime \
    workflow::tests::ss_and_fhe_publish_sortition_handoff_compute_and_location_update \
    -- --exact --nocapture

echo "[2/3] Running Solidity storage-location handoff test"
forge test \
    --match-contract PpscControlPlaneTest \
    --match-test testDataLocationsMoveToSelectedCommittee \
    -vvv

echo "[3/3] Checking production contract sizes"
forge build --sizes --skip script --skip test

