#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_DIR"

echo "============================================================"
echo "Demo 2: SS/FHE storage, sortition, handoff and computation"
echo "Flow: SS(40) + FHE(60) -> select committee -> handoff -> FHE(100)"
echo "============================================================"

cargo test --quiet -p ppsc-runtime \
  workflow::tests::ss_and_fhe_publish_sortition_handoff_compute_and_location_update \
  -- --exact --nocapture

echo
echo "Checking the on-chain storage-location handoff rule"
if command -v forge >/dev/null 2>&1; then
  forge test --quiet \
    --match-contract PpscControlPlaneTest \
    --match-test testDataLocationsMoveToSelectedCommittee
else
  echo "SKIP: forge is not installed; Rust workflow completed successfully"
fi
echo "Demo 2 passed"
