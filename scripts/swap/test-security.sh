#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$HOME/.zshenv" 2>/dev/null || true
cd "$PROJECT_DIR"

forge test \
    --match-contract ConfidentialTokenSwapTest \
    --match-test testRejectsInsufficientCommitteeSignatures \
    -vvvv

