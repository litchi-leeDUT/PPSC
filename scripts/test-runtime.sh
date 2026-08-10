#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$HOME/.cargo/env" 2>/dev/null || true
cd "$PROJECT_DIR"

echo "[1/4] Checking Runtime formatting"
cargo fmt --all --check

echo "[2/4] Compiling Runtime"
cargo check -p ppsc-runtime

echo "[3/4] Running Runtime tests"
cargo test -p ppsc-runtime

echo "[4/4] Running plaintext development flow"
cargo run -p ppsc-runtime

