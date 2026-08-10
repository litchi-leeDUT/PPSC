#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TEST_DATABASE_URL:-}" ]]; then
  echo "TEST_DATABASE_URL is required" >&2
  echo "example: postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/ppsc" >&2
  exit 2
fi

DATABASE_URL="$TEST_DATABASE_URL" cargo run -p ppsc-runtime --bin postgres_migrate
cargo test -p ppsc-runtime --test postgres_persistence -- --nocapture
