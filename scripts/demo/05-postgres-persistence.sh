#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_DIR"

echo "============================================================"
echo "Demo 5: PostgreSQL persistence"
echo "Flow: migrate -> deposit -> restart Runtime -> query -> withdraw -> replay check"
echo "============================================================"

if [[ -n "${TEST_DATABASE_URL:-}" ]]; then
  echo "Using externally supplied TEST_DATABASE_URL"
  exec ./scripts/test-postgres-runtime.sh
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is unavailable. Either install Docker or run:"
  echo "  TEST_DATABASE_URL='postgres://user:password@127.0.0.1/db' $0"
  exit 2
fi

docker compose version >/dev/null
docker compose -f docker-compose.postgres.yml up -d postgres

echo "Waiting for PostgreSQL to become healthy"
for _ in {1..40}; do
  if docker compose -f docker-compose.postgres.yml exec -T postgres \
    pg_isready -U ppsc -d ppsc >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! docker compose -f docker-compose.postgres.yml exec -T postgres \
  pg_isready -U ppsc -d ppsc >/dev/null 2>&1; then
  echo "PostgreSQL did not become ready" >&2
  docker compose -f docker-compose.postgres.yml logs postgres >&2
  exit 1
fi

export TEST_DATABASE_URL="postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/ppsc"
./scripts/test-postgres-runtime.sh

echo
echo "PostgreSQL remains running so the persisted rows can be inspected."
echo "Inspect: docker compose -f docker-compose.postgres.yml exec postgres \
psql -U ppsc -d ppsc -c 'SELECT sequence, operation_kind, version FROM ppsc_state_transitions ORDER BY sequence DESC LIMIT 10;'"
echo "Stop:    docker compose -f docker-compose.postgres.yml down"
echo "Demo 5 passed"
