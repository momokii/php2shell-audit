#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
cd -- "$PROJECT_ROOT"

if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker with Compose is required to stop the lab.\n' >&2
    exit 1
fi

compose=(docker compose -f "$PROJECT_ROOT/lab/compose.yaml")
if [[ -f "$PROJECT_ROOT/lab/.env" ]]; then
    compose+=(--env-file "$PROJECT_ROOT/lab/.env")
fi

"${compose[@]}" down -v --remove-orphans
