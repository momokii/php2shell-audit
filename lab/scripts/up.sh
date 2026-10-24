#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
cd -- "$PROJECT_ROOT"

if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker with Compose is required to start the lab.\n' >&2
    exit 1
fi

compose=(docker compose -f "$PROJECT_ROOT/lab/compose.yaml")
if [[ -f "$PROJECT_ROOT/lab/.env" ]]; then
    compose+=(--env-file "$PROJECT_ROOT/lab/.env")
fi

"${compose[@]}" up -d --wait --wait-timeout 60
vulnerable_address="$("${compose[@]}" port vulnerable 80)"
fixed_address="$("${compose[@]}" port fixed 80)"
static_address="$("${compose[@]}" port static 80)"
printf 'Vulnerable: http://127.0.0.1:%s\n' "${vulnerable_address##*:}"
printf 'Fixed: http://127.0.0.1:%s\n' "${fixed_address##*:}"
printf 'Static: http://127.0.0.1:%s\n' "${static_address##*:}"
