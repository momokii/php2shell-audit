#!/usr/bin/env bash
# Local gate: every check CI enforces, in dependency order. Fails fast.
# Prerequisite: uv sync (handled here with --frozen), Docker for container-scan,
# Go toolchain on first secret-scan run, network for audit/analysis databases.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
uv sync --frozen
uv run --frozen pytest
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy src
uv build
"${ROOT}/scripts/checks/secret-scan.sh"
"${ROOT}/scripts/checks/dependency-audit.sh"
"${ROOT}/scripts/checks/static-analysis.sh"
"${ROOT}/scripts/checks/container-scan.sh"
echo "All guardrails passed."
