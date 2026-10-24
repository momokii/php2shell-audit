#!/usr/bin/env bash
# Fail-closed dependency audit of the locked dependency set.
# The audit reads an exported requirements snapshot of uv.lock, so only project
# dependencies are in scope (never the scanner tool's own closure). The only
# expected skip is php2shell-audit itself, which is not on PyPI.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PIP_AUDIT_VERSION="2.10.1"
REQUIREMENTS="$(mktemp)"
trap 'rm -f "$REQUIREMENTS"' EXIT
uv export --frozen --format requirements-txt --no-hashes --output-file "$REQUIREMENTS"
uvx "pip-audit==${PIP_AUDIT_VERSION}" --requirement "$REQUIREMENTS" --desc
