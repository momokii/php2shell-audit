#!/usr/bin/env bash
# Fail-closed Semgrep scan. --config auto needs registry access.
# Excluded rules (each with justification, tracked under TASK-002):
# - python.django.security.injection.raw-html-format.raw-html-format: no Django
#   in this repo (no dependency, no templates; Markdown output escapes via
#   html.escape). The only hit is a version-range string ("<8.4.27") in test
#   fixture data. The full check ID is required for --exclude-rule to match.
# Path exclusions live in .semgrepignore; findings fail the command via --error.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
SEMGREP_VERSION="1.182.1"
uvx "semgrep==${SEMGREP_VERSION}" scan --config auto --error \
  --exclude-rule python.django.security.injection.raw-html-format.raw-html-format
