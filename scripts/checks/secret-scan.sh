#!/usr/bin/env bash
# Fail-closed secret scan using the repo-pinned pre-commit + Gitleaks hook.
# First run installs hook environments; the Gitleaks hook needs a Go toolchain.
# CI runs the same Gitleaks version via the pinned gitleaks-action instead.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PRE_COMMIT_VERSION="4.7.0"
uvx "pre-commit@${PRE_COMMIT_VERSION}" run gitleaks --all-files
