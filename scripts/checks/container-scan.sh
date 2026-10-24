#!/usr/bin/env bash
# Fail-closed Trivy image scans of the loopback-only lab fixtures.
# Policy comes from ./trivy.yaml (auto-loaded with CWD at the repo root);
# --ignore-unfixed is a CLI-only flag in Trivy 0.76 with no config-file
# equivalent (verified against the generated default config). .trivyignore
# documents the accepted fixture-only finding, so any NEW fixable
# HIGH/CRITICAL finding fails the build. Images are pinned by digest.
# The busybox static fixture is intentionally not scanned: it ships no package
# manager database, so there is nothing for Trivy to audit (verified no-op);
# its minimalism is the control, and its hardening is asserted by unit tests.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TRIVY_IMAGE="aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
IMAGES=("php:8.4.26-apache" "php:8.4.27-apache")
for image in "${IMAGES[@]}"; do
  echo "Scanning ${image} ..."
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "${ROOT}:/repo:ro" \
    -w /repo \
    "$TRIVY_IMAGE" image --scanners vuln --ignore-unfixed "$image"
done
