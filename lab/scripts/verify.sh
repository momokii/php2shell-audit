#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
cd -- "$PROJECT_ROOT"

for dependency in docker uv; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        printf '%s is required to verify the lab.\n' "$dependency" >&2
        exit 1
    fi
done
if ! uv run php2shell-audit --help >/dev/null; then
    printf 'The php2shell-audit CLI entrypoint is unavailable.\n' >&2
    exit 1
fi

compose=(docker compose -f "$PROJECT_ROOT/lab/compose.yaml")
if [[ -f "$PROJECT_ROOT/lab/.env" ]]; then
    compose+=(--env-file "$PROJECT_ROOT/lab/.env")
fi

cleanup() {
    status=$?
    trap - EXIT
    if [[ "${KEEP_LAB:-0}" != "1" ]]; then
        cleanup_status=0
        "$SCRIPT_DIR/down.sh" || cleanup_status=$?
        if [[ "$cleanup_status" != "0" ]]; then
            printf 'FAIL: Lab cleanup exited %s. Run ./lab/scripts/down.sh to retry.\n' "$cleanup_status" >&2
        fi
        if [[ "$status" == "0" ]]; then
            status=$cleanup_status
        fi
    fi
    if [[ "$status" != "0" ]]; then
        printf 'FAIL: Lab verification exited %s.\n' "$status" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$SCRIPT_DIR/up.sh"
vulnerable_address="$("${compose[@]}" port vulnerable 80)"
fixed_address="$("${compose[@]}" port fixed 80)"
static_address="$("${compose[@]}" port static 80)"

vulnerable_url="http://127.0.0.1:${vulnerable_address##*:}"
fixed_url="http://127.0.0.1:${fixed_address##*:}"
static_url="http://127.0.0.1:${static_address##*:}"
mkdir -p reports/qa/lab-vulnerable reports/qa/lab-fixed reports/qa/lab-static
vulnerable_reports="$(mktemp -d reports/qa/lab-vulnerable/run.XXXXXXXXXX)"
fixed_reports="$(mktemp -d reports/qa/lab-fixed/run.XXXXXXXXXX)"
static_reports="$(mktemp -d reports/qa/lab-static/run.XXXXXXXXXX)"
printf 'Reports: %s\nReports: %s\nReports: %s\n' "$vulnerable_reports" "$fixed_reports" "$static_reports"

uv run php2shell-audit scan "$vulnerable_url" --authorized --allow-private --deep --format json --output-dir "$vulnerable_reports"
uv run php2shell-audit scan "$fixed_url" --authorized --allow-private --deep --format json --output-dir "$fixed_reports"
uv run php2shell-audit scan "$static_url" --authorized --allow-private --deep --format json --output-dir "$static_reports"

uv run python - "$vulnerable_reports" "$vulnerable_url" "$fixed_reports" "$fixed_url" "$static_reports" "$static_url" <<'PY'
import json
import sys
from pathlib import Path

for directory, url, version, expected in (
    (Path(sys.argv[1]), sys.argv[2], "8.4.26", "VULNERABLE_VERSION"),
    (Path(sys.argv[3]), sys.argv[4], "8.4.27", "NOT_VULNERABLE_VERSION"),
):
    reports = list(directory.glob("*.json"))
    if len(reports) != 1:
        raise SystemExit(f"FAIL: {directory}: expected exactly one JSON report, got {len(reports)}")
    report = reports[0]
    print(f"Selected report: {report}", flush=True)
    results = json.loads(report.read_text(encoding="utf-8"))["results"]
    if len(results) != 1:
        raise SystemExit(f"FAIL: {report}: expected exactly one target result")
    result = results[0]
    if result["target"]["url"] != url:
        raise SystemExit(f"FAIL: {report}: expected target {url}, got {result['target']['url']}")
    if result["verdict"] != expected:
        raise SystemExit(f"FAIL: {report}: expected {expected}, got {result['verdict']}")
    php = result.get("php")
    if not isinstance(php, dict) or php.get("detected") is not True:
        raise SystemExit(f"FAIL: {report}: expected detected PHP evidence")
    if php.get("version") != version:
        raise SystemExit(f"FAIL: {report}: expected PHP {version}, got {php.get('version')}")
    assessments = result.get("assessments")
    if not isinstance(assessments, list) or any(
        not isinstance(item, dict) for item in assessments
    ):
        raise SystemExit(f"FAIL: {report}: expected CVE assessments")
    for cve_id in ("CVE-2026-109618", "CVE-2026-109619"):
        matches = [item for item in assessments if item.get("cve_id") == cve_id]
        if len(matches) != 1:
            raise SystemExit(f"FAIL: {report}: expected exactly one assessment for {cve_id}")
        if matches[0].get("verdict") != expected:
            raise SystemExit(f"FAIL: {report}: expected {expected} for {cve_id}")
    print(f"PASS: {url}: {expected}: {report}")

static_directory, static_url = Path(sys.argv[5]), sys.argv[6]
static_reports = list(static_directory.glob("*.json"))
if len(static_reports) != 1:
    raise SystemExit(
        f"FAIL: {static_directory}: expected exactly one JSON report, got {len(static_reports)}"
    )
static_report = static_reports[0]
print(f"Selected report: {static_report}", flush=True)
static_results = json.loads(static_report.read_text(encoding="utf-8"))["results"]
if len(static_results) != 1:
    raise SystemExit(f"FAIL: {static_report}: expected exactly one target result")
static_result = static_results[0]
if static_result["target"]["url"] != static_url:
    raise SystemExit(
        f"FAIL: {static_report}: expected target {static_url}, "
        f"got {static_result['target']['url']}"
    )
if static_result["verdict"] != "NOT_PHP":
    raise SystemExit(
        f"FAIL: {static_report}: expected NOT_PHP, got {static_result['verdict']}"
    )
static_php = static_result.get("php")
if not isinstance(static_php, dict) or static_php.get("detected") is not False:
    raise SystemExit(f"FAIL: {static_report}: expected undetected PHP evidence")
if static_php.get("version") is not None:
    raise SystemExit(f"FAIL: {static_report}: expected no PHP version")
if static_result.get("assessments") != []:
    raise SystemExit(f"FAIL: {static_report}: expected no CVE assessments")
print(f"PASS: {static_url}: NOT_PHP: {static_report}")
PY
