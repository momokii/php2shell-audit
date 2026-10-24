"""Local report exports with detection-only guidance and redacted evidence."""

import csv
import json
import re
from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Final

from php2shell_audit.logging import redact_value
from php2shell_audit.models import Evidence, ScanReport, Target, Verdict
from php2shell_audit.safety import redact_header, redact_url

_CSV_FIELDS: Final = (
    "target verdict php_detected php_version sapi waf assessments findings requests_made error"
).split()


def report_stem(report: ScanReport) -> str:
    """Use the ISO start time in UTC, assuming UTC for naive dates; fall back to now."""
    try:
        timestamp = datetime.fromisoformat(report.started_at or "")
    except ValueError:
        timestamp = datetime.now(UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def _validated_stem(report: ScanReport, stem: str | None) -> str:
    name = report_stem(report)
    if stem is not None:
        if "/" in stem or "\\" in stem or ".." in stem:
            raise ValueError("Unsafe report stem: separators and '..' are forbidden")
        name = re.sub(r"[^a-zA-Z0-9_.-]", "_", stem) or name
    return name


def _free_stem(directory: Path, stem: str, suffixes: tuple[str, ...]) -> str:
    candidate = stem
    number = 0
    while any((directory / f"{candidate}.{suffix}").exists() for suffix in suffixes):
        number += 1
        candidate = f"{stem}-{number}"
    return candidate


def _path(report: ScanReport, output_dir: str | Path, stem: str | None, suffix: str) -> Path:
    name = _validated_stem(report, stem)
    directory = Path(output_dir)
    if not directory.is_dir():
        directory.mkdir(parents=True, exist_ok=True)
    name = _free_stem(directory, name, (suffix,))
    return directory / f"{name}.{suffix}"


def _safe_evidence(observations: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
    safe = []
    for item in observations:
        label = item.source.removeprefix("header:")
        value = (
            redact_header(label, item.value)
            if label.lower() == "set-cookie"
            else str(redact_value(item.value, label))
        )
        if item.source.lower().startswith("cookie:"):
            value = "<redacted>"
        safe.append(replace(item, value=value))
    return tuple(safe)


def _safe_report(report: ScanReport) -> ScanReport:
    return replace(
        report,
        results=tuple(
            replace(
                result,
                target=Target(redact_url(result.target.url)),
                php=replace(result.php, evidence=_safe_evidence(result.php.evidence)),
                evidence=_safe_evidence(result.evidence),
                findings=tuple(
                    replace(finding, evidence=_safe_evidence(finding.evidence))
                    for finding in result.findings
                ),
            )
            for result in report.results
        ),
    )


def write_json(report: ScanReport, output_dir: str | Path, *, stem: str | None = None) -> Path:
    """Create the directory and write an indented, UTF-8 JSON report."""
    path = _path(report, output_dir, stem, "json")
    with path.open("x", encoding="utf-8") as stream:
        stream.write(
            json.dumps(_safe_report(report).to_dict(), indent=2, ensure_ascii=False) + "\n"
        )
    return path


def write_jsonl(report: ScanReport, output_dir: str | Path, *, stem: str | None = None) -> Path:
    """Write one metadata record followed by one JSON record per target."""
    path = _path(report, output_dir, stem, "jsonl")
    safe = _safe_report(report)
    metadata = {
        "type": "report",
        "schema_version": safe.schema_version,
        "started_at": safe.started_at,
        "finished_at": safe.finished_at,
    }
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(metadata, ensure_ascii=False) + "\n")
        for result in safe.results:
            stream.write(
                json.dumps({"type": "result", **result.to_dict()}, ensure_ascii=False) + "\n"
            )
    return path


def _cell(value: str) -> str:
    return (
        escape(value, quote=False)
        .replace("|", "\\|")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\n", "<br>")
    )


def _table(headers: tuple[str, ...], rows: Iterable[tuple[str, ...]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(_cell(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def write_markdown(report: ScanReport, output_dir: str | Path, *, stem: str | None = None) -> Path:
    """Write exposure evidence, branch remediation and remote-detection limitations."""
    path = _path(report, output_dir, stem, "md")
    safe = _safe_report(report)
    sections = [
        "# PHP2Shell Audit Report",
        f"Generated UTC: {datetime.now(UTC).isoformat()}",
        "> Detection-only: A version match is exposure evidence, not proof of exploitability.",
        "## Summary",
        _table(
            ("Target", "Verdict", "PHP", "SAPI", "WAF", "Requests", "Error"),
            (
                (
                    result.target.url,
                    result.verdict.value,
                    result.php.version
                    or ("detected; version unknown" if result.php.detected else "not detected"),
                    result.php.sapi.value,
                    result.waf.value,
                    str(result.requests_made),
                    result.error or "",
                )
                for result in safe.results
            ),
        ),
    ]
    for result in safe.results:
        sections.extend(
            [
                f"## Target: {_cell(result.target.url)}",
                f"Verdict: {result.verdict.value}",
                "### PHP Evidence",
                _table(
                    ("Source", "Value"), ((item.source, item.value) for item in result.php.evidence)
                ),
                "### Assessments",
                _table(
                    ("CVE", "Verdict", "Reason", "Fixed version"),
                    (
                        (
                            item.cve_id,
                            item.verdict.value,
                            item.reason,
                            item.fixed_version or "not established",
                        )
                        for item in result.assessments
                    ),
                ),
                "### Findings",
                _table(
                    ("Severity", "Title", "Mitigation"),
                    (
                        (item.severity.value, item.title, item.mitigation or "")
                        for item in result.findings
                    ),
                ),
                "### Evidence",
                _table(
                    ("Source", "Value"),
                    (
                        (item.source, item.value)
                        for item in (
                            *result.evidence,
                            *(item for finding in result.findings for item in finding.evidence),
                        )
                    ),
                ),
            ]
        )
    sections.append("## Remediation")
    for result in safe.results:
        for assessment in result.assessments:
            if assessment.verdict == Verdict.VULNERABLE_VERSION:
                upgrade = (
                    f"upgrade to the branch fixed version {assessment.fixed_version} "
                    "or a supported newer release"
                    if assessment.fixed_version
                    else "upgrade to a supported patched PHP branch"
                )
                sections.append(
                    f"- {_cell(result.target.url)} ({assessment.cve_id}): {upgrade}; "
                    "restart PHP-FPM/Apache workers and verify the serving runtime."
                )
    sections.extend(
        [
            "- For CVE-2026-115560, apply `session.upload_progress.enabled=0` before request "
            "parsing and restart every worker. Fixed versions for CVE-2026-109618 and "
            "CVE-2026-109619 do not establish remediation of this configuration-dependent issue. "
            "Its severity and score are project-supplied classifications, "
            "not a published PHP rating.",
            "- Unknown versions require server-side verification of the runtime "
            "and vendor patch status.",
            "## Limitations",
            "Hidden `X-Powered-By`, WAF stripping, reverse proxies, shared hosting, "
            "and distro backports "
            "can obscure or change version evidence. Banners can be stale. WAF presence does not "
            "establish protection, and remote evidence cannot confirm "
            "configuration-dependent conditions.",
        ]
    )
    with path.open("x", encoding="utf-8") as stream:
        stream.write("\n\n".join(sections) + "\n")
    return path


def write_csv(report: ScanReport, output_dir: str | Path, *, stem: str | None = None) -> Path:
    """Write one CSV row per target with compact assessments and findings."""
    path = _path(report, output_dir, stem, "csv")
    with path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=_CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        for result in _safe_report(report).results:
            writer.writerow(
                {
                    "target": result.target.url,
                    "verdict": result.verdict.value,
                    "php_detected": result.php.detected,
                    "php_version": result.php.version or "",
                    "sapi": result.php.sapi.value,
                    "waf": result.waf.value,
                    "assessments": "; ".join(
                        f"{item.cve_id}={item.verdict.value}" for item in result.assessments
                    ),
                    "findings": "; ".join(
                        f"{item.severity.value}:{item.title}" for item in result.findings
                    ),
                    "requests_made": result.requests_made,
                    "error": result.error or "",
                }
            )
    return path


def write_all(
    report: ScanReport,
    output_dir: str | Path,
    *,
    formats: Iterable[str] = ("json", "jsonl", "markdown", "csv"),
    stem: str | None = None,
) -> dict[str, Path]:
    """Validate formats before writing; normalize md and write each format once."""
    writers = {
        "json": write_json,
        "jsonl": write_jsonl,
        "markdown": write_markdown,
        "csv": write_csv,
    }
    selected = dict.fromkeys("markdown" if name == "md" else name for name in formats)
    for name in selected:
        if name not in writers:
            raise ValueError(f"Unknown report format: {name}")
    shared_stem = _validated_stem(report, stem)
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    suffixes = tuple("md" if name == "markdown" else name for name in selected)
    shared_stem = _free_stem(directory, shared_stem, suffixes)
    return {name: writers[name](report, directory, stem=shared_stem) for name in selected}
