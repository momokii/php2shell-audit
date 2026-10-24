"""Markdown presentation of attached report data; no advisory loading or file I/O."""

import re
from collections.abc import Iterable
from datetime import UTC, datetime
from html import escape
from typing import assert_never

from php2shell_audit.models import Assessment, Evidence, ScanReport, Verdict


def _cell(value: str) -> str:
    text = escape(value, quote=False).replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"([\\`*_{\[\]()|#!}])", r"\\\1", text).replace("\n", "<br>")


def _table(headers: tuple[str, ...], rows: Iterable[tuple[str, ...]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(_cell(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def _bullets(values: tuple[str, ...]) -> str:
    return "\n".join(f"- {_cell(value)}" for value in values) or "Not established in this report."


def _evidence(observations: tuple[Evidence, ...]) -> str:
    if not observations:
        return "No supporting observation attached."
    rows = []
    for item in observations:
        request = item.request
        context = (
            (
                request.method,
                request.requested_url,
                request.final_url,
                str(request.status_code),
                request.observed_at,
                str(request.body_prefix_bytes),
                "yes" if request.body_truncated else "no",
            )
            if request is not None
            else ("not established",) * 7
        )
        rows.append((item.source, item.value, *context))
    return _table(
        (
            "Source",
            "Value",
            "Method",
            "Requested URL",
            "Final URL",
            "Status",
            "Observed UTC",
            "Body prefix bytes",
            "Body truncated",
        ),
        rows,
    )


def _outcome(verdict: Verdict) -> str:
    match verdict:
        case Verdict.VULNERABLE_VERSION:
            return "Observed version matches an affected rule; not proof of exploitability."
        case Verdict.NOT_VULNERABLE_VERSION:
            return (
                "Version rule indicates a fixed release, not an all-clear. "
                "Configuration-dependent exposure may remain unknown."
            )
        case Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN:
            return (
                "Exposure is unknown; establish the runtime, applicable rule "
                "and configuration locally."
            )
        case Verdict.NOT_PHP:
            return "PHP was not detected in the bounded response; this is not proof PHP is absent."
        case Verdict.UNREACHABLE:
            return "Collection did not establish an assessable response; exposure remains unknown."
        case Verdict.BLOCKED_BY_SAFETY:
            return "Safety controls blocked collection; no exposure conclusion can be drawn."
        case Verdict.WAF_BLOCKED:
            return (
                "An intermediary may have blocked assessment; "
                "its presence is not proof of protection."
            )
        case unreachable:
            assert_never(unreachable)


def _assessment(item: Assessment) -> list[str]:
    match item.affected_range_match:
        case True:
            matched = "yes"
        case False:
            matched = "no"
        case None:
            matched = "unknown"
        case unreachable:
            assert_never(unreachable)
    return [
        f"#### {_cell(item.cve_id)}: {_cell(item.title or 'Title not established')}",
        _table(
            ("Assessment detail", "Value"),
            (
                ("Conclusion", item.verdict.value),
                ("Severity", item.severity or "not established"),
                ("Rating provenance", item.rating_notes or "not established"),
                ("Assessment basis", item.basis.value),
                ("Observed version", item.observed_version or "not established"),
                ("Affected range", item.affected_range or "not established"),
                ("Affected range match", matched),
                ("Branch fixed version", item.fixed_version or "not established"),
                ("Configuration dependent", "yes" if item.configuration_dependent else "no"),
                ("Source-described conditions", item.conditions or "not established"),
                ("Reasoning", item.reason),
            ),
        ),
        "A version match is not proof of exploitability; "
        "configuration conditions require local verification.",
        "##### Bound HTTP Evidence",
        _evidence(item.evidence),
        "##### Recommended Action",
        _bullets(item.remediation),
        "##### Verification",
        _bullets(item.verification),
        "##### Authoritative References (Attached Snapshot)",
        _bullets(item.references),
    ]


def render_markdown(report: ScanReport) -> str:
    """Format an already-redacted report without inventing missing observations."""
    sections = [
        "# PHP2Shell Audit Report",
        f"Scan started: {_cell(report.started_at or 'not established')}",
        f"Scan finished: {_cell(report.finished_at or 'not established')}",
        f"Generated UTC: {datetime.now(UTC).isoformat()}",
        "> Detection-only: A version match is exposure evidence, not proof of exploitability.",
        "## Advisory Provenance",
    ]
    if report.advisory is None:
        sections.append("Snapshot schema, date and SHA-256: not established in this report.")
    else:
        sections.append(
            _table(
                ("Snapshot schema", "Snapshot date", "Snapshot SHA-256"),
                (
                    (
                        str(report.advisory.schema_version),
                        report.advisory.snapshot_date,
                        report.advisory.snapshot_sha256,
                    ),
                ),
            )
        )
    sections.extend(
        [
            "The advisory snapshot is a project-maintained synthesis, not a live source. "
            "Its hash identifies snapshot bytes; it is not an authenticity signature. "
            "Citations and classifications below come only from the attached assessment data.",
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
                    for result in report.results
                ),
            ),
        ]
    )
    for result in report.results:
        sections.extend(
            [
                f"## Target: {_cell(result.target.url)}",
                f"Verdict: {result.verdict.value}. {_outcome(result.verdict)}",
                "### PHP Evidence",
                _evidence(result.php.evidence),
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
            ]
        )
        for assessment in result.assessments:
            sections.extend(_assessment(assessment))
        sections.extend(
            [
                "### Findings",
                _table(
                    ("Severity", "Title", "Description", "Mitigation"),
                    (
                        (item.severity.value, item.title, item.description, item.mitigation or "")
                        for item in result.findings
                    ),
                ),
                "### Evidence",
                _evidence(
                    (
                        *result.evidence,
                        *(item for finding in result.findings for item in finding.evidence),
                    )
                ),
            ]
        )
    sections.extend(
        [
            "## Remediation",
            "Use each CVE's attached recommended actions and verification steps above. "
            "CSV is a compact summary; JSON, JSONL and this Markdown report carry the full detail.",
            "General guidance (not an observation): verify the installed runtime "
            "and vendor patches locally, then restart PHP-FPM/Apache workers "
            "after remediation. For CVE-2026-115560, review "
            "`session.upload_progress.enabled=0` before request parsing; a "
            "version-fixed result does not establish remediation of this "
            "configuration-dependent issue.",
            "Unknown versions require server-side verification of the runtime "
            "and vendor patch status.",
            "## Limitations",
            "Hidden `X-Powered-By`, WAF stripping, reverse proxies, shared hosting, "
            "and distro backports "
            "can obscure or change version evidence. Banners can be forged or stale. "
            "WAF presence does not establish protection, and remote evidence "
            "cannot confirm configuration-dependent "
            "conditions. Unsupported branches remain unknown, not inferred "
            "affected or fixed. "
            "Only bounded observations are retained, not full response bodies. "
            "Missing request metadata "
            "means collection details were not established, not that a request was observed. "
            "No heuristic confidence or numeric risk score is inferred.",
        ]
    )
    return "\n\n".join(sections) + "\n"
