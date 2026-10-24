import csv
import json
import re
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from php2shell_audit.models import (
    Assessment,
    Evidence,
    Finding,
    PhpInfo,
    Sapi,
    ScanReport,
    Severity,
    Target,
    TargetResult,
    Verdict,
    Waf,
)
from php2shell_audit.reporting import (
    report_stem,
    write_all,
    write_csv,
    write_json,
    write_jsonl,
    write_markdown,
)


@pytest.fixture
def report() -> ScanReport:
    vulnerable = TargetResult(
        target=Target("https://vulnerable.example.test/"),
        verdict=Verdict.VULNERABLE_VERSION,
        php=PhpInfo(True, "8.4.26", Sapi.FPM, (Evidence("header:X-Powered-By", "PHP/8.4.26"),)),
        waf=Waf.CLOUDFLARE,
        assessments=(
            Assessment(
                "CVE-2026-109618", Verdict.VULNERABLE_VERSION, "Version precedes patch", "8.4.27"
            ),
        ),
        findings=(
            Finding(
                "WAF | detected\nupstream",
                Severity.INFO,
                "Not proof of protection",
                (Evidence("header:Server", "cloudflare"),),
                "Patch | verify\nworkers",
            ),
        ),
        evidence=(Evidence("header:Set-Cookie", "PHPSESSID=<redacted>"),),
        requests_made=2,
    )
    fixed = replace(
        vulnerable,
        target=Target("https://fixed.example.test/"),
        verdict=Verdict.NOT_VULNERABLE_VERSION,
        php=PhpInfo(True, "8.4.27"),
        assessments=(
            Assessment(
                "CVE-2026-109618", Verdict.NOT_VULNERABLE_VERSION, "Fixed release", "8.4.27"
            ),
        ),
        findings=(),
    )
    unknown = TargetResult(
        Target("https://unknown.example.test/"),
        Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN,
        php=PhpInfo(True),
    )
    non_php = TargetResult(Target("https://static.example.test/"), Verdict.NOT_PHP)
    return ScanReport(
        (vulnerable, fixed, unknown, non_php),
        "2026-10-24T14:15:16+02:00",
        "2026-10-24T12:16:00Z",
    )


def test_json_preserves_report_structure(tmp_path: Path, report: ScanReport) -> None:
    path = write_json(report, tmp_path / "new")
    data = json.loads(path.read_text())
    assert data == report.to_dict()
    assert data["schema_version"] == 1
    assert "advisory" not in data
    result = data["results"][0]
    assert result["target"]["url"] == "https://vulnerable.example.test/"
    assert result["verdict"] == "VULNERABLE_VERSION"
    assert result["assessments"][0]["fixed_version"] == "8.4.27"
    assert result["php"]["evidence"] == [{"source": "header:X-Powered-By", "value": "PHP/8.4.26"}]
    assert path.read_bytes().endswith(b"\n")


def test_jsonl_has_metadata_and_one_record_per_target(tmp_path: Path, report: ScanReport) -> None:
    path = write_jsonl(report, tmp_path)
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[0] == {
        "type": "report",
        "schema_version": 1,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
    }
    assert len(records[1:]) == len(report.results)
    assert all(record["type"] == "result" for record in records[1:])
    assert records[1]["verdict"] == "VULNERABLE_VERSION"
    assert path.read_bytes().endswith(b"\n")


def test_markdown_explains_exposure_and_remediation(tmp_path: Path, report: ScanReport) -> None:
    text = write_markdown(report, tmp_path).read_text()
    for expected in (
        "Detection-only",
        "CVE-2026-109618",
        "8.4.27",
        "Remediation",
        "Limitations",
        "https://vulnerable.example.test/",
        "VULNERABLE_VERSION",
        "PHP-FPM/Apache",
        "session.upload_progress.enabled=0",
        "CVE-2026-115560",
        "server-side verification",
        "X-Powered-By",
        "WAF stripping",
        "reverse proxies",
        "shared hosting",
        "distro backports",
        "header:X-Powered-By",
        "header:Server",
        "header:Set-Cookie",
    ):
        assert expected in text
    assert "WAF \\| detected<br>upstream" in text
    assert "Patch \\| verify<br>workers" in text


def test_csv_has_one_row_per_target(tmp_path: Path, report: ScanReport) -> None:
    path = write_csv(report, tmp_path)
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        assert reader.fieldnames == [
            "target",
            "verdict",
            "php_detected",
            "php_version",
            "sapi",
            "waf",
            "assessments",
            "findings",
            "requests_made",
            "error",
        ]
    assert len(rows) == 4
    assert rows[0]["assessments"] == "CVE-2026-109618=VULNERABLE_VERSION"
    assert rows[0]["findings"].startswith("info:WAF")
    assert rows[0]["php_version"] == "8.4.26"
    assert b"\r\n" not in path.read_bytes()


def test_write_all_defaults_and_aliases(tmp_path: Path, report: ScanReport) -> None:
    paths = write_all(report, tmp_path / "all")
    assert set(paths) == {"json", "jsonl", "markdown", "csv"}
    assert all(path.is_file() for path in paths.values())
    selected = write_all(report, tmp_path / "selected", formats=["json", "md", "markdown"])
    assert set(selected) == {"json", "markdown"}
    assert len(list((tmp_path / "selected").iterdir())) == 2


def test_write_all_preserves_same_timestamp_reports(tmp_path: Path, report: ScanReport) -> None:
    first = write_all(report, tmp_path)
    original = {name: path.read_bytes() for name, path in first.items()}

    second = write_all(report, tmp_path)

    assert len(set(first.values()) | set(second.values())) == 8
    assert len(list(tmp_path.iterdir())) == 8
    assert {path.stem for path in second.values()} == {"20261024T121516Z-1"}
    assert {name: path.read_bytes() for name, path in first.items()} == original


@pytest.mark.parametrize("occupied", [1, 2])
def test_write_all_skips_stems_with_any_selected_suffix(
    tmp_path: Path, report: ScanReport, occupied: int
) -> None:
    existing = tmp_path / "20261024T121516Z.json"
    existing.write_text("original evidence")
    if occupied == 2:
        (tmp_path / "20261024T121516Z-1.csv").write_text("other evidence")

    paths = write_all(report, tmp_path)

    assert {path.stem for path in paths.values()} == {f"20261024T121516Z-{occupied}"}
    assert len(paths) == 4
    assert existing.read_text() == "original evidence"


@pytest.mark.parametrize("writer", [write_json, write_jsonl, write_markdown, write_csv])
def test_direct_writers_preserve_existing_reports(
    tmp_path: Path, report: ScanReport, writer: Callable[[ScanReport, Path], Path]
) -> None:
    first = writer(report, tmp_path)
    original = first.read_bytes()

    second = writer(replace(report, results=()), tmp_path)

    assert second != first
    assert second.stem == "20261024T121516Z-1"
    assert first.read_bytes() == original
    assert second.read_bytes() != original


def test_unknown_format_fails_before_writing(tmp_path: Path, report: ScanReport) -> None:
    with pytest.raises(ValueError, match="xml"):
        write_all(report, tmp_path, formats=["json", "xml"])
    assert list(tmp_path.iterdir()) == []


def test_report_stem_uses_start_time_in_utc(report: ScanReport) -> None:
    assert report_stem(report) == "20261024T121516Z"
    assert report_stem(replace(report, started_at="2026-10-24T12:15:16")) == "20261024T121516Z"


@pytest.mark.parametrize("started_at", [None, "invalid"])
def test_invalid_start_uses_current_utc(started_at: str | None) -> None:
    before = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = report_stem(ScanReport(started_at=started_at))
    after = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    assert before <= stem <= after
    assert re.fullmatch(r"\d{8}T\d{6}Z", stem)


def test_custom_stem_is_sanitized(tmp_path: Path, report: ScanReport) -> None:
    path = write_json(report, tmp_path, stem="audit report!@v1")
    assert path.stem == "audit_report__v1"
    assert re.fullmatch(r"[a-zA-Z0-9_.-]+", path.name)


@pytest.mark.parametrize("stem", ["../escape", "a/b", "a\\b", "a..b", ".."])
def test_unsafe_stem_is_rejected(tmp_path: Path, report: ScanReport, stem: str) -> None:
    with (
        patch.object(Path, "exists", side_effect=AssertionError("Unexpected existence check")),
        patch.object(Path, "is_dir", side_effect=AssertionError("Unexpected directory check")),
        patch.object(Path, "mkdir", side_effect=AssertionError("Unexpected directory creation")),
    ):
        with pytest.raises(ValueError, match="stem"):
            write_all(report, tmp_path, stem=stem)
        with pytest.raises(ValueError, match="stem"):
            write_json(report, tmp_path, stem=stem)


def test_raw_sensitive_evidence_is_redacted_in_every_format(
    tmp_path: Path, report: ScanReport
) -> None:
    target = replace(
        report.results[0],
        target=Target("https://example.test/?token=fixture-query"),
        evidence=(
            Evidence("header:Set-Cookie", "PHPSESSID=fixture-cookie"),
            Evidence("header:Authorization", "Bearer fixture-authorization"),
            Evidence("cookie:PHPSESSID", "fixture-cookie"),
        ),
        php=PhpInfo(True, evidence=(Evidence("header:Cookie", "fixture-cookie"),)),
        findings=(
            Finding(
                "header",
                Severity.INFO,
                "observed",
                (Evidence("header:X-Api-Key", "fixture-authorization"),),
            ),
        ),
        assessments=(
            replace(
                report.results[0].assessments[0],
                evidence=(Evidence("header:Authorization", "Bearer fixture-authorization"),),
            ),
        ),
    )
    for path in write_all(replace(report, results=(target,)), tmp_path).values():
        text = path.read_text()
        assert "fixture-cookie" not in text
        assert "fixture-authorization" not in text
        assert "fixture-query" not in text


def test_empty_report_writes_all_formats(tmp_path: Path) -> None:
    paths = write_all(ScanReport(), tmp_path)
    assert json.loads(paths["json"].read_text())["results"] == []
    assert len(paths["jsonl"].read_text().splitlines()) == 1
    assert "Remediation" in paths["markdown"].read_text()


def test_markdown_preserves_finding_context_without_active_markup(
    tmp_path: Path, report: ScanReport
) -> None:
    finding = Finding(
        "[click](javascript:alert(1)) <script>bad</script>",
        Severity.INFO,
        "A banner alone cannot establish the serving runtime.",
    )
    contextual = replace(report, results=(replace(report.results[0], findings=(finding,)),))

    text = write_markdown(contextual, tmp_path).read_text()

    assert finding.description in text
    assert finding.title not in text
    assert "\\[click\\]" in text
    assert "&lt;script&gt;" in text
