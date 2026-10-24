import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from php2shell_audit.models import (
    AdvisoryProvenance,
    Assessment,
    AssessmentBasis,
    Evidence,
    Finding,
    PhpInfo,
    RequestContext,
    ScanConfig,
    ScanReport,
    Severity,
    Target,
    TargetResult,
    Verdict,
)
from php2shell_audit.reporting import write_all, write_json, write_jsonl, write_markdown
from php2shell_audit.scanner import Scanner


def handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    version = "8.4.27" if host == "fixed.example.test" else "8.4.26"
    return httpx.Response(
        200,
        headers={"X-Powered-By": f"PHP/{version}", "Server": "Apache/2.4"},
        content=b"lab fixture",
    )


def test_scan_and_write_all_report_formats(tmp_path: Path) -> None:
    config = ScanConfig(authorized=True, deep=False)
    targets = [
        Target("https://vulnerable.example.test/"),
        Target("https://fixed.example.test/"),
    ]
    transport = httpx.MockTransport(handler)

    def resolver(host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    with Scanner(config, transport=transport, resolver=resolver) as scanner:
        report = scanner.scan_many(targets)

    assert len(report.results) == 2
    vulnerable, fixed = report.results
    assert vulnerable.verdict is Verdict.VULNERABLE_VERSION
    assert vulnerable.php.version == "8.4.26"
    assert fixed.verdict is Verdict.NOT_VULNERABLE_VERSION
    assert fixed.php.version == "8.4.27"

    for result in report.results:
        assert len(result.assessments) == 3
        assert result.assessments[2].cve_id == "CVE-2026-115560"
        assert result.assessments[2].configuration_dependent is True
        assert result.error is None

    paths = write_all(report, tmp_path, formats=("json", "jsonl", "markdown", "csv"))

    assert set(paths) == {"json", "jsonl", "markdown", "csv"}
    for path in paths.values():
        assert path.exists()
        assert path.is_relative_to(tmp_path)

    json_report = json.loads(paths["json"].read_text())
    assert json_report["schema_version"] == 1
    assert len(json_report["results"]) == 2

    jsonl_lines = [line for line in paths["jsonl"].read_text().splitlines() if line]
    jsonl_records = [json.loads(line) for line in jsonl_lines]
    assert jsonl_records[0]["type"] == "report"
    assert len(jsonl_records) == 3

    markdown = paths["markdown"].read_text()
    assert "not proof of exploitability" in markdown
    assert "CVE-2026-109618" in markdown

    csv_lines = paths["csv"].read_text().splitlines()
    assert csv_lines[0] == (
        "target,verdict,php_detected,php_version,sapi,waf,assessments,findings,requests_made,error"
    )
    assert len(csv_lines) == 3


@pytest.fixture(params=["alpha", "beta"])
def contextual_report(request: pytest.FixtureRequest) -> ScanReport:
    variant = str(request.param)
    observation = Evidence(
        "header:X-Powered-By",
        "PHP/8.4.26",
        RequestContext(
            "GET",
            "https://example.test/start",
            "https://example.test/final",
            200,
            512,
            True,
            "2026-10-20T12:00:00+00:00",
        ),
    )
    assessment = Assessment(
        "CVE-2026-109618",
        Verdict.VULNERABLE_VERSION,
        f"Matched {variant} rule",
        "8.4.27",
        basis=AssessmentBasis.OBSERVED_VERSION,
        observed_version="8.4.26",
        affected_range=f">=8.4.0 <8.4.27 ({variant})",
        affected_range_match=True,
        evidence=(observation,),
        remediation=(f"Patch per {variant} source",),
        verification=(f"Verify {variant} workers locally",),
        references=(f"https://www.php.net/{variant}",),
        title=f"Issue {variant}",
        severity="critical",
        rating_notes=f"Source rating {variant}",
        conditions=f"Runtime condition {variant}",
    )
    target = TargetResult(
        Target("https://example.test/"),
        Verdict.VULNERABLE_VERSION,
        php=PhpInfo(True, "8.4.26", evidence=(observation,)),
        assessments=(assessment,),
    )
    return ScanReport(
        (target,),
        "2026-10-20T11:59:00Z",
        "2026-10-20T12:01:00Z",
        advisory=AdvisoryProvenance(1, f"2026-10-20-{variant}", variant[0] * 64),
    )


@pytest.mark.parametrize("writer", [write_json, write_jsonl])
def test_context_and_attached_snapshot_survive_structured_exports(
    tmp_path: Path, contextual_report: ScanReport, writer: object
) -> None:
    path = writer(contextual_report, tmp_path)

    if path.suffix == ".json":
        metadata = json.loads(path.read_text())
        target = metadata["results"][0]
    else:
        metadata, target = map(json.loads, path.read_text().splitlines())
    assert metadata["advisory"] == contextual_report.advisory.to_dict()
    assert target["assessments"] == [contextual_report.results[0].assessments[0].to_dict()]
    assert target["assessments"][0]["evidence"][0]["request"] == {
        "method": "GET",
        "requested_url": "https://example.test/start",
        "final_url": "https://example.test/final",
        "status_code": 200,
        "body_prefix_bytes": 512,
        "body_truncated": True,
        "observed_at": "2026-10-20T12:00:00+00:00",
    }


def test_markdown_dossier_uses_attached_snapshot_details(
    tmp_path: Path, contextual_report: ScanReport
) -> None:
    assessment = contextual_report.results[0].assessments[0]
    provenance = contextual_report.advisory
    assert provenance is not None

    text = write_markdown(contextual_report, tmp_path).read_text()

    for value in (
        assessment.title,
        assessment.reason,
        assessment.rating_notes,
        assessment.conditions,
        *assessment.remediation,
        *assessment.verification,
        *assessment.references,
        provenance.snapshot_date,
        provenance.snapshot_sha256,
        "Scan started: 2026-10-20T11:59:00Z",
        "Scan finished: 2026-10-20T12:01:00Z",
        "Generated UTC:",
        "https://example.test/start",
        "https://example.test/final",
        "2026-10-20T12:00:00+00:00",
        "GET",
        "512",
        "200",
        "| Affected range match | yes |",
        "| Observed version | 8.4.26 |",
        "&gt;=8.4.0 &lt;8.4.27",
        "not an authenticity signature",
    ):
        assert value is not None and value in text


def test_request_context_and_sensitive_values_are_redacted_at_every_evidence_path(
    tmp_path: Path, contextual_report: ScanReport
) -> None:
    request = RequestContext(
        "GET",
        "https://fixture-user:fixture-password@example.test/start?token=fixture-request",
        "https://example.test/final?api_key=fixture-final#fixture-fragment",
        200,
        17,
        False,
        "2026-10-20T12:00:00Z",
    )
    evidence = (
        Evidence("header:X-Api-Key", "fixture-header", request),
        Evidence("response:body", "fixture-body-content", request),
    )
    result = replace(
        contextual_report.results[0],
        evidence=evidence,
        php=PhpInfo(True, "8.4.26", evidence=evidence),
        findings=(Finding("Observed", Severity.INFO, "Fixture", evidence),),
        assessments=(replace(contextual_report.results[0].assessments[0], evidence=evidence),),
    )
    original = replace(contextual_report, results=(result,))
    before = original.to_dict()

    paths = write_all(original, tmp_path)

    for path in paths.values():
        assert "fixture-" not in path.read_text()
    target = json.loads(paths["json"].read_text())["results"][0]
    for observations in (
        target["evidence"],
        target["php"]["evidence"],
        target["findings"][0]["evidence"],
        target["assessments"][0]["evidence"],
    ):
        for observation in observations:
            assert observation["value"] == "<redacted>"
            assert observation["request"]["requested_url"] == "https://example.test/start"
            assert observation["request"]["final_url"] == "https://example.test/final"
    assert original.to_dict() == before


@pytest.mark.parametrize("version", ["7.4.33", "8.1.33", "8.6.0", "9.0.0"])
def test_unsupported_branch_remains_unknown_through_scan_and_export(
    tmp_path: Path, version: str
) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, headers={"X-Powered-By": f"PHP/{version}"}, content=b"bounded fixture"
        )
    )
    with Scanner(
        ScanConfig(authorized=True, rate_limit=0),
        transport=transport,
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        report = scanner.scan_many([Target("https://example.test/")])

    paths = write_all(report, tmp_path)

    target = json.loads(paths["json"].read_text())["results"][0]
    assert target["verdict"] == Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN.value
    for assessment in target["assessments"]:
        assert assessment["verdict"] == Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN.value
        assert assessment["affected_range_match"] is None
    configuration = target["assessments"][2]
    assert configuration["basis"] == "unverified_configuration"
    assert configuration["evidence"] == []
    assert configuration["observed_version"] is None
    assert configuration["conditions"]
    assert "| Affected range match | unknown |" in paths["markdown"].read_text()
