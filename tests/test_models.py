"""Serialization contracts for detection-only domain models."""

import json
from dataclasses import FrozenInstanceError

import pytest

from php2shell_audit.models import (
    AdvisoryProvenance,
    Assessment,
    Evidence,
    Finding,
    PhpInfo,
    RequestContext,
    Sapi,
    ScanConfig,
    ScanReport,
    Severity,
    Target,
    TargetResult,
    Verdict,
    Waf,
)


def test_report_round_trips_when_nested_models_are_serialized() -> None:
    evidence = Evidence(source="header:X-Powered-By", value="PHP/8.3.35")
    report = ScanReport(
        started_at="2026-10-24T12:00:00Z",
        finished_at="2026-10-24T12:00:01Z",
        results=(
            TargetResult(
                target=Target("https://example.test/"),
                verdict=Verdict.VULNERABLE_VERSION,
                php=PhpInfo(detected=True, version="8.3.35", sapi=Sapi.FPM, evidence=(evidence,)),
                waf=Waf.CLOUDFLARE,
                assessments=(
                    Assessment(
                        cve_id="CVE-2026-109618",
                        verdict=Verdict.VULNERABLE_VERSION,
                        reason="Observed version precedes the fixed release.",
                        fixed_version="8.3.36",
                    ),
                ),
                findings=(
                    Finding(
                        title="PHP version disclosed",
                        severity=Severity.INFO,
                        description="Version observed in a response header.",
                        evidence=(evidence,),
                    ),
                ),
                evidence=(evidence,),
                requests_made=1,
            ),
        ),
    )

    decoded = json.loads(json.dumps(report.to_dict()))

    assert decoded == report.to_dict()
    result = decoded["results"][0]
    assert result["target"] == {"url": "https://example.test/"}
    assert result["php"]["version"] == "8.3.35"
    assert result["php"]["evidence"] == [{"source": "header:X-Powered-By", "value": "PHP/8.3.35"}]
    assert result["assessments"][0]["fixed_version"] == "8.3.36"
    assert result["verdict"] == "VULNERABLE_VERSION"
    assert result["php"]["sapi"] == "fpm"
    assert result["waf"] == "cloudflare"
    assert result["findings"][0]["severity"] == "info"


@pytest.mark.parametrize("verdict", list(Verdict))
def test_verdict_serializes_when_outcome_is_inconclusive_or_decisive(verdict: Verdict) -> None:
    result = TargetResult(target=Target("https://example.test/"), verdict=verdict)

    serialized = result.to_dict()

    assert serialized["verdict"] == verdict.value
    assert type(serialized["verdict"]) is str


@pytest.mark.parametrize("sapi", list(Sapi))
def test_sapi_serializes_when_metadata_is_converted(sapi: Sapi) -> None:
    metadata = PhpInfo(sapi=sapi)

    serialized = metadata.to_dict()

    assert serialized["sapi"] == sapi.value
    assert type(serialized["sapi"]) is str


@pytest.mark.parametrize("waf", list(Waf))
def test_waf_serializes_when_result_is_converted(waf: Waf) -> None:
    result = TargetResult(Target("https://example.test/"), Verdict.NOT_PHP, waf=waf)

    serialized = result.to_dict()

    assert serialized["waf"] == waf.value
    assert type(serialized["waf"]) is str


@pytest.mark.parametrize("severity", list(Severity))
def test_severity_serializes_when_finding_is_converted(severity: Severity) -> None:
    finding = Finding("Observed issue", severity, "Detection only.")

    serialized = finding.to_dict()

    assert serialized["severity"] == severity.value
    assert type(serialized["severity"]) is str


def test_scan_config_defaults_when_no_options_are_supplied() -> None:
    config = ScanConfig()

    serialized = config.to_dict()

    assert serialized == {
        "rate_limit": 1.0,
        "timeout": 10.0,
        "max_requests": 20,
        "max_redirects": 5,
        "max_response_bytes": 1_048_576,
        "deep": False,
        "allow_private": False,
        "authorized": False,
        "scope_file": None,
        "output_dir": "reports",
    }


def test_scan_config_is_mutable_when_operator_updates_options() -> None:
    config = ScanConfig()

    config.authorized = True

    assert config.authorized is True


@pytest.mark.parametrize("field_name", ["url"])
def test_target_rejects_mutation_when_constructed(field_name: str) -> None:
    target = Target("https://example.test/")

    with pytest.raises(FrozenInstanceError):
        setattr(target, field_name, "https://different.test/")


def test_unknown_metadata_survives_when_report_is_serialized() -> None:
    report = ScanReport(
        results=(
            TargetResult(
                Target("https://example.test/"),
                Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN,
                php=PhpInfo(detected=True),
            ),
        )
    )

    decoded = json.loads(json.dumps(report.to_dict()))

    assert decoded["results"][0]["php"]["version"] is None
    assert decoded["results"][0]["php"]["sapi"] == "unknown"
    assert decoded["results"][0]["verdict"] == "POTENTIALLY_VULNERABLE_VERSION_UNKNOWN"


def test_optional_provenance_preserves_legacy_report_shape() -> None:
    report = ScanReport()

    assert "advisory" not in report.to_dict()
    assert Evidence("header:x-powered-by", "PHP/8.4.26").to_dict() == {
        "source": "header:x-powered-by",
        "value": "PHP/8.4.26",
    }


def test_nested_assessment_context_serializes_without_body_retention() -> None:
    request = RequestContext(
        "GET",
        "https://example.test/",
        "https://example.test/php",
        200,
        16,
        True,
        "2026-10-24T12:00:00+00:00",
    )
    evidence = Evidence("header:x-powered-by", "PHP/8.4.26", request)
    assessment = Assessment(
        "CVE-test",
        Verdict.VULNERABLE_VERSION,
        "range match",
        evidence=(evidence,),
        observed_version="8.4.26",
        affected_range=">=8.4.0 <8.4.27",
        affected_range_match=True,
    )
    report = ScanReport(advisory=AdvisoryProvenance(1, "2026-10-24", "a" * 64))

    decoded = json.loads(json.dumps(assessment.to_dict()))

    assert decoded["evidence"][0]["request"] == request.to_dict()
    assert decoded["basis"] == "observed_version"
    assert decoded["affected_range_match"] is True
    assert report.to_dict()["advisory"] == {
        "schema_version": 1,
        "snapshot_date": "2026-10-24",
        "snapshot_sha256": "a" * 64,
    }
