import json
from dataclasses import replace
from pathlib import Path

import pytest

from php2shell_audit.advisory import (
    Advisory,
    assess_configuration,
    assess_php,
    fixed_version_for,
    load_advisories,
    overall_verdict,
    parse_version,
)
from php2shell_audit.models import Assessment, JsonValue, PhpInfo, Verdict


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr("socket.socket")
    monkeypatch.delattr("socket.getaddrinfo")


@pytest.fixture
def advisory() -> Advisory:
    return load_advisories()


@pytest.fixture
def snapshot() -> dict[str, JsonValue]:
    return {
        "schema_version": 1,
        "generated_at": "2026-10-24",
        "fixed_versions": {"8.4": "8.4.99"},
        "cves": {"CVE-2026-109618": {"title": "Local test snapshot"}},
        "mitigations": ["Upgrade PHP"],
        "references": ["https://example.invalid/advisory"],
    }


def test_load_bundled_advisory(advisory: Advisory) -> None:
    assert advisory.schema_version == 1
    assert advisory.generated_at == "2026-10-24"
    assert set(advisory.cves) == {"CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"}
    assert advisory.fixed_versions == {
        "8.2": "8.2.35",
        "8.3": "8.3.36",
        "8.4": "8.4.27",
        "8.5": "8.5.12",
    }
    assert isinstance(advisory.mitigations, tuple)
    assert isinstance(advisory.references, tuple)


def test_load_explicit_snapshot(tmp_path: Path, snapshot: dict[str, JsonValue]) -> None:
    path = tmp_path / "advisory.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")

    loaded = load_advisories(path)

    assert loaded.fixed_versions == {"8.4": "8.4.99"}
    assert loaded.cves["CVE-2026-109618"]["title"] == "Local test snapshot"
    assert loaded.mitigations == ("Upgrade PHP",)
    assert loaded.references == ("https://example.invalid/advisory",)


def test_missing_fixed_versions(tmp_path: Path, snapshot: dict[str, JsonValue]) -> None:
    del snapshot["fixed_versions"]
    path = tmp_path / "advisory.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")

    with pytest.raises(ValueError, match="fixed_versions"):
        load_advisories(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("schema_version", 1.0),
        ("generated_at", None),
        ("fixed_versions", []),
        ("fixed_versions", {"8.4": 27}),
        ("cves", []),
        ("cves", {"CVE-2026-109618": "invalid"}),
        ("mitigations", "Upgrade PHP"),
        ("mitigations", [1]),
        ("references", None),
        ("references", [False]),
    ],
)
def test_malformed_fields(
    tmp_path: Path, snapshot: dict[str, JsonValue], field: str, value: JsonValue
) -> None:
    snapshot[field] = value
    path = tmp_path / "advisory.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")

    with pytest.raises(ValueError, match=field):
        load_advisories(path)


@pytest.mark.parametrize("text", ["{broken", "[]", "null"])
def test_malformed_json(tmp_path: Path, text: str) -> None:
    path = tmp_path / "advisory.json"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="[Aa]dvisory"):
        load_advisories(path)


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("8.4.26", (8, 4, 26)),
        ("8.4.26-1ubuntu1", (8, 4, 26)),
        ("PHP 8.4.26", (8, 4, 26)),
        ("8.5.0RC1", (8, 5, 0)),
        (None, None),
        ("8.4", None),
        ("8.4.x", None),
        ("abc", None),
        ("", None),
        ("-8.4.26", None),
        ("8.-4.26", None),
        ("8.4.-26", None),
        ("prefix 8.4.26", None),
    ],
)
def test_parse_version(version: str | None, expected: tuple[int, int, int] | None) -> None:
    assert parse_version(version) == expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("8.2.34", "8.2.35"),
        ("8.3.35", "8.3.36"),
        ("8.4.26", "8.4.27"),
        ("8.5.11", "8.5.12"),
        ("8.6.0", None),
        ("7.4.33", None),
        ("8.4.x", None),
    ],
)
def test_fixed_version_for(advisory: Advisory, version: str, expected: str | None) -> None:
    assert fixed_version_for(version, advisory) == expected


@pytest.mark.parametrize(
    ("version", "verdict", "fixed"),
    [
        ("8.4.26", Verdict.VULNERABLE_VERSION, "8.4.27"),
        ("8.2.34", Verdict.VULNERABLE_VERSION, "8.2.35"),
        ("8.3.35", Verdict.VULNERABLE_VERSION, "8.3.36"),
        ("8.5.11", Verdict.VULNERABLE_VERSION, "8.5.12"),
        ("8.4.27", Verdict.NOT_VULNERABLE_VERSION, "8.4.27"),
        ("8.4.28", Verdict.NOT_VULNERABLE_VERSION, "8.4.27"),
        ("8.2.35", Verdict.NOT_VULNERABLE_VERSION, "8.2.35"),
        ("8.3.36", Verdict.NOT_VULNERABLE_VERSION, "8.3.36"),
        ("8.5.12", Verdict.NOT_VULNERABLE_VERSION, "8.5.12"),
        ("7.4.33", Verdict.VULNERABLE_VERSION, None),
        ("8.0.30", Verdict.VULNERABLE_VERSION, None),
        ("8.1.31", Verdict.VULNERABLE_VERSION, None),
        ("8.6.0", Verdict.NOT_VULNERABLE_VERSION, "8.5.12"),
        ("9.0.0", Verdict.NOT_VULNERABLE_VERSION, "8.5.12"),
        (None, Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN, None),
        ("8.4.x", Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN, None),
    ],
)
def test_assess_php(
    advisory: Advisory, version: str | None, verdict: Verdict, fixed: str | None
) -> None:
    assessments = assess_php(version, advisory)

    assert tuple(item.cve_id for item in assessments) == ("CVE-2026-109618", "CVE-2026-109619")
    assert tuple(item.verdict for item in assessments) == (verdict, verdict)
    assert tuple(item.fixed_version for item in assessments) == (fixed, fixed)
    assert all(item.reason and not item.configuration_dependent for item in assessments)


def test_unknown_branch_inside_snapshot_range(advisory: Advisory) -> None:
    sparse = replace(advisory, fixed_versions={"8.2": "8.2.35", "8.5": "8.5.12"})

    assessments = assess_php("8.4.99", sparse)

    assert all(
        item.verdict == Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN
        and item.fixed_version is None
        for item in assessments
    )


def test_configuration_assessment(advisory: Advisory) -> None:
    assessment = assess_configuration(advisory)

    assert assessment.cve_id == "CVE-2026-115560"
    assert assessment.configuration_dependent is True
    assert assessment.fixed_version is None
    assert assessment.verdict == Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN
    assert assessment.reason == (
        "Configuration-dependent issue; remote version fingerprinting cannot confirm "
        "the required session.serialize_handler and session.upload_progress conditions."
    )


@pytest.mark.parametrize(
    ("detected", "verdicts", "expected"),
    [
        (False, (Verdict.VULNERABLE_VERSION,), Verdict.NOT_PHP),
        (False, (), Verdict.NOT_PHP),
        (
            True,
            (
                Verdict.NOT_VULNERABLE_VERSION,
                Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN,
                Verdict.VULNERABLE_VERSION,
            ),
            Verdict.VULNERABLE_VERSION,
        ),
        (
            True,
            (Verdict.NOT_VULNERABLE_VERSION, Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN),
            Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN,
        ),
        (True, (Verdict.NOT_VULNERABLE_VERSION,) * 2, Verdict.NOT_VULNERABLE_VERSION),
        (True, (), Verdict.NOT_VULNERABLE_VERSION),
    ],
)
def test_overall_verdict(detected: bool, verdicts: tuple[Verdict, ...], expected: Verdict) -> None:
    php = PhpInfo(detected=detected)
    assessments = tuple(Assessment(cve_id="test", verdict=item, reason="test") for item in verdicts)

    assert overall_verdict(php, assessments) == expected
