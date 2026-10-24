"""Validate the bundled advisory snapshot without network access."""

import json
from pathlib import Path
from typing import Final

import pytest

from php2shell_audit.models import JsonValue

DATA_PATH: Final = (
    Path(__file__).resolve().parents[1] / "src" / "php2shell_audit" / "data" / "php2shell.json"
)
FIXED_VERSIONS: Final = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
CONDITION: Final = (
    "application sets session.serialize_handler to php_binary or php_serialize, "
    "then switches to php at runtime with ini_set() before session_start(), "
    "with session.upload_progress.enabled=1"
)


def test_advisory_schema_when_snapshot_is_loaded() -> None:
    with DATA_PATH.open(encoding="utf-8") as advisory_file:
        advisory = json.load(advisory_file)

    assert advisory["schema_version"] == 1
    assert advisory["generated_at"] == "2026-10-24"
    assert advisory["fixed_versions"] == FIXED_VERSIONS
    assert "project-maintained synthesis" in advisory["notes"]
    assert "not an upstream authority" in advisory["notes"]
    assert set(advisory["cves"]) == {"CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"}
    for cve in advisory["cves"].values():
        assert cve["title"]
        assert cve["affected"]
        assert cve["sapi_notes"]
        assert cve["mitigations"]
        assert all(reference.startswith("https://") for reference in cve["references"])


@pytest.mark.parametrize("cve_id", ["CVE-2026-109618", "CVE-2026-109619"])
def test_affected_ranges_when_version_based_advisories_are_loaded(cve_id: str) -> None:
    with DATA_PATH.open(encoding="utf-8") as advisory_file:
        advisory = json.load(advisory_file)

    affected = {entry["branch"]: entry for entry in advisory["cves"][cve_id]["affected"]}

    assert set(affected) == set(FIXED_VERSIONS)
    assert advisory["cves"][cve_id]["severity"] == "critical"
    assert advisory["cves"][cve_id]["cvss_v4"] == 9.2
    for branch, fixed in FIXED_VERSIONS.items():
        assert affected[branch]["fixed"] == fixed
        assert affected[branch]["range"] == f">={branch}.0 <{fixed}"


@pytest.mark.parametrize("cve_id", ["CVE-2026-109618", "CVE-2026-109619"])
def test_unsupported_branches_when_version_based_advisories_are_loaded(cve_id: str) -> None:
    with DATA_PATH.open(encoding="utf-8") as advisory_file:
        advisory = json.load(advisory_file)

    cve = advisory["cves"][cve_id]

    assert all(entry["branch"] in FIXED_VERSIONS for entry in cve["affected"])
    notes = cve["unsupported_branch_notes"]
    assert "PHP <=8.1 is unsupported" in notes
    assert "No upstream fixed release" in notes
    assert "7.4, 8.0 and 8.1" in notes
    assert "vendor" in notes
    assert "verification" in notes
    assert "not a verified affected range" in notes


def test_session_issue_condition_when_configuration_dependent_advisory_is_loaded() -> None:
    with DATA_PATH.open(encoding="utf-8") as advisory_file:
        advisory = json.load(advisory_file)

    cve = advisory["cves"]["CVE-2026-115560"]

    assert cve["configuration_dependent"] is True
    assert cve["condition"] == CONDITION
    assert cve["out_of_band_patch"] is False
    assert all(entry["fixed"] is None for entry in cve["affected"])
    assert [entry["range"] for entry in cve["affected"]] == [
        "Not established by the informational advisory"
    ]
    assert "session.upload_progress.enabled=0" in cve["mitigations"]


def test_session_issue_attribution_when_configuration_dependent_advisory_is_loaded() -> None:
    with DATA_PATH.open(encoding="utf-8") as advisory_file:
        advisory = json.load(advisory_file)

    cve = advisory["cves"]["CVE-2026-115560"]

    assert cve["severity"] == "critical"
    assert cve["cvss_v4"] == 9.2
    assert "Project-supplied" in cve["rating_notes"]
    assert "no published upstream severity, CVSS rating or affected range" in cve["rating_notes"]
    assert set(cve["references"]) == {
        "https://www.php.net/archive/2026.php#2026-10-23-1",
        "https://cert.europa.eu/publications/security-advisories/2026-018/",
    }


def test_detection_only_keys_when_entire_snapshot_is_loaded() -> None:
    keys: list[str] = []

    def collect_keys(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        keys.extend(key for key, _value in pairs)
        return dict(pairs)

    with DATA_PATH.open(encoding="utf-8") as advisory_file:
        json.load(advisory_file, object_pairs_hook=collect_keys)

    assert {"payload", "exploit", "shell", "command"}.isdisjoint(keys)
