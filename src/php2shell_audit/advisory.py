"""Offline advisory snapshot loading and conservative PHP version assessment."""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType

from php2shell_audit.models import Assessment, JsonValue, PhpInfo, Verdict


@dataclass(frozen=True, slots=True)
class Advisory:
    """Typed snapshot with read-only mappings and immutable top-level sequences."""

    schema_version: int
    generated_at: str
    fixed_versions: Mapping[str, str]
    cves: Mapping[str, Mapping[str, JsonValue]]
    mitigations: tuple[str, ...]
    references: tuple[str, ...]


def _mapping(value: JsonValue, field: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ValueError(f"Advisory {field} must be a mapping")
    return value


def _strings(value: JsonValue, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Advisory {field} must be a list of strings")
    return tuple(item for item in value if isinstance(item, str))


def load_advisories(path: Path | None = None) -> Advisory:
    """Read local JSON, raising ValueError for malformed snapshot data.

    File access errors propagate to the caller. No network access is performed.
    """
    source = path if path is not None else files("php2shell_audit").joinpath("data/php2shell.json")
    try:
        data: JsonValue = json.loads(source.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"Malformed advisory JSON: {error}") from error
    snapshot = _mapping(data, "root")
    schema_version = snapshot.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise ValueError("Advisory schema_version must be integer 1")
    generated_at = snapshot.get("generated_at")
    if not isinstance(generated_at, str):
        raise ValueError("Advisory generated_at must be a string")
    fixed_versions: dict[str, str] = {}
    for branch, fixed in _mapping(snapshot.get("fixed_versions"), "fixed_versions").items():
        if not isinstance(fixed, str):
            raise ValueError("Advisory fixed_versions must map strings to strings")
        fixed_versions[branch] = fixed
    cves: dict[str, Mapping[str, JsonValue]] = {}
    for cve_id, details in _mapping(snapshot.get("cves"), "cves").items():
        cves[cve_id] = MappingProxyType(_mapping(details, f"cves.{cve_id}"))
    return Advisory(
        schema_version=schema_version,
        generated_at=generated_at,
        fixed_versions=MappingProxyType(fixed_versions),
        cves=MappingProxyType(cves),
        mitigations=_strings(snapshot.get("mitigations"), "mitigations"),
        references=_strings(snapshot.get("references"), "references"),
    )


def parse_version(version: str | None) -> tuple[int, int, int] | None:
    """Parse a leading X.Y.Z after an optional 'PHP ' prefix, else None."""
    if version is None:
        return None
    match = re.match(r"(?:PHP )?([0-9]+)\.([0-9]+)\.([0-9]+)", version)
    if match is None:
        return None
    return int(match[1]), int(match[2]), int(match[3])


def fixed_version_for(version: str, advisory: Advisory) -> str | None:
    """Return the snapshot's fixed release for the observed branch, if known."""
    parsed = parse_version(version)
    if parsed is None:
        return None
    return advisory.fixed_versions.get(f"{parsed[0]}.{parsed[1]}")


def assess_php(version: str | None, advisory: Advisory) -> tuple[Assessment, ...]:
    """Assess the two version-based CVEs without claiming exploitability."""
    parsed = parse_version(version)
    fixed = None
    verdict = Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN
    if version is None:
        reason = "No PHP version was observed; exposure cannot be ruled out."
    elif parsed is None:
        reason = f"Unrecognized PHP version string {version!r}; exposure cannot be ruled out."
    elif parsed < (8, 2, 0):
        verdict = Verdict.VULNERABLE_VERSION
        reason = "EOL PHP branch; no upstream fixed release"
    else:
        fixed = fixed_version_for(version, advisory)
        parsed_fixed = parse_version(fixed)
        if parsed_fixed is not None:
            verdict = (
                Verdict.VULNERABLE_VERSION
                if parsed < parsed_fixed
                else Verdict.NOT_VULNERABLE_VERSION
            )
            relation = "below" if parsed < parsed_fixed else "at or above"
            reason = f"Observed PHP {version} is {relation} fixed release {fixed}."
        else:
            releases = [
                (parsed_release, release)
                for release in advisory.fixed_versions.values()
                if (parsed_release := parse_version(release)) is not None
            ]
            latest = max(releases, default=None)
            if latest is not None and parsed[:2] > latest[0][:2] and parsed > latest[0]:
                verdict = Verdict.NOT_VULNERABLE_VERSION
                fixed = latest[1]
                reason = "Version is newer than the latest fixed release in this advisory snapshot"
            else:
                fixed = None
                reason = f"No usable fixed release for PHP {version} in this advisory snapshot."
    return tuple(
        Assessment(cve_id=cve_id, verdict=verdict, reason=reason, fixed_version=fixed)
        for cve_id in ("CVE-2026-109618", "CVE-2026-109619")
    )


def assess_configuration(advisory: Advisory) -> Assessment:
    """Keep configuration-dependent exposure unconfirmed regardless of version."""
    return Assessment(
        cve_id="CVE-2026-115560",
        verdict=Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN,
        reason=(
            "Configuration-dependent issue; remote version fingerprinting cannot confirm "
            "the required session.serialize_handler and session.upload_progress conditions."
        ),
        fixed_version=None,
        configuration_dependent=True,
    )


def overall_verdict(php: PhpInfo, assessments: tuple[Assessment, ...]) -> Verdict:
    """Prioritize PHP detection, then vulnerable, unknown, and fixed outcomes."""
    if not php.detected:
        return Verdict.NOT_PHP
    verdicts = {assessment.verdict for assessment in assessments}
    if Verdict.VULNERABLE_VERSION in verdicts:
        return Verdict.VULNERABLE_VERSION
    if Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN in verdicts:
        return Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN
    return Verdict.NOT_VULNERABLE_VERSION
