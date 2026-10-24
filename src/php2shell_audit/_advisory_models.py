"""Typed per-CVE metadata parsed at the snapshot construction seam."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from php2shell_audit.models import Assessment, JsonValue, Verdict


def _text(details: Mapping[str, JsonValue], field: str) -> str | None:
    if field not in details:
        return None
    value = details[field]
    if not isinstance(value, str):
        raise ValueError(f"Advisory {field} must be a string")
    return value


def _texts(details: Mapping[str, JsonValue], field: str) -> tuple[str, ...]:
    value = details.get(field, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Advisory {field} must be a list of strings")
    return tuple(item for item in value if isinstance(item, str))


@dataclass(frozen=True, slots=True)
class AffectedRelease:
    branch: str
    range: str
    fixed: str | None


@dataclass(frozen=True, slots=True)
class CveMetadata:
    assessment: Assessment
    affected: tuple[AffectedRelease, ...] = ()

    @classmethod
    def parse(cls, cve_id: str, details: Mapping[str, JsonValue]) -> CveMetadata:
        affected = details.get("affected", [])
        if not isinstance(affected, list):
            raise ValueError("Advisory affected must be a list")
        releases: list[AffectedRelease] = []
        for entry in affected:
            if not isinstance(entry, dict):
                raise ValueError("Advisory affected entry must be a mapping")
            branch = entry.get("branch")
            version_range = entry.get("range")
            fixed = entry.get("fixed")
            if not isinstance(branch, str) or not isinstance(version_range, str):
                raise ValueError("Advisory affected branch and range must be strings")
            if fixed is not None and not isinstance(fixed, str):
                raise ValueError("Advisory affected fixed must be a string or null")
            releases.append(AffectedRelease(branch, version_range, fixed))
        return cls(
            Assessment(
                cve_id,
                Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN,
                "",
                title=_text(details, "title") or "",
                severity=_text(details, "severity"),
                rating_notes=_text(details, "rating_notes"),
                conditions=_text(details, "condition"),
                remediation=_texts(details, "mitigations"),
                verification=_texts(details, "verification"),
                references=_texts(details, "references"),
            ),
            tuple(releases),
        )
