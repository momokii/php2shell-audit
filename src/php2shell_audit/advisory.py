"""Offline advisory snapshot loading and conservative PHP version assessment."""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from hashlib import sha256

# False positive under requires-python >=3.12; tracked under TASK-002.
# nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType

from php2shell_audit._advisory_models import CveMetadata
from php2shell_audit.models import Assessment, AssessmentBasis, JsonValue, PhpInfo, Verdict


@dataclass(frozen=True, slots=True)
class Advisory:
    """Typed snapshot with read-only mappings and immutable top-level sequences."""

    schema_version: int
    generated_at: str
    fixed_versions: Mapping[str, str]
    cves: Mapping[str, Mapping[str, JsonValue]]
    mitigations: tuple[str, ...]
    references: tuple[str, ...]
    snapshot_sha256: str = ""
    metadata: Mapping[str, CveMetadata] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(
                {
                    cve_id: CveMetadata.parse(cve_id, details)
                    for cve_id, details in self.cves.items()
                }
            ),
        )


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
    payload = source.read_bytes()
    try:
        data: JsonValue = json.loads(payload.decode("utf-8"))
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
        snapshot_sha256=sha256(payload).hexdigest(),
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
    """Compare only documented stable branch ranges, without proving exploitability."""
    return tuple(
        _assess_version(version, advisory, cve_id)
        for cve_id in ("CVE-2026-109618", "CVE-2026-109619")
    )


def _assess_version(version: str | None, advisory: Advisory, cve_id: str) -> Assessment:
    metadata = advisory.metadata.get(
        cve_id, CveMetadata(Assessment(cve_id, Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN, ""))
    )
    assessment = replace(metadata.assessment, observed_version=version)
    parsed = parse_version(version)
    if version is None:
        return replace(
            assessment,
            reason="No PHP version was observed; exposure cannot be ruled out.",
        )
    if parsed is None or re.fullmatch(r"(?:PHP )?[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        return replace(
            assessment,
            reason=(
                f"Unsupported or non-stable PHP version {version!r}; "
                "verify the serving runtime locally."
            ),
        )
    if parsed < (8, 2, 0):
        return replace(
            assessment,
            reason=(
                "EOL PHP branch outside documented affected ranges; "
                "no upstream fixed release. Verify vendor backports and migrate "
                "to a supported branch; EOL alone is not a CVE match."
            ),
        )
    branch = f"{parsed[0]}.{parsed[1]}"
    release = next((entry for entry in metadata.affected if entry.branch == branch), None)
    if release is None or branch not in {"8.2", "8.3", "8.4", "8.5"}:
        return replace(
            assessment,
            reason=f"No documented affected range for PHP {branch} in snapshot.",
        )
    assessment = replace(assessment, affected_range=release.range)
    bounds = re.fullmatch(r">=([0-9]+\.[0-9]+\.[0-9]+) <([0-9]+\.[0-9]+\.[0-9]+)", release.range)
    fixed = release.fixed
    parsed_fixed = parse_version(fixed)
    lower = parse_version(bounds[1]) if bounds else None
    if (
        bounds is None
        or lower is None
        or parsed_fixed is None
        or fixed != bounds[2]
        or advisory.fixed_versions.get(branch) != fixed
        or lower[:2] != parsed[:2]
        or parsed_fixed[:2] != parsed[:2]
        or lower >= parsed_fixed
    ):
        return replace(
            assessment,
            reason=f"No usable documented fixed/range rule for PHP {branch}.",
        )
    matched = lower <= parsed < parsed_fixed
    if parsed < lower:
        return replace(
            assessment,
            reason="Observed version precedes the documented affected range.",
        )
    return replace(
        assessment,
        fixed_version=fixed,
        affected_range_match=matched,
        verdict=Verdict.VULNERABLE_VERSION if matched else Verdict.NOT_VULNERABLE_VERSION,
        reason=f"Observed PHP {version} is {'within' if matched else 'outside'} affected range "
        f"{release.range}; fixed release {fixed}. Version evidence is not exploit proof.",
    )


def assess_configuration(advisory: Advisory) -> Assessment:
    """Keep configuration-dependent exposure unconfirmed regardless of version."""
    cve_id = "CVE-2026-115560"
    metadata = advisory.metadata.get(
        cve_id, CveMetadata(Assessment(cve_id, Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN, ""))
    )
    return replace(
        metadata.assessment,
        reason=(
            "Configuration-dependent issue; remote version fingerprinting cannot confirm "
            "the required session.serialize_handler and session.upload_progress conditions."
        ),
        fixed_version=None,
        configuration_dependent=True,
        basis=AssessmentBasis.UNVERIFIED_CONFIGURATION,
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
