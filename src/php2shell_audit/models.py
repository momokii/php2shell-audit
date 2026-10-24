"""Side-effect-free domain values for detection-only PHP assessments.

Constructors accept already-parsed values. ``to_dict`` returns detached,
JSON-compatible data; it does not read configuration or perform I/O.
"""

from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "Assessment",
    "AssessmentBasis",
    "AdvisoryProvenance",
    "Evidence",
    "Finding",
    "JsonValue",
    "PhpInfo",
    "RequestContext",
    "Sapi",
    "ScanConfig",
    "ScanReport",
    "Severity",
    "Target",
    "TargetResult",
    "Verdict",
    "Waf",
]

type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]


class Verdict(StrEnum):
    """Version-based conclusions, never confirmation of exploitability."""

    VULNERABLE_VERSION = "VULNERABLE_VERSION"
    POTENTIALLY_VULNERABLE_VERSION_UNKNOWN = "POTENTIALLY_VULNERABLE_VERSION_UNKNOWN"
    NOT_VULNERABLE_VERSION = "NOT_VULNERABLE_VERSION"
    NOT_PHP = "NOT_PHP"
    UNREACHABLE = "UNREACHABLE"
    BLOCKED_BY_SAFETY = "BLOCKED_BY_SAFETY"
    WAF_BLOCKED = "WAF_BLOCKED"


class Sapi(StrEnum):
    """Observed PHP server interface, or unknown when not established."""

    MOD_PHP = "mod_php"
    FPM = "fpm"
    PHP_CGI = "php_cgi"
    LITESPEED = "litespeed"
    FRANKENPHP = "frankenphp"
    UNKNOWN = "unknown"


class Waf(StrEnum):
    """Observed intermediary; its presence is not proof of protection."""

    NONE = "none"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    CLOUDFRONT = "cloudfront"
    FASTLY = "fastly"
    VERCEL = "vercel"
    SUCURI = "sucuri"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    """Finding severity labels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AssessmentBasis(StrEnum):
    OBSERVED_VERSION = "observed_version"
    UNVERIFIED_CONFIGURATION = "unverified_configuration"


@dataclass(frozen=True, slots=True)
class RequestContext:
    method: str
    requested_url: str
    final_url: str
    status_code: int
    body_prefix_bytes: int
    body_truncated: bool
    observed_at: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "method": self.method,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "body_prefix_bytes": self.body_prefix_bytes,
            "body_truncated": self.body_truncated,
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True, slots=True)
class AdvisoryProvenance:
    schema_version: int
    snapshot_date: str
    snapshot_sha256: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "snapshot_date": self.snapshot_date,
            "snapshot_sha256": self.snapshot_sha256,
        }


@dataclass(frozen=True, slots=True)
class Target:
    """A parsed target URL, without authorization implied by construction."""

    url: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {"url": self.url}


@dataclass(frozen=True, slots=True)
class Evidence:
    """A bounded observation supporting an assessment."""

    source: str
    value: str
    request: RequestContext | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {"source": self.source, "value": self.value}
        if self.request is not None:
            result["request"] = self.request.to_dict()
        return result


@dataclass(frozen=True, slots=True)
class PhpInfo:
    """Detected PHP metadata; missing version is not a safe-version signal."""

    detected: bool = False
    version: str | None = None
    sapi: Sapi = Sapi.UNKNOWN
    evidence: tuple[Evidence, ...] = ()

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "detected": self.detected,
            "version": self.version,
            "sapi": self.sapi.value,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class Assessment:
    """A CVE-specific conclusion with its reasoning and remediation."""

    cve_id: str
    verdict: Verdict
    reason: str
    fixed_version: str | None = None
    configuration_dependent: bool = False
    basis: AssessmentBasis = AssessmentBasis.OBSERVED_VERSION
    observed_version: str | None = None
    affected_range: str | None = None
    affected_range_match: bool | None = None
    evidence: tuple[Evidence, ...] = ()
    remediation: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    title: str = ""
    severity: str | None = None
    rating_notes: str | None = None
    conditions: str | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "cve_id": self.cve_id,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "fixed_version": self.fixed_version,
            "configuration_dependent": self.configuration_dependent,
            "basis": self.basis.value,
            "observed_version": self.observed_version,
            "affected_range": self.affected_range,
            "affected_range_match": self.affected_range_match,
            "evidence": [item.to_dict() for item in self.evidence],
            "remediation": list(self.remediation),
            "verification": list(self.verification),
            "references": list(self.references),
            "title": self.title,
            "severity": self.severity,
            "rating_notes": self.rating_notes,
            "conditions": self.conditions,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """An observed issue, distinct from a version-based CVE assessment."""

    title: str
    severity: Severity
    description: str
    evidence: tuple[Evidence, ...] = ()
    mitigation: str | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": [item.to_dict() for item in self.evidence],
            "mitigation": self.mitigation,
        }


@dataclass(frozen=True, slots=True)
class TargetResult:
    """Detection outcome for one target, including inconclusive outcomes."""

    target: Target
    verdict: Verdict
    php: PhpInfo = PhpInfo()
    waf: Waf = Waf.UNKNOWN
    assessments: tuple[Assessment, ...] = ()
    findings: tuple[Finding, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    requests_made: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "target": self.target.to_dict(),
            "verdict": self.verdict.value,
            "php": self.php.to_dict(),
            "waf": self.waf.value,
            "assessments": [item.to_dict() for item in self.assessments],
            "findings": [item.to_dict() for item in self.findings],
            "evidence": [item.to_dict() for item in self.evidence],
            "requests_made": self.requests_made,
            "error": self.error,
        }


@dataclass(slots=True)
class ScanConfig:
    """Mutable operator options assembled before a scan; no implicit consent."""

    rate_limit: float = 1.0
    timeout: float = 10.0
    max_requests: int = 20
    max_redirects: int = 5
    max_response_bytes: int = 1_048_576
    deep: bool = False
    allow_private: bool = False
    authorized: bool = False
    scope_file: str | None = None
    output_dir: str = "reports"

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "rate_limit": self.rate_limit,
            "timeout": self.timeout,
            "max_requests": self.max_requests,
            "max_redirects": self.max_redirects,
            "max_response_bytes": self.max_response_bytes,
            "deep": self.deep,
            "allow_private": self.allow_private,
            "authorized": self.authorized,
            "scope_file": self.scope_file,
            "output_dir": self.output_dir,
        }


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Immutable scan outcomes with caller-supplied ISO-8601 timestamps."""

    results: tuple[TargetResult, ...] = ()
    started_at: str | None = None
    finished_at: str | None = None
    schema_version: int = 1
    advisory: AdvisoryProvenance | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {
            "schema_version": self.schema_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "results": [item.to_dict() for item in self.results],
        }
        if self.advisory is not None:
            result["advisory"] = self.advisory.to_dict()
        return result
