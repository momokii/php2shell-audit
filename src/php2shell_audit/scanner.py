"""Authorization-gated, detection-only orchestration with redacted observations."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Final, Protocol

import httpx

from php2shell_audit.advisory import (
    Advisory,
    assess_configuration,
    assess_php,
    load_advisories,
    overall_verdict,
)
from php2shell_audit.fingerprint import detect_php, detect_waf, header_values
from php2shell_audit.models import (
    Evidence,
    Finding,
    JsonValue,
    ScanConfig,
    ScanReport,
    Severity,
    Target,
    TargetResult,
    Verdict,
    Waf,
)
from php2shell_audit.recon import BudgetExceeded, HttpRecon, ReconResponse
from php2shell_audit.safety import (
    SafetyError,
    assert_in_scope,
    load_scope,
    normalize_target,
    redact_url,
    require_authorization,
    validate_target,
)

_BASELINE_HEADERS: Final = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)
_DEEP_PATHS: Final = (
    "/.user.ini",
    "/phpinfo.php",
    "/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42",
)


class AuditSink(Protocol):
    """Structured event boundary accepting only JSON-compatible fields."""

    def event(self, name: str, **fields: JsonValue) -> None: ...


class _FingerprintView:
    def __init__(self, response: ReconResponse) -> None:
        self.status_code = response.status_code
        self.headers = response.headers
        self.body_text = response.body_text
        self.final_url = response.final_url


def _error_code(error: Exception) -> str:
    if isinstance(error, SafetyError):
        return error.reason
    if isinstance(error, BudgetExceeded):
        return "request_budget_exhausted"
    if isinstance(error, httpx.TimeoutException):
        return "timeout"
    if isinstance(error, httpx.ConnectError):
        return "connect_error"
    if isinstance(error, httpx.HTTPError):
        return "http_error"
    return "unexpected_error"


class Scanner:
    """Reuse a lazy recon client; authorization always precedes DNS and HTTP."""

    def __init__(
        self,
        config: ScanConfig,
        *,
        logger: AuditSink | None = None,
        transport: httpx.BaseTransport | None = None,
        advisory: Advisory | None = None,
        resolver: Callable[[str], tuple[str, ...]] | None = None,
    ) -> None:
        self._config = config
        self._logger = logger
        self._transport = transport
        self._resolver = resolver
        self._advisory = advisory if advisory is not None else load_advisories()
        self._scope = load_scope(config.scope_file) if config.scope_file else frozenset()
        self._recon: HttpRecon | None = None

    def _event(self, name: str, **fields: JsonValue) -> None:
        if self._logger is not None:
            self._logger.event(name, **fields)

    def _validate_redirect(self, url: str) -> None:
        target = normalize_target(url)
        assert_in_scope(target, self._scope)
        validate_target(target, allow_private=self._config.allow_private, resolver=self._resolver)

    def _fetch(self, target: Target, path: str) -> ReconResponse:
        if self._recon is None:
            self._recon = HttpRecon(
                self._config,
                transport=self._transport,
                redirect_validator=self._validate_redirect,
            )
        response = self._recon.fetch(target, path)
        self._event(
            "scan.request",
            target=redact_url(target.url),
            path=path,
            status=response.status_code,
            requests=response.requests_made,
        )
        return response

    def scan(self, target: Target) -> TargetResult:
        """Assess one target; raise for missing consent, return safe failure results otherwise."""
        require_authorization(self._config)
        safe_target = Target(redact_url(target.url))
        self._event("scan.start", target=safe_target.url, deep=self._config.deep)
        try:
            assert_in_scope(target, self._scope)
            validate_target(
                target, allow_private=self._config.allow_private, resolver=self._resolver
            )
            response = self._fetch(target, "/")
            result = self._assess(safe_target, response, target)
        except Exception as error:
            reason = _error_code(error)
            blocked = isinstance(error, SafetyError)
            if blocked:
                self._event("scan.blocked", target=safe_target.url, reason=reason)
            else:
                self._event(
                    "scan.error",
                    target=safe_target.url,
                    error=reason,
                    exception_type=type(error).__name__,
                )
            result = TargetResult(
                target=safe_target,
                verdict=Verdict.BLOCKED_BY_SAFETY if blocked else Verdict.UNREACHABLE,
                error=reason,
            )
        self._event(
            "scan.result",
            target=safe_target.url,
            verdict=result.verdict.value,
            php_version=result.php.version,
            requests=result.requests_made,
        )
        return result

    def _assess(self, safe_target: Target, response: ReconResponse, target: Target) -> TargetResult:
        view = _FingerprintView(response)
        php = detect_php(view)
        waf = detect_waf(view)
        versions = assess_php(php.version, self._advisory) if php.detected else ()
        assessments = (*versions, assess_configuration(self._advisory)) if php.detected else ()
        verdict = overall_verdict(php, versions)
        findings: list[Finding] = []
        error = None
        if php.version is not None:
            findings.append(
                Finding(
                    "PHP version disclosed",
                    Severity.INFO,
                    "A PHP version banner was observed; this is not proof of exploitability.",
                    php.evidence,
                    "Disable expose_php or remove the version header.",
                )
            )
        elif php.detected:
            findings.append(
                Finding(
                    "PHP detected without a version",
                    Severity.INFO,
                    "Version-based exposure cannot be ruled out.",
                    php.evidence,
                )
            )
        if waf is not Waf.NONE:
            findings.append(
                Finding(
                    "WAF or CDN detected",
                    Severity.INFO,
                    f"Observed {waf.value}; presence is not proof of protection.",
                )
            )
        if response.status_code >= 400 and php.version is None:
            verdict = Verdict.UNREACHABLE
            error = f"http_status_{response.status_code}"
        if (
            response.status_code in {403, 406, 429, 503}
            and waf is not Waf.NONE
            and php.version is None
        ):
            verdict = Verdict.WAF_BLOCKED
            error = None
            findings.append(
                Finding(
                    "WAF or CDN may be blocking assessment",
                    Severity.INFO,
                    "The HTTP response and intermediary indicators prevent a version conclusion.",
                    (Evidence("response:status", str(response.status_code)),),
                )
            )
        missing = [name for name in _BASELINE_HEADERS if not header_values(response.headers, name)]
        if missing:
            findings.append(
                Finding(
                    "Missing baseline security headers",
                    Severity.LOW,
                    "Missing: " + ", ".join(missing) + ". Separate from CVE version assessments.",
                    mitigation="Configure security headers appropriate for the application.",
                )
            )
        requests = response.requests_made
        if self._config.deep:
            deep_findings, deep_requests = self._probe(target)
            findings.extend(deep_findings)
            requests += deep_requests
        return TargetResult(
            target=safe_target,
            verdict=verdict,
            php=php,
            waf=waf,
            assessments=assessments,
            findings=tuple(findings),
            requests_made=requests,
            error=error,
            evidence=(
                *php.evidence,
                Evidence("response:status", str(response.status_code)),
                Evidence("response:final_url", redact_url(response.final_url)),
            ),
        )

    def _probe(self, target: Target) -> tuple[list[Finding], int]:
        findings: list[Finding] = []
        requests = 0
        for path in _DEEP_PATHS:
            try:
                response = self._fetch(target, path)
            except (BudgetExceeded, httpx.HTTPError, SafetyError, ValueError, OSError) as error:
                self._event("scan.error", target=redact_url(target.url), error=_error_code(error))
                if isinstance(error, (BudgetExceeded, SafetyError)):
                    break
                continue
            requests += response.requests_made
            if response.status_code != 200:
                continue
            content_type = next(iter(header_values(response.headers, "content-type")), "")
            evidence = (Evidence("response:status", "200"),)
            if path == "/.user.ini":
                findings.append(
                    Finding(
                        "PHP configuration file may be exposed",
                        Severity.HIGH,
                        "The configuration path returned status=200; contents were not retained.",
                        evidence,
                        "Deny web access to PHP configuration files.",
                    )
                )
            elif path == "/phpinfo.php" and (
                "phpinfo" in response.body_text.casefold() or "PHP Version" in response.body_text
            ):
                findings.append(
                    Finding(
                        "phpinfo page may be exposed",
                        Severity.HIGH,
                        "A PHP diagnostic page may disclose runtime configuration.",
                        (*evidence, Evidence("response:content-type", content_type)),
                        "Remove public diagnostic pages.",
                    )
                )
            elif path == _DEEP_PATHS[2] and content_type.casefold().startswith("image/"):
                findings.append(
                    Finding(
                        "PHP Easter egg endpoint accessible",
                        Severity.INFO,
                        "An image response was observed; this does not establish a PHP version.",
                        evidence,
                    )
                )
        return findings, requests

    def scan_many(self, targets: Iterable[Target]) -> ScanReport:
        """Consume targets once in order and always release the shared recon client."""
        try:
            require_authorization(self._config)
            started_at = datetime.now(UTC).isoformat()
            results = tuple(self.scan(target) for target in targets)
            return ScanReport(results, started_at, datetime.now(UTC).isoformat())
        finally:
            self.close()

    def close(self) -> None:
        """Release the lazy recon client; repeated calls are harmless."""
        if self._recon is not None:
            self._recon.close()
            self._recon = None

    def __enter__(self) -> Scanner:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
