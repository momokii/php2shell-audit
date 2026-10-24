"""Offline scanner contracts exercised through HTTP transport and public results."""

import json
from collections.abc import Iterator
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path

import httpx
import pytest

from php2shell_audit.advisory import load_advisories
from php2shell_audit.models import JsonValue, ScanConfig, ScanReport, Severity, Target, Verdict
from php2shell_audit.recon import BudgetExceeded
from php2shell_audit.safety import AuthorizationError, SafetyError
from php2shell_audit.scanner import Scanner


@pytest.mark.parametrize(
    ("version", "verdict"),
    [("8.4.26", Verdict.VULNERABLE_VERSION), ("8.4.27", Verdict.NOT_VULNERABLE_VERSION)],
)
def test_version_assessment_excludes_configuration_unknown(version: str, verdict: Verdict) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, headers={"X-Powered-By": f"PHP/{version}"})
    )
    with Scanner(
        ScanConfig(authorized=True),
        transport=transport,
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test"))

    assert result.verdict is verdict
    assert result.php.version == version
    assert len(result.assessments) == 3
    assert [item.configuration_dependent for item in result.assessments] == [False, False, True]
    assert any(item.title == "PHP version disclosed" for item in result.findings)
    assert result.requests_made == 1
    json.dumps(result.to_dict())


@pytest.mark.parametrize(
    ("headers", "status", "verdict", "error", "assessment_count"),
    [
        ({}, 200, Verdict.NOT_PHP, None, 0),
        (
            {"Set-Cookie": "PHPSESSID=secret"},
            200,
            Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN,
            None,
            3,
        ),
        ({"CF-Ray": "fixture"}, 403, Verdict.WAF_BLOCKED, None, 0),
        ({}, 500, Verdict.UNREACHABLE, "http_status_500", 0),
        (
            {"X-Powered-By": "PHP/8.4.27", "CF-Ray": "fixture"},
            403,
            Verdict.NOT_VULNERABLE_VERSION,
            None,
            3,
        ),
    ],
)
def test_response_outcomes(
    headers: dict[str, str],
    status: int,
    verdict: Verdict,
    error: str | None,
    assessment_count: int,
) -> None:
    with Scanner(
        ScanConfig(authorized=True),
        transport=httpx.MockTransport(lambda request: httpx.Response(status, headers=headers)),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test"))

    assert (result.verdict, result.error) == (verdict, error)
    assert len(result.assessments) == assessment_count
    if assessment_count:
        assert result.assessments[-1].configuration_dependent
    if verdict is Verdict.WAF_BLOCKED:
        assert any("WAF" in item.title for item in result.findings)
    assert "secret" not in json.dumps(result.to_dict())


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        (httpx.ConnectTimeout("fixture"), "timeout"),
        (httpx.ConnectError("fixture"), "connect_error"),
        (httpx.RemoteProtocolError("fixture"), "http_error"),
        (BudgetExceeded(), "request_budget_exhausted"),
        (RuntimeError("sensitive-exception-message"), "unexpected_error"),
    ],
)
def test_request_errors_return_safe_results(failure: Exception, code: str) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise failure

    sink = EventSink()
    with Scanner(
        ScanConfig(authorized=True),
        logger=sink,
        transport=httpx.MockTransport(handle),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test"))

    assert (result.verdict, result.error) == (Verdict.UNREACHABLE, code)
    assert "sensitive-exception-message" not in json.dumps([result.to_dict(), sink.events])


@pytest.mark.parametrize("allow_private", [False, True])
def test_private_resolution_requires_opt_in(allow_private: bool) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200)

    with Scanner(
        ScanConfig(authorized=True, allow_private=allow_private),
        transport=httpx.MockTransport(handle),
        resolver=lambda host: ("127.0.0.1",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test"))

    assert len(requests) == int(allow_private)
    assert result.verdict is (Verdict.NOT_PHP if allow_private else Verdict.BLOCKED_BY_SAFETY)


def test_private_redirect_is_blocked_before_second_request() -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/"})

    with Scanner(
        ScanConfig(authorized=True),
        transport=httpx.MockTransport(handle),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test"))

    assert result.verdict is Verdict.BLOCKED_BY_SAFETY
    assert len(requests) == 1


@pytest.mark.parametrize("redirect", [False, True])
def test_scope_blocks_before_dns_or_http(tmp_path: Path, redirect: bool) -> None:
    scope = tmp_path / "scope.txt"
    scope.write_text("allowed.test\n", encoding="utf-8")
    requests: list[str] = []
    resolved: list[str] = []

    def resolve(host: str) -> tuple[str, ...]:
        resolved.append(host)
        return ("93.184.216.34",)

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://outside.test/"})

    with Scanner(
        ScanConfig(authorized=True, scope_file=str(scope)),
        transport=httpx.MockTransport(handle),
        resolver=resolve,
    ) as scanner:
        result = scanner.scan(
            Target("https://allowed.test" if redirect else "https://outside.test")
        )

    assert (result.verdict, result.error) == (Verdict.BLOCKED_BY_SAFETY, "out_of_scope")
    assert len(requests) == int(redirect)
    assert resolved == (["allowed.test"] if redirect else [])


@pytest.mark.parametrize("many", [False, True])
def test_authorization_precedes_iteration_dns_and_http(many: bool) -> None:
    def resolve(host: str) -> tuple[str, ...]:
        pytest.fail("Unauthorized DNS")

    def handle(request: httpx.Request) -> httpx.Response:
        pytest.fail("Unauthorized HTTP")

    def targets() -> Iterator[Target]:
        pytest.fail("Unauthorized iteration")
        yield Target("https://example.test")

    with Scanner(ScanConfig(), transport=httpx.MockTransport(handle), resolver=resolve) as scanner:
        with pytest.raises(AuthorizationError):
            if many:
                scanner.scan_many(targets())
            else:
                scanner.scan(Target("https://example.test"))


def test_deep_findings_keep_only_bounded_metadata() -> None:
    requests: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        assert request.method == "GET"
        assert "cookie" not in request.headers and "authorization" not in request.headers
        if request.url.query:
            return httpx.Response(200, headers={"Content-Type": "image/gif"})
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html", "Set-Cookie": "fixture=secret"},
            text="PHP Version phpinfo sensitive-body",
        )

    with Scanner(
        ScanConfig(authorized=True, deep=True),
        transport=httpx.MockTransport(handle),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test"))

    assert result.requests_made == len(requests) == 4
    high = [item for item in result.findings if item.severity is Severity.HIGH]
    assert [item.title for item in high] == [
        "PHP configuration file may be exposed",
        "phpinfo page may be exposed",
    ]
    assert high[0].evidence[0].value == "200"
    assert any(item.title == "PHP Easter egg endpoint accessible" for item in result.findings)
    assert result.php.version is None
    serialized = json.dumps(result.to_dict())
    assert "sensitive-body" not in serialized and "secret" not in serialized


@pytest.mark.parametrize("budget", [0, 1, 2])
def test_deep_probes_respect_budget(budget: int) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200)

    with Scanner(
        ScanConfig(authorized=True, deep=True, max_requests=budget),
        transport=httpx.MockTransport(handle),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test"))

    assert len(requests) == result.requests_made == budget
    assert result.verdict is (Verdict.NOT_PHP if budget else Verdict.UNREACHABLE)


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ReadTimeout("fixture"),
        SafetyError("blocked", "fixture"),
        ValueError("fixture"),
        OSError("fixture"),
    ],
)
def test_deep_probe_errors_preserve_root_result(failure: Exception) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.user.ini":
            raise failure
        return httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.27"})

    with Scanner(
        ScanConfig(authorized=True, deep=True),
        transport=httpx.MockTransport(handle),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test"))

    assert (result.verdict, result.error) == (Verdict.NOT_VULNERABLE_VERSION, None)


class EventSink:
    def __init__(self) -> None:
        self.events: list[dict[str, JsonValue]] = []

    def event(self, name: str, **fields: JsonValue) -> None:
        self.events.append({"event": name, **fields})


def test_events_and_results_are_json_safe_and_redacted() -> None:
    sink = EventSink()
    with Scanner(
        ScanConfig(authorized=True),
        logger=sink,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"Set-Cookie": "PHPSESSID=secret", "Authorization": "Bearer fixture-auth"},
                text="fixture-body",
            )
        ),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test/?token=fixture-query"))

    assert [item["event"] for item in sink.events] == ["scan.start", "scan.request", "scan.result"]
    serialized = json.dumps([result.to_dict(), sink.events])
    assert all(
        value not in serialized
        for value in (
            "secret",
            "fixture-auth",
            "fixture-body",
            "fixture-query",
        )
    )
    assert {item.source for item in result.evidence} >= {
        "cookie:PHPSESSID",
        "response:status",
        "response:final_url",
    }


@pytest.mark.parametrize("count", [0, 2])
def test_scan_many_consumes_once_preserves_order_and_closes(count: int) -> None:
    consumed: list[int] = []

    class ClosingTransport(httpx.MockTransport):
        closed = False

        def close(self) -> None:
            self.closed = True

    transport = ClosingTransport(lambda request: httpx.Response(200))

    def targets() -> Iterator[Target]:
        for number in range(count):
            consumed.append(number)
            yield Target(f"https://target-{number}.test")

    with Scanner(
        ScanConfig(authorized=True, max_requests=1),
        transport=transport,
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        report = scanner.scan_many(targets())

    assert isinstance(report, ScanReport)
    assert consumed == list(range(count))
    assert [item.target.url for item in report.results] == [
        f"https://target-{number}.test" for number in range(count)
    ]
    assert all(item.requests_made == 1 for item in report.results)
    assert report.started_at is not None and report.finished_at is not None
    start, finish = (
        datetime.fromisoformat(report.started_at),
        datetime.fromisoformat(report.finished_at),
    )
    assert start <= finish and start.utcoffset() == finish.utcoffset() == timedelta(0)
    assert transport.closed is bool(count)


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit()])
def test_scan_many_closes_on_process_interrupt(failure: BaseException) -> None:
    class ClosingTransport(httpx.MockTransport):
        closed = False

        def close(self) -> None:
            self.closed = True

    def handle(request: httpx.Request) -> httpx.Response:
        raise failure

    transport = ClosingTransport(handle)
    scanner = Scanner(
        ScanConfig(authorized=True),
        transport=transport,
        resolver=lambda host: ("93.184.216.34",),
    )
    with pytest.raises(type(failure)):
        scanner.scan_many([Target("https://example.test")])
    assert transport.closed
    scanner.close()


def test_constructor_performs_no_dns_or_http() -> None:
    def resolve(host: str) -> tuple[str, ...]:
        pytest.fail("Constructor resolved a hostname")

    def handle(request: httpx.Request) -> httpx.Response:
        pytest.fail("Constructor sent a request")

    with Scanner(ScanConfig(), transport=httpx.MockTransport(handle), resolver=resolve):
        pass


def test_present_baseline_headers_do_not_create_missing_header_finding() -> None:
    headers = dict.fromkeys(
        [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
        ],
        "fixture",
    )
    with Scanner(
        ScanConfig(authorized=True),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, headers=headers)),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test"))

    assert result.findings == ()


def test_redirect_evidence_uses_sanitized_actual_request_context() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(302, headers={"Location": "/php?token=redirect-secret"})
        return httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.26"}, content=b"abcdefgh")

    with Scanner(
        ScanConfig(authorized=True, max_response_bytes=4, rate_limit=0),
        transport=httpx.MockTransport(handle),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        result = scanner.scan(Target("https://example.test/path?token=target-secret"))

    evidence = result.php.evidence
    context = evidence[0].request
    assert context is not None
    assert context.method == "GET" and context.requested_url == "https://example.test/"
    assert context.final_url == "https://example.test/php"
    assert context.status_code == 200 and context.body_prefix_bytes == 4
    assert context.body_truncated is True
    assert datetime.fromisoformat(context.observed_at).utcoffset() == timedelta(0)
    assert result.assessments[0].evidence is evidence
    assert result.assessments[1].evidence is evidence
    assert result.assessments[2].evidence == ()
    assert result.requests_made == 2
    serialized = json.dumps(result.to_dict())
    assert all(value not in serialized for value in ("target-secret", "redirect-secret", "abcd"))


def test_scan_provenance_comes_from_selected_snapshot(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-01-02",
            "fixed_versions": {},
            "cves": {},
            "mitigations": [],
            "references": [],
        }
    ).encode()
    path = tmp_path / "custom.json"
    path.write_bytes(payload)
    custom = load_advisories(path)
    with Scanner(
        ScanConfig(authorized=True),
        advisory=custom,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.26"})
        ),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        report = scanner.scan_many([Target("https://example.test")])

    assert report.advisory is not None
    assert report.advisory.snapshot_sha256 == custom.snapshot_sha256 == sha256(payload).hexdigest()
    assert report.advisory.snapshot_date == "2026-01-02"
    assert report.results[0].assessments[0].references == ()
