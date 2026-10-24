"""Offline contracts for bounded HTTP observations."""

from collections.abc import Iterator

import httpx
import pytest

from php2shell_audit.models import ScanConfig, Target
from php2shell_audit.recon import BudgetExceeded, HttpRecon, RequestBudget


def test_get_returns_observation() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(200, headers=[("X-PHP-Version", "8.4.27")], content=b"hello")

    with HttpRecon(ScanConfig(), transport=httpx.MockTransport(handle)) as recon:
        result = recon.fetch(Target("https://example.test/base"), "/index.php")

    assert result.status_code == 200
    assert ("X-PHP-Version", "8.4.27") in result.headers
    assert result.body == b"hello"
    assert result.body_text == "hello"
    assert result.requested_url == "https://example.test/index.php"
    assert result.final_url == result.requested_url
    assert result.requests_made == 1
    assert result.truncated is False
    assert result.elapsed_ms >= 0


class ObservedStream(httpx.SyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self.chunks = chunks
        self.reads = 0
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("chunks", "expected", "truncated", "reads"),
    [((b"abcd", b"e", b"unread"), b"abcd", True, 2), ((b"abcd",), b"abcd", False, 1)],
)
def test_body_is_bounded(
    chunks: tuple[bytes, ...], expected: bytes, truncated: bool, reads: int
) -> None:
    stream = ObservedStream(chunks)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    with HttpRecon(ScanConfig(max_response_bytes=4), transport=transport) as recon:
        result = recon.fetch(Target("https://example.test"))

    assert result.body == expected
    assert len(result.body) <= 4
    assert result.truncated is truncated
    assert stream.reads == reads
    assert stream.closed


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_is_validated_and_closed_before_following(status: int) -> None:
    stream = ObservedStream((b"do not read redirect bodies",))
    validated: list[str] = []
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(status, headers={"Location": "../done"}, stream=stream)
        assert stream.closed
        assert validated == ["https://example.test/done"]
        return httpx.Response(200, content=b"done")

    with HttpRecon(
        ScanConfig(), transport=httpx.MockTransport(handle), redirect_validator=validated.append
    ) as recon:
        result = recon.fetch(Target("https://example.test"), "/start/here")

    assert result.final_url == "https://example.test/done"
    assert result.requests_made == 2
    assert [request.method for request in requests] == ["GET", "GET"]
    assert stream.reads == 0


@pytest.mark.parametrize(
    "destination", ["ftp://example.test/file", "https://user@example.test/", "//user@other.test/"]
)
def test_unsafe_redirect_is_rejected(destination: str) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"Location": destination})

    with HttpRecon(ScanConfig(), transport=httpx.MockTransport(handle)) as recon:
        with pytest.raises(ValueError, match="HTTP|userinfo"):
            recon.fetch(Target("https://example.test"))

    assert len(requests) == 1


def test_redirect_limit_prevents_extra_request() -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(301, headers={"Location": "/loop"})

    with HttpRecon(ScanConfig(max_redirects=1), transport=httpx.MockTransport(handle)) as recon:
        with pytest.raises(httpx.TooManyRedirects):
            recon.fetch(Target("https://example.test"))

    assert len(requests) == 2


def test_redirect_validator_failure_propagates_unchanged() -> None:
    failure = RuntimeError("blocked by scope")
    stream = ObservedStream(())

    def validate(destination: str) -> None:
        raise failure

    transport = httpx.MockTransport(
        lambda request: httpx.Response(302, headers={"Location": "/blocked"}, stream=stream)
    )
    with HttpRecon(ScanConfig(), transport=transport, redirect_validator=validate) as recon:
        with pytest.raises(RuntimeError) as raised:
            recon.fetch(Target("https://example.test"))

    assert raised.value is failure
    assert stream.closed


def test_head_does_not_read_body() -> None:
    stream = ObservedStream((b"must not be read",))

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "HEAD"
        return httpx.Response(200, stream=stream)

    with HttpRecon(ScanConfig(), transport=httpx.MockTransport(handle)) as recon:
        result = recon.fetch_headers(Target("https://example.test"))

    assert (result.body, result.body_text, result.truncated) == (b"", "", False)
    assert result.requests_made == 1
    assert stream.reads == 0
    assert stream.closed


@pytest.mark.parametrize("status", [405, 501])
def test_head_fallback_is_bounded_and_counted(status: int) -> None:
    methods: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(status if request.method == "HEAD" else 200, content=b"abcdef")

    with HttpRecon(
        ScanConfig(max_response_bytes=3), transport=httpx.MockTransport(handle)
    ) as recon:
        result = recon.fetch_headers(Target("https://example.test"))

    assert methods == ["HEAD", "GET"]
    assert (result.body, result.truncated, result.requests_made) == (b"abc", True, 2)


@pytest.mark.parametrize("operation", ["zero", "repeat", "redirect", "fallback"])
def test_budget_exhaustion_prevents_sending_request(operation: str) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if operation == "redirect":
            return httpx.Response(302, headers={"Location": "/next"})
        return httpx.Response(405 if operation == "fallback" else 200)

    target = Target("https://example.test")
    config = ScanConfig(max_requests=0 if operation == "zero" else 1)
    with HttpRecon(config, transport=httpx.MockTransport(handle)) as recon:
        if operation == "repeat":
            recon.fetch(target)
        with pytest.raises(BudgetExceeded):
            if operation == "fallback":
                recon.fetch_headers(target)
            else:
                recon.fetch(target)

    assert len(requests) == (0 if operation == "zero" else 1)


def test_budget_counter_tracks_consumption() -> None:
    budget = RequestBudget(1)
    assert (budget.used, budget.remaining) == (0, 1)
    budget.consume()

    with pytest.raises(BudgetExceeded):
        budget.consume()

    assert (budget.used, budget.remaining) == (1, 0)


def test_budgets_are_separate_for_each_target() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    with HttpRecon(ScanConfig(max_requests=1), transport=transport) as recon:
        first = recon.fetch(Target("https://first.test"))
        second = recon.fetch(Target("https://second.test"))

    assert (first.requests_made, second.requests_made) == (1, 1)


def test_requests_never_send_cookies_or_ambient_headers() -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                302, headers={"Location": "/done", "Set-Cookie": "fixture=value; Path=/"}
            )
        return httpx.Response(200, headers={"Set-Cookie": "fixture=value; Path=/"})

    with HttpRecon(ScanConfig(), transport=httpx.MockTransport(handle)) as recon:
        recon.fetch(Target("https://example.test"))
        recon.fetch(Target("https://example.test"))
        assert not recon._client.cookies

    assert len(requests) == 3
    for request in requests:
        assert request.headers["User-Agent"].startswith("php2shell-audit/")
        assert {"cookie", "authorization", "proxy-authorization", "referer"}.isdisjoint(
            request.headers
        )


def test_client_disables_environment_and_automatic_redirects() -> None:
    with HttpRecon(
        ScanConfig(), transport=httpx.MockTransport(lambda request: httpx.Response(200))
    ) as recon:
        assert recon._client.trust_env is False
        assert recon._client.follow_redirects is False
    assert recon._client.is_closed


@pytest.mark.parametrize(
    "path",
    [
        "../etc/passwd",
        "/../etc/passwd",
        "/%2e%2e/etc",
        "https://other.test/",
        "//other.test/",
        "/\\other.test/",
    ],
)
def test_unsafe_paths_are_rejected_before_sending(path: str) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        pytest.fail("Unsafe paths must not send requests")

    with HttpRecon(ScanConfig(), transport=httpx.MockTransport(handle)) as recon:
        with pytest.raises(ValueError, match="root-relative"):
            recon.fetch(Target("https://example.test"), path)


@pytest.mark.parametrize(
    ("charset", "body", "expected"),
    [("iso-8859-1", b"caf\xe9", "caf\u00e9"), ("not-an-encoding", b"\xff", "\ufffd")],
)
def test_body_decoding_uses_charset_or_utf8_replacement(
    charset: str, body: bytes, expected: str
) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, headers={"Content-Type": f"text/plain; charset={charset}"}, content=body
        )
    )
    with HttpRecon(ScanConfig(), transport=transport) as recon:
        result = recon.fetch(Target("https://example.test"))

    assert result.body_text == expected


def test_headers_preserve_duplicates_and_case() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, headers=[("X-Test", "one"), ("x-test", "two")])
    )
    with HttpRecon(ScanConfig(), transport=transport) as recon:
        result = recon.fetch(Target("https://example.test"))

    assert result.headers[:2] == (("X-Test", "one"), ("x-test", "two"))
