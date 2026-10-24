"""Bounded GET/HEAD observations; callers authorize and validate initial targets."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter
from typing import Literal
from urllib.parse import unquote, urljoin, urlsplit

import httpx

from php2shell_audit.models import ScanConfig, Target


class BudgetExceeded(Exception):
    """The target's request allowance has been exhausted."""


@dataclass(frozen=True, slots=True)
class ReconResponse:
    """An in-memory observation containing only a bounded body prefix."""

    requested_url: str
    final_url: str
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    body_text: str
    truncated: bool
    elapsed_ms: float
    requests_made: int


class RequestBudget:
    """Mutable counter shared by all requests for one target."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._used = 0

    @property
    def remaining(self) -> int:
        return max(0, self._limit - self._used)

    @property
    def used(self) -> int:
        return self._used

    def consume(self) -> None:
        """Raise BudgetExceeded when the next request would exceed the limit."""
        if self.remaining == 0:
            raise BudgetExceeded("Per-target request budget exhausted")
        self._used += 1


def _validate_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Recon requires an HTTP(S) URL with a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Recon URLs must not contain userinfo")


def _join_path(target: Target, path: str) -> str:
    parsed = urlsplit(path)
    decoded_path = unquote(parsed.path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or "\\" in decoded_path
        or ".." in decoded_path.split("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise ValueError("Path must be root-relative without traversal or an absolute URL")
    _validate_url(target.url)
    return urljoin(target.url, path)


class HttpRecon:
    """Sequential, cookie-free requests with per-target budgets and checked redirects.

    Initial DNS, authorization, and scope checks belong to the caller. Supply a
    redirect validator to apply those same checks to every redirect destination.
    """

    def __init__(
        self,
        config: ScanConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        redirect_validator: Callable[[str], None] | None = None,
    ) -> None:
        self._config = config
        self._redirect_validator = redirect_validator
        self._budgets: dict[str, RequestBudget] = {}
        self._client = httpx.Client(
            follow_redirects=False,
            max_redirects=config.max_redirects,
            timeout=config.timeout,
            trust_env=False,
            headers={
                "User-Agent": "php2shell-audit/0.1 (+authorized defensive exposure audit)",
            },
            cookies=None,
            transport=transport,
        )
        self._client.cookies.clear()

    def fetch(self, target: Target, path: str = "/") -> ReconResponse:
        """Fetch a bounded GET prefix; validation, budget, and HTTP errors propagate."""
        return self._fetch(target, path, "GET")

    def fetch_headers(self, target: Target, path: str = "/") -> ReconResponse:
        """Try HEAD, falling back to bounded GET only for status 405 or 501."""
        return self._fetch(target, path, "HEAD")

    def _fetch(self, target: Target, path: str, method: Literal["GET", "HEAD"]) -> ReconResponse:
        requested_url = _join_path(target, path)
        budget = self._budgets.setdefault(target.url, RequestBudget(self._config.max_requests))
        used_before = budget.used
        started = perf_counter()
        current_url = requested_url
        current_method = method
        redirects = 0
        while True:
            budget.consume()
            self._client.cookies.clear()
            try:
                with self._client.stream(current_method, current_url) as response:
                    location = response.headers.get("location")
                    if response.status_code in {301, 302, 303, 307, 308} and location is not None:
                        if redirects >= self._config.max_redirects:
                            raise httpx.TooManyRedirects(
                                "Recon redirect limit exceeded", request=response.request
                            )
                        destination = urljoin(str(response.url), location)
                        _validate_url(destination)
                        if self._redirect_validator is not None:
                            self._redirect_validator(destination)
                        current_url = destination
                        redirects += 1
                        if response.status_code == 303:
                            current_method = "GET"
                        continue
                    if current_method == "HEAD" and response.status_code in {405, 501}:
                        current_method = "GET"
                        continue
                    body = bytearray()
                    truncated = False
                    if current_method == "GET":
                        limit = max(0, self._config.max_response_bytes)
                        for chunk in response.iter_bytes(chunk_size=min(limit + 1, 65_536)):
                            remaining = limit - len(body)
                            body.extend(chunk[:remaining])
                            if len(chunk) > remaining:
                                truncated = True
                                break
                    encoding = response.encoding or "utf-8"
                    try:
                        body_text = body.decode(encoding, errors="replace")
                    except LookupError:
                        body_text = body.decode("utf-8", errors="replace")
                    return ReconResponse(
                        requested_url=requested_url,
                        final_url=str(response.url),
                        status_code=response.status_code,
                        headers=tuple(
                            (name.decode("ascii"), value.decode("latin-1"))
                            for name, value in response.headers.raw
                        ),
                        body=bytes(body),
                        body_text=body_text,
                        truncated=truncated,
                        elapsed_ms=(perf_counter() - started) * 1000,
                        requests_made=budget.used - used_before,
                    )
            finally:
                self._client.cookies.clear()

    def close(self) -> None:
        """Release the HTTP client's resources."""
        self._client.close()

    def __enter__(self) -> HttpRecon:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
