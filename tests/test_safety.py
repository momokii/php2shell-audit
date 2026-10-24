"""Offline behavioral contracts for the audit trust boundary."""

import socket
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from php2shell_audit import safety
from php2shell_audit.models import ScanConfig, Target
from php2shell_audit.safety import (
    AuthorizationError,
    SafetyError,
    assert_in_scope,
    is_public_ip,
    load_scope,
    normalize_target,
    redact_header,
    redact_url,
    require_authorization,
    resolve_host,
    validate_target,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" example.com ", "https://example.com"),
        ("http://example.com/path", "http://example.com/path"),
        ("https://example.com", "https://example.com"),
        ("HTTPS://EXAMPLE.COM", "https://example.com"),
        ("example.com:8443/path?", "https://example.com:8443/path"),
        ("https://b\u00fccher.example", "https://xn--bcher-kva.example"),
        ("https://[2606:4700:4700::1111]:443/", "https://[2606:4700:4700::1111]:443/"),
        ("example.com./?a=1", "https://example.com/?a=1"),
    ],
)
def test_normalize_target_when_valid(raw: str, expected: str) -> None:
    assert normalize_target(raw) == Target(expected)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "  ",
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://example.com/#fragment",
        "https://example.com/#",
        "https:///path",
        "https://exa mple.com",
        "https://example.com/a\nb",
        "https://example.com/\x7f",
        "https://example.com/\x80",
        "https://example.com..",
        "https://example.com:65536",
        "https://example.com:bad",
        "https://[::1",
        "https://example.com\\@other.com",
        "https://bad_label.example",
        "https://" + "a" * 64 + ".com",
        "https://" + ".".join(["a" * 63] * 4),
        "https://[fe80::1%25eth0]",
        "https://example.com:",
    ],
)
def test_normalize_target_rejects_when_malformed(raw: str) -> None:
    with pytest.raises(SafetyError):
        normalize_target(raw)


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_is_public_ip_when_globally_routable(address: str) -> None:
    assert is_public_ip(address)


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        str(IPv4Address(0)),
        "::1",
        "fc00::1",
        "fe80::1",
        "240.0.0.1",
        "100.64.0.1",
        "ff02::1",
        "not-an-ip",
    ],
)
def test_is_public_ip_rejects_when_not_public_unicast(address: str) -> None:
    assert not is_public_ip(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700:4700::1111"])
def test_validate_target_accepts_when_public(address: str) -> None:
    assert validate_target(Target("https://example.com"), resolver=lambda host: (address,)) is None


@pytest.mark.parametrize("address", ["10.0.0.1", "127.0.0.1", "::1", "fc00::1", "172.18.0.2"])
def test_validate_target_requires_opt_in_when_private(address: str) -> None:
    target = Target("https://example.com")
    with pytest.raises(SafetyError):
        validate_target(target, resolver=lambda host: (address,))
    assert validate_target(target, allow_private=True, resolver=lambda host: (address,)) is None


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",
        "fd00:ec2::254",
        "169.254.1.1",
        "224.0.0.1",
        str(IPv4Address(0)),
        "240.0.0.1",
        "fe80::1",
        "::",
        "ff02::1",
        "192.0.2.1",
    ],
)
@pytest.mark.parametrize("allow_private", [False, True])
def test_validate_target_blocks_when_forbidden_address(address: str, allow_private: bool) -> None:
    with pytest.raises(SafetyError):
        validate_target(
            Target("https://example.com"),
            allow_private=allow_private,
            resolver=lambda host: (address,),
        )


@pytest.mark.parametrize(
    "host",
    ["metadata.google.internal", "metadata.azure.internal", "169.254.169.254", "[fd00:ec2::254]"],
)
def test_validate_target_blocks_metadata_even_when_resolver_returns_public(host: str) -> None:
    with pytest.raises(SafetyError):
        validate_target(
            Target(f"https://{host}"), allow_private=True, resolver=lambda host: ("8.8.8.8",)
        )


@pytest.mark.parametrize("host", ["localhost", "app.local", "app.internal", "app.localhost"])
def test_validate_target_rejects_private_names_when_not_opted_in(host: str) -> None:
    with pytest.raises(SafetyError):
        validate_target(Target(f"https://{host}"), resolver=lambda host: ("8.8.8.8",))


def test_validate_target_rejects_when_resolution_mixes_public_and_private() -> None:
    with pytest.raises(SafetyError):
        validate_target(
            Target("https://example.com"), resolver=lambda host: ("8.8.8.8", "10.0.0.1")
        )


def test_validate_target_raises_stable_reason_when_dns_fails() -> None:
    def failing_resolver(host: str) -> tuple[str, ...]:
        raise socket.gaierror(socket.EAI_NONAME, "fixture failure")

    with pytest.raises(SafetyError) as caught:
        validate_target(Target("https://example.com"), resolver=failing_resolver)
    assert caught.value.reason == "dns_resolution_failed"


def test_validate_target_rejects_when_dns_returns_no_addresses() -> None:
    with pytest.raises(SafetyError) as caught:
        validate_target(Target("https://example.com"), resolver=lambda host: ())
    assert caught.value.reason == "dns_resolution_failed"


def test_validate_target_rejects_when_dns_returns_invalid_address() -> None:
    with pytest.raises(SafetyError) as caught:
        validate_target(Target("https://example.com"), resolver=lambda host: ("invalid",))
    assert caught.value.reason == "dns_resolution_failed"


@pytest.mark.parametrize("raw", ["ftp://example.com", "https://user:pass@example.com"])
def test_validate_target_rejects_when_target_bypasses_normalization(raw: str) -> None:
    with pytest.raises(SafetyError):
        validate_target(Target(raw), resolver=lambda host: ("8.8.8.8",))


def test_validate_target_uses_default_resolver_when_not_injected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(safety, "resolve_host", lambda host: ("127.0.0.1",))
    assert validate_target(Target("https://localhost"), allow_private=True) is None


def test_resolve_host_collects_all_unique_records_when_dns_has_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def records(
        host: str, port: int | None, **kwargs: int
    ) -> list[tuple[int, int, int, str, tuple[str, int] | tuple[str, int, int, int]]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", records)
    assert set(resolve_host("example.com")) == {"8.8.8.8", "2606:4700:4700::1111"}


def test_resolve_host_wraps_failure_when_socket_cannot_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failing_lookup(host: str, port: int | None, **kwargs: int) -> list[tuple[str, ...]]:
        raise socket.gaierror(socket.EAI_NONAME, "fixture failure")

    monkeypatch.setattr(socket, "getaddrinfo", failing_lookup)
    with pytest.raises(SafetyError) as caught:
        resolve_host("example.com")
    assert caught.value.reason == "dns_resolution_failed"


def test_load_scope_normalizes_when_file_contains_comments_and_urls(tmp_path: Path) -> None:
    path = tmp_path / "scope.txt"
    path.write_text(
        "# comment\n\n EXAMPLE.COM. \nhttps://B.Example.org:443/path\n127.0.0.1\n::1\n",
        encoding="utf-8",
    )
    assert load_scope(str(path)) == frozenset({"example.com", "b.example.org", "127.0.0.1", "::1"})
    assert load_scope(path) == load_scope(str(path))


def test_load_scope_raises_stable_reason_when_unreadable(tmp_path: Path) -> None:
    with pytest.raises(SafetyError) as caught:
        load_scope(tmp_path / "missing")
    assert caught.value.reason == "scope_read_failed"


@pytest.mark.parametrize("host", ["example.com", "www.example.com", "WWW.EXAMPLE.COM."])
def test_assert_in_scope_accepts_when_exact_or_subdomain(host: str) -> None:
    assert assert_in_scope(Target(f"https://{host}"), frozenset({"example.com"})) is None


@pytest.mark.parametrize("host", ["evil-example.com", "example.org", "example.com.evil.org"])
def test_assert_in_scope_rejects_when_unrelated(host: str) -> None:
    with pytest.raises(SafetyError) as caught:
        assert_in_scope(Target(f"https://{host}"), frozenset({"example.com"}))
    assert caught.value.reason == "out_of_scope"


def test_assert_in_scope_accepts_when_scope_empty() -> None:
    assert assert_in_scope(Target("https://example.org"), frozenset()) is None


def test_require_authorization_rejects_when_consent_missing() -> None:
    with pytest.raises(AuthorizationError) as caught:
        require_authorization(ScanConfig())
    assert caught.value.reason == "authorization_required"


def test_require_authorization_accepts_when_consent_given() -> None:
    assert require_authorization(ScanConfig(authorized=True)) is None


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("Set-Cookie", "PHPSESSID=fixture; Secure; HttpOnly", "PHPSESSID=<redacted>"),
        ("set-cookie", "malformed", "<redacted>"),
        ("Authorization", "fixture", "<redacted>"),
        ("Proxy-Authorization", "fixture", "<redacted>"),
        ("X-Api-Key", "fixture", "<redacted>"),
        ("X-Auth-Token", "fixture", "<redacted>"),
        ("Cookie", "fixture", "<redacted>"),
        ("X-Secret", "fixture", "<redacted>"),
        ("Server", "Apache", "Apache"),
    ],
)
def test_redact_header_when_sensitive_or_safe(name: str, value: str, expected: str) -> None:
    assert redact_header(name, value) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://user:pass@example.com:8443/path?token=fixture#part",
            "https://example.com:8443/path",
        ),
        ("https://user:pass@[::1]:443/path?q=fixture", "https://[::1]:443/path"),
        ("not-a-url", "<redacted-url>"),
        ("https://[broken", "<redacted-url>"),
        ("https://example.com:bad", "<redacted-url>"),
        ("ftp://example.com", "<redacted-url>"),
    ],
)
def test_redact_url_when_valid_or_malformed(url: str, expected: str) -> None:
    assert redact_url(url) == expected
