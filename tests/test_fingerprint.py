"""Public fingerprinting behavior using local response values only."""

import json
from dataclasses import dataclass

import pytest

from php2shell_audit.fingerprint import (
    ResponseView,
    detect_php,
    detect_sapi,
    detect_waf,
    header_values,
    parse_php_version,
)
from php2shell_audit.models import Evidence, PhpInfo, Sapi, Waf


@dataclass(slots=True)
class FakeResponse:
    """Mutable fields match the response protocol without a transport."""

    headers: tuple[tuple[str, str], ...] = ()
    body_text: str = ""
    status_code: int = 200
    final_url: str = "https://example.test/"


@pytest.mark.parametrize(
    "text",
    [
        "PHP/8.4.26",
        "PHP 8.4.26",
        "PHP8.4.26",
        "PHP/8.4.26-1ubuntu1",
        "PHP/8.4.26RC1",
        "php/8.4.26",
        "Apache/2.4.62 PHP/8.4.26",
    ],
)
def test_parse_php_version_extracts_numeric_prefix(text: str) -> None:
    version = parse_php_version(text)
    assert version == "8.4.26"


@pytest.mark.parametrize(
    "text", ["Apache/2.4.62", "nginx/1.24.0", "8.4.26", "", "PHP/8.4", "NotPHP/8.4.26"]
)
def test_parse_php_version_requires_php_token_and_three_components(text: str) -> None:
    version = parse_php_version(text)
    assert version is None


def test_header_values_preserves_duplicates_and_exact_values() -> None:
    headers = (("Server", " Apache "), ("X-Other", "ignored"), ("sErVeR", "nginx"))
    values = header_values(headers, "SERVER")
    assert values == (" Apache ", "nginx")


def test_header_values_returns_empty_tuple_when_missing() -> None:
    values = header_values((("Server", "Apache"),), "x-powered-by")
    assert values == ()


@pytest.mark.parametrize(
    ("name", "value", "source"),
    [
        ("X-Powered-By", "PHP/8.4.26", "header:x-powered-by"),
        ("Server", "Apache/2.4.62 (Debian) PHP/8.4.26", "header:server"),
        ("X-PHP-Version", "8.4.26", "header:x-php-version"),
        ("x-php-version", "8.4.26RC1", "header:x-php-version"),
    ],
)
def test_detect_php_retains_original_version_header(name: str, value: str, source: str) -> None:
    response: ResponseView = FakeResponse(headers=((name, value),))
    info = detect_php(response)
    assert info.detected is True
    assert info.version == "8.4.26"
    assert info.evidence == (Evidence(source=source, value=value),)


def test_detect_php_prioritizes_header_types_then_duplicate_order() -> None:
    response = FakeResponse(
        headers=(
            ("X-PHP-Version", "8.2.35"),
            ("Server", "PHP/8.3.36"),
            ("X-Powered-By", "unrelated"),
            ("x-powered-by", "PHP/8.4.26"),
            ("X-Powered-By", "PHP/8.5.12"),
        )
    )
    info = detect_php(response)
    assert info.version == "8.4.26"
    assert info.evidence == (Evidence(source="header:x-powered-by", value="PHP/8.4.26"),)


def test_detect_php_redacts_session_cookie_in_serialization() -> None:
    response = FakeResponse(
        headers=(
            ("Set-Cookie", "other=unrelated; Path=/"),
            ("Set-Cookie", "PHPSESSID=secret; Path=/; HttpOnly"),
            ("Authorization", "Bearer authorization-fixture"),
        ),
        body_text="private-body-fixture",
    )
    info = detect_php(response)
    assert info == PhpInfo(detected=True, evidence=(Evidence("cookie:PHPSESSID", "<redacted>"),))
    serialized = json.dumps(info.to_dict())
    assert "secret" not in serialized
    assert "authorization-fixture" not in serialized
    assert "private-body-fixture" not in serialized


@pytest.mark.parametrize(
    "cookie",
    ["other=PHPSESSID; Path=/", "other=secret; Path=/PHPSESSID=secret", "XPHPSESSID=secret"],
)
def test_detect_php_requires_session_cookie_name(cookie: str) -> None:
    response = FakeResponse(headers=(("Set-Cookie", cookie),))
    info = detect_php(response)
    assert info == PhpInfo(detected=False)


@pytest.mark.parametrize(
    "body",
    [
        '<meta name="generator" content="PHP 8.4.26">',
        "<meta name='generator' content='PHP/8.4.26'>",
        '<META CONTENT="PHP/8.4.26" NAME="GENERATOR" />',
    ],
)
def test_detect_php_reads_generator_meta_without_retaining_body(body: str) -> None:
    response = FakeResponse(body_text=body + "private-body-fixture")
    info = detect_php(response)
    assert info.detected is True
    assert info.version == "8.4.26"
    assert info.evidence == (Evidence("meta:generator", "PHP/8.4.26"),)
    assert "private-body-fixture" not in json.dumps(info.to_dict())


def test_detect_php_accepts_versionless_generator() -> None:
    response = FakeResponse(body_text='<meta name="generator" content="PHP">')
    info = detect_php(response)
    assert info == PhpInfo(detected=True, evidence=(Evidence("meta:generator", "PHP"),))


@pytest.mark.parametrize(
    "body",
    [
        "PHP/8.4.26",
        '<meta name="description" content="PHP/8.4.26">',
        '<!-- <meta name="generator" content="PHP/8.4.26"> -->',
        '<meta name="generator" content="NotPHP/8.4.26">',
    ],
)
def test_detect_php_ignores_non_generator_body_indications(body: str) -> None:
    response = FakeResponse(headers=(("Server", "nginx/1.24.0"),), body_text=body)
    info = detect_php(response)
    assert info == PhpInfo(detected=False)


def test_detect_php_returns_default_without_indications() -> None:
    info = detect_php(FakeResponse())
    assert info == PhpInfo(detected=False)


@pytest.mark.parametrize(
    ("server", "php_header", "expected"),
    [
        ("LiteSpeed", "", Sapi.LITESPEED),
        ("FrankenPHP", "", Sapi.FRANKENPHP),
        ("Apache/2.4.62", "PHP/8.4.26", Sapi.MOD_PHP),
        ("nginx/1.24.0", "PHP/8.4.26", Sapi.FPM),
        ("php-cgi", "", Sapi.PHP_CGI),
        ("CGI", "", Sapi.PHP_CGI),
        ("Apache/2.4.62", "", Sapi.UNKNOWN),
        ("nginx/1.24.0", "", Sapi.UNKNOWN),
        ("", "PHP/8.4.26", Sapi.UNKNOWN),
        ("", "PHP", Sapi.UNKNOWN),
    ],
)
def test_detect_sapi_uses_conservative_server_clues(
    server: str, php_header: str, expected: Sapi
) -> None:
    response = FakeResponse(headers=(("Server", server), ("X-Powered-By", php_header)))
    sapi = detect_sapi(response)
    assert sapi is expected


@pytest.mark.parametrize(
    "name,value", [("Server", "Apache PHP/8.4.26"), ("X-PHP-Version", "8.4.26")]
)
def test_detect_php_includes_inferred_sapi(name: str, value: str) -> None:
    response = FakeResponse(headers=(("Server", "Apache"), (name, value)))
    info = detect_php(response)
    assert info.sapi is Sapi.MOD_PHP


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("CF-Ray", "fixture", Waf.CLOUDFLARE),
        ("Server", "CloudFlare", Waf.CLOUDFLARE),
        ("Akamai-Cache-Status", "fixture", Waf.AKAMAI),
        ("Server", "AkamaiGHost", Waf.AKAMAI),
        ("X-Amz-Cf-Id", "fixture", Waf.CLOUDFRONT),
        ("Via", "1.1 CloudFront", Waf.CLOUDFRONT),
        ("X-Fastly-Request-ID", "fixture", Waf.FASTLY),
        ("X-Served-By", "cache.fastly.test", Waf.FASTLY),
        ("X-Vercel-Id", "fixture", Waf.VERCEL),
        ("X-Sucuri-ID", "fixture", Waf.SUCURI),
    ],
)
def test_detect_waf_recognizes_each_vendor(name: str, value: str, expected: Waf) -> None:
    response = FakeResponse(headers=((name, value),))
    waf = detect_waf(response)
    assert waf is expected


@pytest.mark.parametrize("offset", range(5))
def test_detect_waf_uses_vendor_priority_not_header_order(offset: int) -> None:
    indicators = (
        ("CF-Ray", "fixture"),
        ("Akamai-Test", "fixture"),
        ("X-Amz-Cf-Id", "fixture"),
        ("X-Fastly-Test", "fixture"),
        ("X-Vercel-Id", "fixture"),
        ("X-Sucuri-Id", "fixture"),
    )
    expected = (Waf.CLOUDFLARE, Waf.AKAMAI, Waf.CLOUDFRONT, Waf.FASTLY, Waf.VERCEL)
    response = FakeResponse(headers=tuple(reversed(indicators[offset:])))
    waf = detect_waf(response)
    assert waf is expected[offset]


def test_detect_waf_returns_none_without_vendor_indications() -> None:
    response = FakeResponse(headers=(("Server", "nginx"),), body_text="Cloudflare Akamai")
    waf = detect_waf(response)
    assert waf is Waf.NONE
