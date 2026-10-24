"""Pure response fingerprinting; observations are not proof of exploitability."""

import re
from html.parser import HTMLParser
from typing import Final, Protocol

from php2shell_audit.models import Evidence, PhpInfo, Sapi, Waf

_PHP_VERSION: Final = re.compile(r"\bPHP(?:/|\s*)([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
_PHP_TOKEN: Final = re.compile(r"\bPHP(?=\b|[0-9])", re.IGNORECASE)
_PHP_HEADERS: Final = ("x-powered-by", "server", "x-php-version")


class ResponseView(Protocol):
    """Transport-independent response fields consumed without network access."""

    status_code: int
    headers: tuple[tuple[str, str], ...]
    body_text: str
    final_url: str


def header_values(headers: tuple[tuple[str, str], ...], name: str) -> tuple[str, ...]:
    """Return case-insensitive header matches in order, with values unchanged."""
    return tuple(value for key, value in headers if key.casefold() == name.casefold())


def parse_php_version(text: str) -> str | None:
    """Extract a PHP X.Y.Z version from text, or None."""
    match = _PHP_VERSION.search(text)
    return match.group(1) if match else None


def _header_version(name: str, value: str) -> str | None:
    version = parse_php_version(value)
    if version is None and name == "x-php-version":
        version = parse_php_version(f"PHP/{value.strip()}")
    return version


class _GeneratorParser(HTMLParser):
    """Accumulate only sanitized generator evidence, never body fragments."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.info: PhpInfo | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta" or self.info is not None:
            return
        attributes = dict(attrs)
        name = attributes.get("name")
        content = attributes.get("content")
        if name is None or name.casefold() != "generator" or content is None:
            return
        if _PHP_TOKEN.search(content):
            version = parse_php_version(content)
            value = f"PHP/{version}" if version else "PHP"
            self.info = PhpInfo(
                detected=True,
                version=version,
                evidence=(Evidence(source="meta:generator", value=value),),
            )


def detect_php(response: ResponseView) -> PhpInfo:
    """Infer PHP from ordered headers, cookie names and generator tags only.

    Cookie values and bodies are never copied into evidence. Header evidence
    preserves the original value; generator evidence retains only PHP/version.
    """
    evidence: list[Evidence] = []
    for name in _PHP_HEADERS:
        for value in header_values(response.headers, name):
            version = _header_version(name, value)
            if version is not None:
                return PhpInfo(
                    detected=True,
                    version=version,
                    sapi=detect_sapi(response),
                    evidence=(Evidence(source=f"header:{name}", value=value),),
                )
            if _PHP_TOKEN.search(value):
                evidence.append(Evidence(source=f"header:{name}", value=value))

    for cookie in header_values(response.headers, "set-cookie"):
        cookie_name, separator, _ = cookie.partition("=")
        if separator and cookie_name.strip() == "PHPSESSID":
            evidence.append(Evidence(source="cookie:PHPSESSID", value="<redacted>"))
            break

    parser = _GeneratorParser()
    parser.feed(response.body_text)
    parser.close()
    if parser.info is not None:
        evidence.extend(parser.info.evidence)
    if evidence:
        return PhpInfo(
            detected=True,
            version=parser.info.version if parser.info else None,
            sapi=detect_sapi(response),
            evidence=tuple(evidence),
        )
    return PhpInfo(detected=False)


def detect_sapi(response: ResponseView) -> Sapi:
    """Infer SAPI conservatively; this is not proof, and proxies can hide it.

    A reverse proxy can obscure the real SAPI even when PHP is disclosed.
    """
    server = " ".join(header_values(response.headers, "server")).casefold()
    if "litespeed" in server:
        return Sapi.LITESPEED
    if "frankenphp" in server:
        return Sapi.FRANKENPHP
    has_php_version = any(
        _header_version(name, value) is not None
        for name in _PHP_HEADERS
        for value in header_values(response.headers, name)
    )
    if "apache" in server and has_php_version:
        return Sapi.MOD_PHP
    if "nginx" in server and has_php_version:
        return Sapi.FPM
    if "cgi" in server:
        return Sapi.PHP_CGI
    return Sapi.UNKNOWN


def detect_waf(response: ResponseView) -> Waf:
    """Return the first vendor indicator in priority order.

    Presence is not proof of protection; absence is not proof of no WAF.
    """
    headers = tuple((name.casefold(), value.casefold()) for name, value in response.headers)
    names = tuple(name for name, _ in headers)
    server = " ".join(header_values(headers, "server"))
    if "cf-ray" in names or "cloudflare" in server:
        return Waf.CLOUDFLARE
    if any(name.startswith("akamai-") for name in names) or "akamai" in server:
        return Waf.AKAMAI
    if "x-amz-cf-id" in names or any(
        "cloudfront" in value for value in header_values(headers, "via")
    ):
        return Waf.CLOUDFRONT
    if any(name.startswith("x-fastly-") for name in names) or any(
        "fastly" in value for value in header_values(headers, "x-served-by")
    ):
        return Waf.FASTLY
    if any(name.startswith("x-vercel-") for name in names):
        return Waf.VERCEL
    if any(name.startswith("x-sucuri-") for name in names):
        return Waf.SUCURI
    return Waf.NONE
