"""Parse audit targets and enforce authorization, scope, and disclosure boundaries."""

import re
import socket
from collections.abc import Callable
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit, urlunsplit

from php2shell_audit.models import ScanConfig, Target

_METADATA_HOSTS: Final = frozenset(
    {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "metadata.azure.internal"}
)
_PRIVATE_NETWORKS: Final = tuple(
    ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
_SITE_LOCAL: Final = ip_network("fec0::/10")


class SafetyError(Exception):
    """An expected boundary rejection with a stable machine-readable reason."""

    reason: str

    def __init__(self, reason: str, message: str) -> None:
        """Store the reason and a safe message without copying untrusted input."""
        self.reason = reason
        super().__init__(message)


class AuthorizationError(SafetyError):
    """The operator has not explicitly authorized the assessment."""


def normalize_target(raw: str) -> Target:
    """Parse an HTTP(S) URL or host into a Target, defaulting to HTTPS.

    Raise SafetyError for unsafe syntax; never resolve or contact the host.
    """
    value = raw.strip()
    if not value or any(
        character.isspace() or ord(character) < 32 or 127 <= ord(character) < 160
        for character in value
    ):
        raise SafetyError("invalid_target", "Target is empty or contains forbidden whitespace.")
    if "\\" in value or "#" in value:
        raise SafetyError("invalid_target", "Target contains a fragment or ambiguous separator.")
    candidate = value if "://" in value else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise SafetyError("unsafe_scheme", "Only HTTP and HTTPS targets are permitted.")
        if parsed.username is not None or parsed.password is not None:
            raise SafetyError("userinfo_not_allowed", "Target credentials are not permitted.")
        host = parsed.hostname
        port = parsed.port
        if not host or parsed.netloc.endswith(":"):
            raise SafetyError("invalid_target", "Target must contain a host and a valid port.")
        hostname = host.encode("idna").decode("ascii").lower().removesuffix(".")
        if not hostname or len(hostname) > 253 or "%" in hostname:
            raise SafetyError("invalid_target", "Target hostname is invalid or too long.")
        if ":" in hostname:
            ip_address(hostname)
            hostname = f"[{hostname}]"
        elif any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in hostname.split(".")
        ):
            raise SafetyError("invalid_target", "Target hostname contains an invalid label.")
        authority = hostname if port is None else f"{hostname}:{port}"
        return Target(urlunsplit((parsed.scheme.lower(), authority, parsed.path, parsed.query, "")))
    except (ValueError, UnicodeError) as error:
        raise SafetyError("invalid_target", "Target URL is malformed.") from error


def resolve_host(host: str) -> tuple[str, ...]:
    """Resolve all unique A/AAAA addresses, raising SafetyError on DNS failure."""
    try:
        records = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except OSError as error:
        raise SafetyError(
            "dns_resolution_failed", "Target hostname could not be resolved."
        ) from error
    addresses = tuple(dict.fromkeys(str(record[4][0]) for record in records))
    if not addresses:
        raise SafetyError("dns_resolution_failed", "Target hostname resolved to no addresses.")
    return addresses


def is_public_ip(address: str) -> bool:
    """Return true only for a valid globally routable unicast IP address."""
    try:
        parsed = ip_address(address)
    except ValueError:
        return False
    return (
        parsed.is_global
        and not parsed.is_private
        and not parsed.is_loopback
        and not parsed.is_link_local
        and not parsed.is_multicast
        and not parsed.is_reserved
        and not parsed.is_unspecified
        and parsed not in _SITE_LOCAL
        and "%" not in address
    )


def validate_target(
    target: Target,
    *,
    allow_private: bool = False,
    resolver: Callable[[str], tuple[str, ...]] | None = None,
) -> None:
    """Reject unsafe target syntax, metadata, and any disallowed resolved IP.

    Private opt-in permits only RFC1918, IPv6 ULA, and loopback addresses.
    The injected resolver must return all addresses; DNS failures fail closed.
    """
    normalized = normalize_target(target.url)
    host = urlsplit(normalized.url).hostname
    if host is None:
        raise SafetyError("invalid_target", "Target hostname is missing.")
    if host in _METADATA_HOSTS:
        raise SafetyError("metadata_blocked", "Cloud metadata targets are never permitted.")
    if not allow_private and (
        host == "localhost" or host.endswith((".local", ".internal", ".localhost"))
    ):
        raise SafetyError("private_target", "Private hostnames require explicit opt-in.")
    try:
        literal = ip_address(host)
    except ValueError:
        literal = None
    try:
        addresses = (str(literal),) if literal is not None else (resolver or resolve_host)(host)
    except OSError as error:
        raise SafetyError(
            "dns_resolution_failed", "Target hostname could not be resolved."
        ) from error
    if not addresses:
        raise SafetyError("dns_resolution_failed", "Target hostname resolved to no addresses.")
    for address in addresses:
        try:
            parsed = ip_address(address)
        except ValueError as error:
            raise SafetyError(
                "dns_resolution_failed", "Resolver returned an invalid address."
            ) from error
        if str(parsed) in _METADATA_HOSTS:
            raise SafetyError("metadata_blocked", "Cloud metadata targets are never permitted.")
        if (
            allow_private
            and "%" not in address
            and (parsed.is_loopback or any(parsed in network for network in _PRIVATE_NETWORKS))
        ):
            continue
        if not is_public_ip(address):
            raise SafetyError("unsafe_address", "Target resolves to a disallowed address.")


def load_scope(path: str | Path) -> frozenset[str]:
    """Read hosts or URLs from UTF-8 lines, ignoring blanks and # comments.

    Raise SafetyError for unreadable files or malformed entries.
    """
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise SafetyError("scope_read_failed", "Scope file could not be read.") from error
    hosts: set[str] = set()
    for line in lines:
        entry = line.strip()
        if entry and not entry.startswith("#"):
            try:
                ip_address(entry)
            except ValueError:
                host = urlsplit(normalize_target(entry).url).hostname
            else:
                host = entry
            if host is not None:
                hosts.add(host)
    return frozenset(hosts)


def assert_in_scope(target: Target, scope: frozenset[str]) -> None:
    """Require an exact host or subdomain match; empty scope adds no restriction."""
    if not scope:
        return
    host = urlsplit(normalize_target(target.url).url).hostname
    if host is not None and any(host == entry or host.endswith(f".{entry}") for entry in scope):
        return
    raise SafetyError("out_of_scope", "Target is outside the authorized scope.")


def require_authorization(config: ScanConfig) -> None:
    """Raise AuthorizationError unless the operator explicitly authorized scanning."""
    if not config.authorized:
        raise AuthorizationError("authorization_required", "Explicit authorization is required.")


def redact_url(url: str) -> str:
    """Keep scheme, host, port, and path; malformed URLs become <redacted-url>."""
    try:
        parsed = urlsplit(url)
        if not parsed.scheme or not parsed.hostname:
            return "<redacted-url>"
        sanitized = urlunsplit(
            (parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", "")
        )
        return normalize_target(sanitized).url
    except (ValueError, SafetyError):
        return "<redacted-url>"


def redact_header(name: str, value: str) -> str:
    """Redact secret-bearing headers, retaining only the name of a Set-Cookie cookie."""
    lowered = name.lower()
    if lowered == "set-cookie":
        cookie_name, separator, _ = value.partition("=")
        return f"{cookie_name.strip()}=<redacted>" if separator else "<redacted>"
    if lowered == "cookie" or any(part in lowered for part in ("token", "secret", "key", "auth")):
        return "<redacted>"
    return value
