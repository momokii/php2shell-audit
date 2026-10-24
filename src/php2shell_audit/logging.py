"""Thread-safe audit events, redacted before either output sink receives them."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Final

from rich.console import Console

from php2shell_audit.models import JsonValue
from php2shell_audit.safety import redact_header, redact_url

_LEVELS: Final = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
_SENSITIVE: Final = frozenset(
    {
        "cookie",
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "auth",
        "session",
        "sessionid",
        "body",
        "body_text",
        "content",
        "response_body",
    }
)


def redact_value(value: object, key: str = "") -> JsonValue:
    """Return detached JSON data with secrets, bodies and URL parameters removed.

    Evidence uses source/value pairs; headers accept mappings or sequences of pairs.
    Unsupported scalar objects are stringified, matching the audit serializer.
    """
    lowered = key.lower()
    if lowered in _SENSITIVE:
        return "<redacted>"
    if isinstance(value, str):
        if lowered.endswith(("url", "target", "location", "redirect")):
            return redact_url(value)
        return redact_header(key, value)
    if lowered == "headers":
        if isinstance(value, Mapping):
            return {str(name): redact_header(str(name), str(item)) for name, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [[str(name), redact_header(str(name), str(item))] for name, item in value]
    if isinstance(value, Mapping):
        result = {str(name): redact_value(item, str(name)) for name, item in value.items()}
        source = value.get("source")
        observation = value.get("value")
        if isinstance(source, str) and isinstance(observation, str):
            label = source.removeprefix("header:")
            result["value"] = (
                "<redacted>"
                if source.lower().startswith("cookie:")
                else redact_value(observation, label)
            )
        return result
    if isinstance(value, (list, tuple)):
        return [redact_value(item, key) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _level(value: JsonValue) -> str:
    if not isinstance(value, str) or value.upper() not in _LEVELS:
        raise ValueError("Invalid audit level; expected DEBUG, INFO, WARNING or ERROR")
    return value.upper()


class AuditLogger:
    """Own a flushed JSONL stream and optional severity-filtered stderr mirror."""

    def __init__(
        self,
        *,
        log_dir: str | Path = "logs",
        level: str = "INFO",
        console: bool = True,
        filename: str | None = None,
    ) -> None:
        self._level = _level(level)
        default = f"php2shell-audit-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}.jsonl"
        name = Path(filename.replace("\\", "/")).name if filename else ""
        if ".." in name:
            raise ValueError("Invalid audit filename")
        use_default = not name
        name = name or default
        if not name.endswith(".jsonl"):
            name += ".jsonl"
        directory = Path(log_dir)
        directory.mkdir(parents=True, exist_ok=True)
        if use_default:
            number = 0
            while True:
                try:
                    self._file = (directory / name).open("x", encoding="utf-8")
                    break
                except FileExistsError:
                    number += 1
                    name = f"{Path(default).stem}-{number}.jsonl"
        else:
            self._file = (directory / name).open("a", encoding="utf-8")
        self._console = Console(stderr=True) if console else None
        self._lock = Lock()

    def event(self, name: str, **fields: JsonValue) -> None:
        """Persist one redacted event; level affects only console visibility."""
        level = _level(fields.get("level", "INFO"))
        record = {key: redact_value(value, key) for key, value in fields.items()}
        timestamp = datetime.now(UTC).isoformat()
        record.update(timestamp=timestamp, event=name)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            self._file.write(line + "\n")
            self._file.flush()
            if self._console is not None and _LEVELS[level] >= _LEVELS[self._level]:
                details = " ".join(
                    f"{key}={json.dumps(value, ensure_ascii=False)}"
                    for key, value in record.items()
                    if key not in {"timestamp", "event"}
                )
                self._console.print(
                    f"{timestamp} {level} {name} {details}", markup=False, highlight=False
                )

    def close(self) -> None:
        """Flush and close once, serialized with concurrent event writers."""
        with self._lock:
            if not self._file.closed:
                self._file.flush()
                self._file.close()

    def __enter__(self) -> AuditLogger:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
