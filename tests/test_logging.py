"""Public audit log persistence and disclosure contracts."""

import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from php2shell_audit.logging import AuditLogger
from php2shell_audit.models import JsonValue


def test_default_log_is_created_and_flushed(tmp_path: Path) -> None:
    directory = tmp_path / "nested" / "logs"
    with AuditLogger(log_dir=directory, console=False) as logger:
        logger.event("scan.started", count=2, label="café")
        path = next(directory.iterdir())
        assert re.fullmatch(r"php2shell-audit-\d{8}T\d{12}Z\.jsonl", path.name)
        record = json.loads(path.read_text())
        assert record["event"] == "scan.started"
        assert record["timestamp"].endswith("+00:00")
        assert record["count"] == 2
        assert "café" in path.read_text()


def test_default_log_collision_preserves_separate_events(tmp_path: Path) -> None:
    timestamp = datetime(2026, 10, 24, 12, 15, 16, 123456, tzinfo=UTC)
    with patch("php2shell_audit.logging.datetime") as clock:
        clock.now.return_value = timestamp
        for number in range(3):
            with AuditLogger(log_dir=tmp_path, console=False) as logger:
                logger.event("scan.started", number=number)

    names = [
        "php2shell-audit-20261024T121516123456Z.jsonl",
        "php2shell-audit-20261024T121516123456Z-1.jsonl",
        "php2shell-audit-20261024T121516123456Z-2.jsonl",
    ]
    assert {path.name for path in tmp_path.iterdir()} == set(names)
    assert [json.loads((tmp_path / name).read_text())["number"] for name in names] == [0, 1, 2]


def test_explicit_filename_appends_existing_events(tmp_path: Path) -> None:
    for number in range(2):
        with AuditLogger(log_dir=tmp_path, filename="audit", console=False) as logger:
            logger.event("scan.started", number=number)

    assert [
        json.loads(line)["number"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()
    ] == [0, 1]
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize(
    "fields",
    [
        {"Set-Cookie": "fixture-private", "Authorization": "fixture-private"},
        {"X-Api-Key": "fixture-private", "token": "fixture-private"},
        {"password": "fixture-private", "body_text": "fixture-private"},
        {"nested": [{"secret": "fixture-private", "content": "fixture-private"}]},
        {"headers": {"Set-Cookie": "sid=fixture-private", "Authorization": "fixture-private"}},
        {"headers": [["X-Api-Key", "fixture-private"], ["Cookie", "fixture-private"]]},
    ],
)
def test_sensitive_values_are_redacted(tmp_path: Path, fields: dict[str, JsonValue]) -> None:
    with AuditLogger(log_dir=tmp_path, filename="audit", console=False) as logger:
        logger.event("response", **fields)
    text = (tmp_path / "audit.jsonl").read_text()
    assert "fixture-private" not in text
    assert "<redacted>" in text


@pytest.mark.parametrize("key", ["url", "target", "location", "final_url", "redirect"])
def test_url_fields_drop_credentials_queries_and_fragments(tmp_path: Path, key: str) -> None:
    with AuditLogger(log_dir=tmp_path, filename="audit", console=False) as logger:
        logger.event("redirect", **{key: "https://user:fixture-private@example.test/p?q=secret#x"})
    assert json.loads((tmp_path / "audit.jsonl").read_text())[key] == "https://example.test/p"


def test_console_can_be_disabled(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with AuditLogger(log_dir=tmp_path, console=False) as logger:
        logger.event("quiet")
    assert capsys.readouterr() == ("", "")


def test_console_filters_without_filtering_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with AuditLogger(log_dir=tmp_path, filename="audit", level="warning") as logger:
        logger.event("hidden", level="debug")
        logger.event("visible", level="ERROR", **{"password": "fixture-private"})
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "hidden" not in captured.err
    assert "ERROR visible" in captured.err
    assert "fixture-private" not in captured.err
    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [record["level"] for record in records] == ["debug", "ERROR"]


def test_invalid_levels_raise(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="level"):
        AuditLogger(log_dir=tmp_path, level="TRACE")
    with AuditLogger(log_dir=tmp_path, console=False) as logger:
        with pytest.raises(ValueError, match="level"):
            logger.event("bad", level="TRACE")


def test_close_is_idempotent_and_context_closes(tmp_path: Path) -> None:
    with AuditLogger(log_dir=tmp_path, console=False) as logger:
        logger.event("done")
    logger.close()
    logger.close()
    with pytest.raises(ValueError, match="closed"):
        logger.event("too_late")


def test_explicit_filename_stays_in_log_directory(tmp_path: Path) -> None:
    with AuditLogger(log_dir=tmp_path, filename="../evil", console=False) as logger:
        logger.event("safe")
    assert (tmp_path / "evil.jsonl").is_file()
    with pytest.raises(ValueError, match="filename"):
        AuditLogger(log_dir=tmp_path, filename="..", console=False)


def test_threaded_events_remain_valid_jsonl(tmp_path: Path) -> None:
    with AuditLogger(log_dir=tmp_path, filename="parallel", console=False) as logger:
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda number: logger.event("item", number=number), range(100)))
    records = [json.loads(line) for line in (tmp_path / "parallel.jsonl").read_text().splitlines()]
    assert sorted(record["number"] for record in records) == list(range(100))
