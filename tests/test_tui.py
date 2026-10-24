"""Offline interaction tests at the Textual application's public UI boundary."""

import asyncio
from collections.abc import Iterable
from threading import Event
from unittest.mock import MagicMock

import pytest
from textual.widgets import Button, Checkbox, DataTable, RichLog, Static, TextArea

from php2shell_audit import tui
from php2shell_audit.models import (
    Assessment,
    Finding,
    PhpInfo,
    Sapi,
    ScanReport,
    Severity,
    Target,
    TargetResult,
    Verdict,
    Waf,
)
from php2shell_audit.tui import AuditApp, parse_targets, run_tui


def log_text(app: AuditApp) -> str:
    return "\n".join(line.text for line in app.query_one("#log", RichLog).lines)


@pytest.fixture(autouse=True)
def offline_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tui, "AuditLogger", MagicMock())
    monkeypatch.setattr(tui, "Scanner", MagicMock(side_effect=AssertionError("Unexpected scan")))
    monkeypatch.setattr(tui, "write_all", MagicMock(side_effect=AssertionError("Unexpected write")))


def test_module_imports_and_entrypoint(monkeypatch: pytest.MonkeyPatch) -> None:
    run = MagicMock()
    monkeypatch.setattr(AuditApp, "run", run)
    run_tui()
    run.assert_called_once_with()


def test_scan_disabled_until_authorized() -> None:
    async def scenario() -> None:
        app = AuditApp()
        async with app.run_test(size=(80, 24)) as pilot:
            scan = app.query_one("#scan", Button)
            assert scan.disabled
            await pilot.click("#authorized")
            await pilot.pause()
            assert not scan.disabled
            await pilot.click("#authorized")
            await pilot.pause()
            assert scan.disabled

    asyncio.run(scenario())


def test_parse_targets() -> None:
    assert parse_targets(" alpha.example\nbeta.example,alpha.example\t gamma.example ,, ") == [
        "alpha.example",
        "beta.example",
        "gamma.example",
    ]
    assert parse_targets(" ,\n\t ") == []


def test_empty_targets_logs_error() -> None:
    async def scenario() -> None:
        app = AuditApp()
        async with app.run_test() as pilot:
            await pilot.click("#authorized")
            await pilot.click("#scan")
            await pilot.pause()
            assert "Enter at least one target" in log_text(app)
            assert not app.workers

    asyncio.run(scenario())


def test_export_disabled_until_report() -> None:
    async def scenario() -> None:
        app = AuditApp()
        async with app.run_test():
            assert app.query_one("#export", Button).disabled

    asyncio.run(scenario())


@pytest.mark.parametrize("theme", ["textual-dark", "textual-light"])
def test_compact_layout_and_safe_quit_binding(theme: str) -> None:
    async def scenario() -> None:
        app = AuditApp()
        app.theme = theme
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            for selector in ("#authorized", "#scan", "#export", "#results", "#details", "#log"):
                region = app.query_one(selector).region
                assert region.width > 0 and region.height > 0
                assert region.right <= 80 and region.bottom <= 23
            await pilot.press("q")
            assert app.query_one("#targets", TextArea).text == "q"
            await pilot.press("ctrl+q")

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("file:///etc/passwd", "Blocked:"),
        ("good.example ftp://bad.example", "Blocked:"),
        (" ".join(f"host{index}.example" for index in range(11)), "10 targets"),
    ],
)
def test_invalid_targets_never_start_scan(text: str, message: str) -> None:
    async def scenario() -> None:
        app = AuditApp()
        async with app.run_test() as pilot:
            app.query_one("#targets", TextArea).load_text(text)
            await pilot.click("#authorized")
            await pilot.click("#scan")
            await pilot.pause()
            assert message in log_text(app)
            assert not app.workers

    asyncio.run(scenario())


def test_unauthorized_handler_cannot_start_scan() -> None:
    async def scenario() -> None:
        app = AuditApp()
        async with app.run_test() as pilot:
            app.query_one("#targets", TextArea).load_text("example.com")
            app.scan_pressed()
            await pilot.pause()
            assert "Authorization is required before scanning." in log_text(app)
            assert not app.workers

    asyncio.run(scenario())


def test_worker_displays_report_and_exports(monkeypatch: pytest.MonkeyPatch) -> None:
    report = ScanReport(
        results=(
            TargetResult(
                Target("https://example.com"),
                Verdict.VULNERABLE_VERSION,
                php=PhpInfo(True, "8.4.26", Sapi.MOD_PHP),
                waf=Waf.NONE,
                assessments=(
                    Assessment(
                        "CVE-2026-109618", Verdict.VULNERABLE_VERSION, "Version match", "8.4.27"
                    ),
                ),
                findings=(
                    Finding("Version disclosed", Severity.INFO, "Banner", mitigation="Patch"),
                ),
                requests_made=1,
            ),
            TargetResult(Target("https://other.example"), Verdict.NOT_PHP),
        )
    )
    scanner = MagicMock()
    scanner.return_value.__enter__.return_value.scan_many.return_value = report
    writes = MagicMock(
        side_effect=lambda result, directory: {
            name: directory / f"report.{name}" for name in ("json", "jsonl", "markdown", "csv")
        }
    )
    monkeypatch.setattr(tui, "Scanner", scanner)
    monkeypatch.setattr(tui, "write_all", writes)

    async def scenario() -> None:
        app = AuditApp()
        async with app.run_test(size=(80, 24)) as pilot:
            app.query_one("#targets", TextArea).load_text("example.com other.example")
            await pilot.click("#authorized")
            app.query_one("#deep", Checkbox).value = True
            app.query_one("#allow_private", Checkbox).value = True
            await pilot.click("#scan")
            await app.workers.wait_for_complete()
            await pilot.pause()
            table = app.query_one("#results", DataTable)
            assert table.row_count == 2
            assert table.max_scroll_x == 0
            assert "8.4.26" in str(app.query_one("#detail", Static).render())
            assert "8.4.27" in str(app.query_one("#detail", Static).render())
            assert not app.query_one("#scan", Button).disabled
            assert not app.query_one("#export", Button).disabled
            table.focus()
            await pilot.press("down", "enter")
            await pilot.pause()
            assert "other.example" in str(app.query_one("#detail", Static).render())
            await pilot.click("#export")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert writes.call_count == 2
            assert str(writes.call_args.args[1]).startswith("reports/tui-export-")
            assert all(f"{name}:" in log_text(app) for name in ("json", "jsonl", "markdown", "csv"))
            assert "not proof of exploitability" in log_text(app)

    asyncio.run(scenario())
    config = scanner.call_args.args[0]
    assert config.authorized and config.deep and config.allow_private
    assert config.output_dir.startswith("reports/tui-")
    scanner.return_value.__enter__.return_value.scan_many.assert_called_once_with(
        [Target("https://example.com"), Target("https://other.example")]
    )


def test_authorization_toggle_cannot_restart_busy_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    started = Event()
    release = Event()

    def scan_many(targets: Iterable[Target]) -> ScanReport:
        started.set()
        if not release.wait(timeout=5):
            raise TimeoutError
        return ScanReport()

    scanner = MagicMock()
    scanner.return_value.__enter__.return_value.scan_many.side_effect = scan_many
    monkeypatch.setattr(tui, "Scanner", scanner)
    monkeypatch.setattr(tui, "write_all", MagicMock(return_value={}))

    async def scenario() -> None:
        app = AuditApp()
        async with app.run_test() as pilot:
            try:
                app.query_one("#targets", TextArea).load_text("example.com")
                await pilot.click("#authorized")
                await pilot.click("#scan")
                assert await asyncio.to_thread(started.wait, 2)
                await pilot.click("#authorized")
                await pilot.click("#authorized")
                await pilot.pause()
                assert app.query_one("#scan", Button).disabled
                await pilot.click("#authorized")
            finally:
                release.set()
                await app.workers.wait_for_complete()
            assert app.query_one("#scan", Button).disabled

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["scan", "export"])
def test_worker_errors_are_safe_and_restore_controls(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    scanner = MagicMock()
    scanner.return_value.__enter__.return_value.scan_many.return_value = ScanReport()
    monkeypatch.setattr(tui, "Scanner", scanner)
    writes = MagicMock(side_effect=OSError("sensitive diagnostic"))
    monkeypatch.setattr(tui, "write_all", writes)

    async def scenario() -> None:
        app = AuditApp()
        async with app.run_test() as pilot:
            await pilot.click("#authorized")
            if operation == "export":
                app.display_report(ScanReport())
            else:
                app.query_one("#targets", TextArea).load_text("example.com")
            await pilot.click(f"#{operation}")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert "failed" in log_text(app)
            assert "sensitive diagnostic" not in log_text(app)
            assert not app.query_one("#scan", Button).disabled

    asyncio.run(scenario())
