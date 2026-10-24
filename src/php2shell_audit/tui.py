"""Authorization-gated Textual interface; network and exports run off the UI thread."""

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Label,
    RichLog,
    Static,
    TextArea,
)

from php2shell_audit.logging import AuditLogger
from php2shell_audit.models import ScanConfig, ScanReport, Target, TargetResult, Verdict
from php2shell_audit.reporting import write_all
from php2shell_audit.safety import SafetyError, normalize_target, redact_url
from php2shell_audit.scanner import Scanner

NOTICE: Final = "Detection-only: a version match is exposure evidence, not proof of exploitability."
VERDICT_LABELS: Final = {
    Verdict.VULNERABLE_VERSION: "Exposed version",
    Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN: "Version unknown",
    Verdict.NOT_VULNERABLE_VERSION: "Not exposed version",
    Verdict.NOT_PHP: "PHP not detected",
    Verdict.UNREACHABLE: "Unreachable",
    Verdict.BLOCKED_BY_SAFETY: "Safety blocked",
    Verdict.WAF_BLOCKED: "WAF blocked",
}


def parse_targets(text: str) -> list[str]:
    """Split operator input on commas/whitespace and deduplicate in input order."""
    return list(dict.fromkeys(part for part in re.split(r"[\s,]+", text.strip()) if part))


def _output_dir(prefix: str) -> Path:
    return Path("reports") / f"{prefix}-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}"


class AuditApp(App[None]):
    """Collect consent and display immutable reports, with mutable UI lifecycle state."""

    TITLE = "PHP Exposure Audit"
    BINDINGS = [("ctrl+q", "quit", "Quit")]
    CSS = """
    Screen { layout: vertical; }
    #notice { height: auto; color: $warning; text-style: bold; }
    Label { height: 1; }
    #targets { height: 3; }
    #options { layout: grid; grid-size: 2; grid-rows: 1 1; height: 2; }
    Checkbox { border: none; padding: 0; height: 1; }
    #authorized { column-span: 2; }
    #actions { height: 3; }
    Button { margin-right: 1; min-width: 12; }
    #results { height: 1fr; min-height: 3; }
    #details { height: 4; border-top: solid $primary; }
    #detail { height: auto; }
    #log { height: 4; border-top: solid $primary; }
    """

    def __init__(self) -> None:
        super().__init__()
        self.report: ScanReport | None = None
        self.results: dict[str, TargetResult] = {}
        self.busy = False

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(NOTICE, id="notice", markup=False)
        yield Label("Targets (one per line)")
        yield TextArea(id="targets")
        with Horizontal(id="options"):
            yield Checkbox("I confirm I am authorized to scan these targets.", id="authorized")
            yield Checkbox("Deep checks", id="deep")
            yield Checkbox("Allow private (local lab)", id="allow_private")
        with Horizontal(id="actions"):
            yield Button("Scan", id="scan", variant="primary", disabled=True)
            yield Button("Export", id="export", disabled=True)
            yield Button("Quit", id="quit")
        yield DataTable(id="results", cursor_type="row")
        with VerticalScroll(id="details"):
            yield Static(
                "No results yet. Enter targets and confirm authorization.",
                id="detail",
                markup=False,
            )
        yield RichLog(id="log", wrap=True, markup=False, highlight=False, max_lines=500)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results", DataTable)
        for name, width in zip(
            ("Target", "Verdict", "PHP", "SAPI", "WAF", "Requests"),
            (18, 19, 6, 7, 8, 8),
            strict=True,
        ):
            table.add_column(name, width=width)
        self.query_one("#details", VerticalScroll).border_title = "Target detail (scroll)"
        self.query_one("#log", RichLog).border_title = "Progress and audit"
        self.log_message("Ready. Only scan targets you own or have explicit permission to assess.")
        self.query_one("#targets", TextArea).focus()

    def log_message(self, message: str) -> None:
        self.query_one("#log", RichLog).write(Text(message))

    @on(Checkbox.Changed, "#authorized")
    def authorization_changed(self, event: Checkbox.Changed) -> None:
        self.query_one("#scan", Button).disabled = self.busy or not event.value

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        self.query_one("#scan", Button).disabled = (
            busy or not self.query_one("#authorized", Checkbox).value
        )
        self.query_one("#export", Button).disabled = busy or self.report is None

    @on(Button.Pressed, "#scan")
    def scan_pressed(self) -> None:
        if not self.query_one("#authorized", Checkbox).value:
            self.log_message("Authorization is required before scanning.")
            return
        if self.busy:
            return
        raw_targets = parse_targets(self.query_one("#targets", TextArea).text)
        if not raw_targets:
            self.log_message("Enter at least one target before scanning.")
            return
        if len(raw_targets) > 10:
            self.log_message("Limit: 10 targets per scan. Reduce the list and try again.")
            return
        try:
            targets = list(dict.fromkeys(normalize_target(raw) for raw in raw_targets))
        except SafetyError as exc:
            self.log_message(f"Blocked: {exc}")
            return
        output_dir = _output_dir("tui")
        config = ScanConfig(
            authorized=True,
            deep=self.query_one("#deep", Checkbox).value,
            allow_private=self.query_one("#allow_private", Checkbox).value,
            output_dir=str(output_dir),
        )
        self._set_busy(True)
        self.log_message(
            f"Scanning {len(targets)} target(s): deep={config.deep}, "
            f"allow_private={config.allow_private}. Please wait; the UI remains available."
        )
        self.scan_targets(targets, config)

    @work(thread=True, exclusive=True)
    def scan_targets(self, targets: list[Target], config: ScanConfig) -> None:
        try:
            with AuditLogger(log_dir="logs", level="INFO", console=False) as logger:
                with Scanner(config, logger=logger) as scanner:
                    report = scanner.scan_many(targets)
                self.call_from_thread(self.display_report, report)
                paths = write_all(report, Path(config.output_dir))
                self.call_from_thread(self._log_paths, paths)
        except (OSError, ValueError, SafetyError) as exc:
            self.call_from_thread(
                self.log_message,
                f"Scan or report save failed ({type(exc).__name__}). Check local permissions "
                "and configuration, then retry or export any available results.",
            )
        finally:
            self.call_from_thread(self._set_busy, False)

    def display_report(self, report: ScanReport) -> None:
        """Render scanner-produced, redacted results on the UI thread."""
        self.report = report
        self.results = {str(index): result for index, result in enumerate(report.results)}
        table = self.query_one("#results", DataTable)
        table.clear()
        for key, result in self.results.items():
            table.add_row(
                Text(redact_url(result.target.url), overflow="ellipsis", no_wrap=True),
                VERDICT_LABELS[result.verdict],
                result.php.version or "?",
                result.php.sapi.value,
                result.waf.value,
                str(result.requests_made),
                key=key,
            )
        if report.results:
            self.show_detail(report.results[0])
            table.move_cursor(row=0, column=0)
        else:
            self.query_one("#detail", Static).update("Scan finished with no target results.")
        self.query_one("#export", Button).disabled = self.busy
        self.log_message(f"Scan complete: {len(report.results)} result(s). {NOTICE}")

    @on(DataTable.RowSelected, "#results")
    @on(DataTable.RowHighlighted, "#results")
    def result_selected(self, event: DataTable.RowSelected | DataTable.RowHighlighted) -> None:
        result = self.results.get(str(event.row_key.value))
        if result is not None:
            self.show_detail(result)

    def show_detail(self, result: TargetResult) -> None:
        lines = [
            f"Target: {redact_url(result.target.url)} | Verdict: {result.verdict.value}",
            f"PHP: {result.php.version or 'version unknown'} | SAPI: {result.php.sapi.value} | "
            f"WAF: {result.waf.value} | Requests: {result.requests_made}",
        ]
        if result.error:
            lines.append(f"Assessment incomplete: {result.error}")
        lines.extend(
            f"{item.cve_id}: {item.verdict.value} | "
            f"Fixed: {item.fixed_version or 'not established'}"
            f"\n  Reason: {item.reason}"
            for item in result.assessments
        )
        lines.extend(
            f"{item.severity.value.upper()}: {item.title}\n  Mitigation: "
            f"{item.mitigation or 'Review server configuration and patch status.'}"
            for item in result.findings
        )
        self.query_one("#detail", Static).update("\n".join(lines))
        self.query_one("#details", VerticalScroll).scroll_home(animate=False)

    def _log_paths(self, paths: dict[str, Path]) -> None:
        for name, path in paths.items():
            self.log_message(f"{name}: {path}")
        self.log_message(NOTICE)

    @on(Button.Pressed, "#export")
    def export_pressed(self) -> None:
        if self.report is not None and not self.busy:
            self._set_busy(True)
            self.export_report(self.report)

    @work(thread=True, exclusive=True)
    def export_report(self, report: ScanReport) -> None:
        try:
            paths = write_all(report, _output_dir("tui-export"))
            self.call_from_thread(self._log_paths, paths)
        except (OSError, ValueError) as exc:
            self.call_from_thread(
                self.log_message,
                f"Export failed ({type(exc).__name__}). Check local write permissions and retry.",
            )
        finally:
            self.call_from_thread(self._set_busy, False)

    @on(Button.Pressed, "#quit")
    def quit_pressed(self) -> None:
        self.exit()


def run_tui() -> None:
    """Run the terminal UI; launching it never grants scan authorization."""
    AuditApp().run()
