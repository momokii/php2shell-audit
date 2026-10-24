"""Authorization-first, detection-only CLI for bounded defensive PHP audits."""

import math
import shutil
import subprocess
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from php2shell_audit import __version__
from php2shell_audit.advisory import load_advisories
from php2shell_audit.logging import AuditLogger
from php2shell_audit.models import ScanConfig, Verdict
from php2shell_audit.reporting import write_all
from php2shell_audit.safety import (
    SafetyError,
    assert_in_scope,
    load_scope,
    normalize_target,
    redact_url,
)
from php2shell_audit.scanner import Scanner

app = typer.Typer(help="Defensive PHP security auditing.", add_completion=False)
lab_app = typer.Typer(help="Manage the loopback-only detection lab.", add_completion=False)
app.add_typer(lab_app, name="lab")


class ReportFormat(StrEnum):
    """Supported report selections at the CLI boundary."""

    ALL = "all"
    JSON = "json"
    JSONL = "jsonl"
    MARKDOWN = "markdown"
    MD = "md"
    CSV = "csv"


class FailOn(StrEnum):
    """Opt-in CI failure policies."""

    VULNERABLE = "vulnerable"
    UNKNOWN = "unknown"
    NEVER = "never"


def _authorize(ctx: typer.Context, value: bool) -> bool:
    if not ctx.resilient_parsing and not value:
        typer.echo("Error: explicit authorization is required; pass --authorized.", err=True)
        raise typer.Exit(code=2)
    return value


@app.command()
def version() -> None:
    """Print the application version and exit successfully."""
    typer.echo(f"php2shell-audit {__version__}")


@app.command()
def scan(
    targets: Annotated[
        list[str], typer.Argument(help="Authorized HTTP(S) targets; detection only.")
    ],
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            callback=_authorize,
            is_eager=True,
            help="Confirm explicit permission to audit every target.",
        ),
    ] = False,
    scope: Annotated[
        Path | None, typer.Option(help="Restrict audits to hosts in this scope file.")
    ] = None,
    output_dir: Annotated[Path, typer.Option(help="Report output directory.")] = Path("reports"),
    report_format: Annotated[ReportFormat, typer.Option("--format")] = ReportFormat.ALL,
    rate_limit: Annotated[
        float, typer.Option(min=0.0, help="Requests per second; 0 disables pacing.")
    ] = 1.0,
    timeout: Annotated[
        float, typer.Option(min=0.0, help="Positive request timeout in seconds.")
    ] = 10.0,
    max_requests: Annotated[int, typer.Option(min=1, max=100)] = 20,
    max_targets: Annotated[int, typer.Option(min=1, max=50)] = 10,
    deep: Annotated[
        bool, typer.Option(help="Enable bounded status-only discovery probes.")
    ] = False,
    allow_private: Annotated[
        bool, typer.Option(help="Allow private/loopback lab targets.")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option(help="Preview without DNS, HTTP, logs, or reports.")
    ] = False,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            help=(
                "CI policy; unknown includes unknown version, "
                "WAF-blocked, and unreachable outcomes."
            )
        ),
    ] = FailOn.NEVER,
    verbose: Annotated[
        bool, typer.Option(help="Enable DEBUG audit logging with redaction.")
    ] = False,
) -> None:
    """Detection-only auditing: requires permission; never exploits or uploads files."""
    if not math.isfinite(timeout) or timeout <= 0 or not math.isfinite(rate_limit):
        typer.echo("Error: timeout must be positive and rate-limit must be finite.", err=True)
        raise typer.Exit(code=2)
    try:
        normalized = list(dict.fromkeys(normalize_target(raw) for raw in targets))
        if len(normalized) > max_targets:
            typer.echo(f"Error: target count exceeds --max-targets {max_targets}.", err=True)
            raise typer.Exit(code=2)
        if scope is not None:
            allowed = load_scope(scope)
            for target in normalized:
                assert_in_scope(target, allowed)
        config = ScanConfig(
            authorized=True,
            scope_file=str(scope) if scope is not None else None,
            output_dir=str(output_dir),
            rate_limit=rate_limit,
            timeout=timeout,
            max_requests=max_requests,
            deep=deep,
            allow_private=allow_private,
        )
        console = Console(markup=False, highlight=False)
        if dry_run:
            plan = Table("Option", "Effective value", title="Detection-only scan plan")
            plan.add_row("Targets", "\n".join(redact_url(target.url) for target in normalized))
            for name, value in config.to_dict().items():
                plan.add_row(name, str(value))
            for name, value in (
                ("format", report_format.value),
                ("max_targets", max_targets),
                ("fail_on", fail_on.value),
                ("verbose", verbose),
            ):
                plan.add_row(name, str(value))
            console.print(plan)
            typer.echo("Dry run: no DNS resolution or HTTP requests were made.")
            return
        with AuditLogger(
            log_dir="logs", level="DEBUG" if verbose else "INFO", console=True
        ) as logger:
            with Scanner(config, logger=logger) as scanner:
                report = scanner.scan_many(normalized)
            formats = (
                ("json", "jsonl", "markdown", "csv")
                if report_format is ReportFormat.ALL
                else (report_format.value,)
            )
            paths = write_all(report, output_dir, formats=formats)
        summary = Table("Target", "Verdict", "PHP", "SAPI", "WAF", "Requests", "Error")
        for result in report.results:
            summary.add_row(
                redact_url(result.target.url),
                result.verdict.value,
                result.php.version or "unknown",
                result.php.sapi.value,
                result.waf.value,
                str(result.requests_made),
                result.error or "",
            )
        console.print(summary)
        for label, path in paths.items():
            typer.echo(f"{label}: {path}")
        typer.echo("A version match is exposure evidence, not proof of exploitability.")
        failing = {
            FailOn.VULNERABLE: {Verdict.VULNERABLE_VERSION},
            FailOn.UNKNOWN: {
                Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN,
                Verdict.WAF_BLOCKED,
                Verdict.UNREACHABLE,
            },
            FailOn.NEVER: set(),
        }
        if any(result.verdict in failing[fail_on] for result in report.results):
            raise typer.Exit(code=1)
    except SafetyError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=2) from None
    except ValueError:
        typer.echo("Error: advisory data or report configuration is invalid.", err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        typer.echo("Error: audit files could not be read or written.", err=True)
        raise typer.Exit(code=1) from None
    except KeyboardInterrupt:
        typer.echo("Interrupted.", err=True)
        raise typer.Exit(code=130) from None


@app.command()
def advisories() -> None:
    """Show the bundled advisory snapshot offline; no network requests."""
    try:
        snapshot = load_advisories()
    except (ValueError, OSError):
        typer.echo("Error: bundled advisory snapshot could not be loaded.", err=True)
        raise typer.Exit(code=1) from None
    console = Console(markup=False, highlight=False)
    console.print(f"schema_version: {snapshot.schema_version}")
    console.print(f"generated_at: {snapshot.generated_at}")
    table = Table("CVE ID", "Title", "CVSS", "Configuration-dependent", "Fixed versions")
    for cve_id, details in snapshot.cves.items():
        dependent = details.get("configuration_dependent", False) is True
        table.add_row(
            cve_id,
            str(details.get("title", "")),
            str(details.get("cvss_v4", "unknown")),
            "yes" if dependent else "no",
            "Not established" if dependent else ", ".join(snapshot.fixed_versions.values()),
        )
    console.print(table)
    for cve_id, details in snapshot.cves.items():
        if details.get("rating_notes"):
            console.print(f"{cve_id}: {details['rating_notes']}")
    console.print("Mitigations:")
    for mitigation in snapshot.mitigations:
        console.print(f"- {mitigation}")
    console.print(f"References: {len(snapshot.references)}")


@app.command()
def tui() -> None:
    """Open the detection-only TUI; authorization is required before scanning."""
    try:
        from php2shell_audit.tui import run_tui
    except ImportError:
        typer.echo("Error: TUI is unavailable; check the Textual installation.", err=True)
        raise typer.Exit(code=1) from None
    run_tui()


def _lab(args: tuple[str, ...]) -> None:
    docker = shutil.which("docker")
    if docker is None:
        typer.echo("Error: docker is not installed or not on PATH.", err=True)
        raise typer.Exit(code=1)
    compose = Path(__file__).resolve().parents[2] / "lab" / "compose.yaml"
    env_file = compose.with_name(".env")
    compose_args = [docker, "compose", "-f", str(compose)]
    if env_file.is_file():
        compose_args.extend(("--env-file", str(env_file)))
    try:
        result = subprocess.run(  # noqa: S603 - resolved Docker executable and fixed lab arguments.
            [*compose_args, *args],
            check=False,
            text=True,
            capture_output=True,
            timeout=300,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        typer.echo("Error: docker compose could not complete within 300 seconds.", err=True)
        raise typer.Exit(code=1) from None
    except KeyboardInterrupt:
        typer.echo("Interrupted.", err=True)
        raise typer.Exit(code=130) from None
    if result.stdout:
        typer.echo(result.stdout, err=result.returncode != 0, nl=False)
    if result.stderr:
        typer.echo(result.stderr, err=True, nl=False)
    if result.returncode:
        typer.echo(f"Error: docker compose {' '.join(args)} exited {result.returncode}.", err=True)
        raise typer.Exit(code=1)


@lab_app.command("up")
def lab_up() -> None:
    """Start the loopback-only vulnerable and fixed detection fixtures."""
    _lab(("up", "-d", "--wait", "--wait-timeout", "60"))
    typer.echo("Lab is ready.")
    typer.echo("DEFAULT ports (not actual URLs when overridden):")
    typer.echo("Vulnerable fixture default: http://127.0.0.1:18080")
    typer.echo("Fixed fixture default: http://127.0.0.1:18081")
    typer.echo("Override ports with lab/.env; use ./lab/scripts/up.sh for actual URLs.")
    typer.echo("Teardown: php2shell-audit lab down (docker compose down -v --remove-orphans).")


@lab_app.command("down")
def lab_down() -> None:
    """Remove the local detection fixtures, their volumes, and orphaned containers."""
    _lab(("down", "-v", "--remove-orphans"))


@lab_app.command("status")
def lab_status() -> None:
    """Show the local detection fixtures' Compose status."""
    _lab(("ps",))
