"""Offline CLI contracts with forbidden external side effects."""

import socket
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from php2shell_audit import cli, safety
from php2shell_audit.cli import app
from php2shell_audit.models import PhpInfo, Sapi, ScanReport, Target, TargetResult, Verdict, Waf
from php2shell_audit.safety import AuthorizationError, SafetyError


@pytest.fixture(autouse=True)
def prevent_external_activity(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Unexpected DNS, scanner, logger, or report activity")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(safety, "resolve_host", forbidden)
    for name in ("Scanner", "AuditLogger", "write_all"):
        monkeypatch.setattr(cli, name, forbidden, raising=False)


def test_version_prints_version_when_invoked() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["version"])

    if (result.exit_code, result.stdout.strip()) != (0, "php2shell-audit 0.1.0"):
        pytest.fail(f"Unexpected version result: {result.exit_code}, {result.output!r}")


def test_scan_exits_two_when_authorization_is_missing() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["scan", "example.com"])

    if result.exit_code != 2:
        pytest.fail(f"Unauthorized scan exited {result.exit_code}, expected 2")
    if "--authorized" not in result.stderr or result.stdout:
        pytest.fail("Unauthorized scan must explain the required flag only on stderr")


def test_dry_run_has_no_external_activity() -> None:
    result = CliRunner().invoke(app, ["scan", "--dry-run", "--authorized", "example.com"])

    assert result.exit_code == 0, result.output
    assert "Dry run" in result.stdout
    assert "no DNS resolution" in result.stdout


def test_version_output_is_exact() -> None:
    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout == "php2shell-audit 0.1.0\n"
    assert result.stderr == ""


def test_authorization_precedes_normalization_and_option_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalize = MagicMock(side_effect=AssertionError("Normalization before authorization"))
    monkeypatch.setattr(cli, "normalize_target", normalize, raising=False)

    result = CliRunner().invoke(app, ["scan", "ftp://bad", "--format", "invalid"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr == "Error: explicit authorization is required; pass --authorized.\n"
    normalize.assert_not_called()


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--format", "xml"),
        ("--fail-on", "always"),
        ("--rate-limit", "-1"),
        ("--timeout", "0"),
        ("--timeout", "nan"),
        ("--rate-limit", "inf"),
        ("--max-requests", "0"),
        ("--max-requests", "101"),
        ("--max-targets", "51"),
    ],
)
def test_invalid_options_exit_two(option: str, value: str) -> None:
    result = CliRunner().invoke(app, ["scan", "example.com", "--authorized", option, value])

    assert result.exit_code == 2
    assert result.stderr


def test_invalid_target_is_safe() -> None:
    result = CliRunner().invoke(app, ["scan", "https://user:secret@example.com", "--authorized"])

    assert result.exit_code == 2
    assert "secret" not in result.output


def test_target_cap_precedes_scanning() -> None:
    result = CliRunner().invoke(
        app, ["scan", "a.example", "b.example", "--authorized", "--max-targets", "1"]
    )

    assert result.exit_code == 2
    assert "--max-targets" in result.stderr


def test_normalized_duplicates_count_once() -> None:
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "EXAMPLE.com",
            "https://example.com",
            "--authorized",
            "--max-targets",
            "1",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert result.stdout.count("https://example.com") == 1


@pytest.mark.parametrize(("host", "exit_code"), [("outside.test", 2), ("app.example.com", 0)])
def test_scope_is_checked_without_dns(tmp_path: Path, host: str, exit_code: int) -> None:
    scope = tmp_path / "scope.txt"
    scope.write_text("# Authorized hosts\nexample.com\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["scan", host, "--authorized", "--scope", str(scope), "--dry-run"]
    )

    assert result.exit_code == exit_code, result.output


@pytest.fixture
def scan_fakes(monkeypatch: pytest.MonkeyPatch) -> tuple[MagicMock, MagicMock, MagicMock]:
    constructor = MagicMock()
    constructor.return_value.__enter__.return_value.scan_many.return_value = ScanReport()
    logger = MagicMock()
    writer = MagicMock(return_value={})
    monkeypatch.setattr(cli, "Scanner", constructor)
    monkeypatch.setattr(cli, "AuditLogger", logger)
    monkeypatch.setattr(cli, "write_all", writer)
    return constructor, logger, writer


@pytest.mark.parametrize(
    ("policy", "verdict", "exit_code"),
    [
        ("vulnerable", Verdict.VULNERABLE_VERSION, 1),
        ("vulnerable", Verdict.NOT_VULNERABLE_VERSION, 0),
        ("unknown", Verdict.POTENTIALLY_VULNERABLE_VERSION_UNKNOWN, 1),
        ("unknown", Verdict.WAF_BLOCKED, 1),
        ("unknown", Verdict.UNREACHABLE, 1),
        ("unknown", Verdict.NOT_VULNERABLE_VERSION, 0),
        ("unknown", Verdict.BLOCKED_BY_SAFETY, 0),
        ("never", Verdict.VULNERABLE_VERSION, 0),
        ("never", Verdict.UNREACHABLE, 0),
    ],
)
def test_scan_failure_policy(
    tmp_path: Path,
    scan_fakes: tuple[MagicMock, MagicMock, MagicMock],
    policy: str,
    verdict: Verdict,
    exit_code: int,
) -> None:
    constructor, _, writer = scan_fakes
    report = ScanReport(
        (
            TargetResult(
                Target("https://example.com"),
                verdict,
                PhpInfo(True, "8.4.27", Sapi.FPM),
                Waf.NONE,
                requests_made=1,
            ),
        )
    )
    constructor.return_value.__enter__.return_value.scan_many.return_value = report

    result = CliRunner().invoke(
        app,
        ["scan", "example.com", "--authorized", "--output-dir", str(tmp_path), "--fail-on", policy],
    )

    assert result.exit_code == exit_code, result.output
    writer.assert_called_once_with(report, tmp_path, formats=("json", "jsonl", "markdown", "csv"))
    assert "8.4.27" in result.stdout
    assert "A version match is exposure evidence, not proof of exploitability." in result.stdout


@pytest.mark.parametrize("report_format", ["json", "jsonl", "markdown", "md", "csv"])
def test_scan_passes_options_and_selected_format(
    tmp_path: Path, scan_fakes: tuple[MagicMock, MagicMock, MagicMock], report_format: str
) -> None:
    constructor, logger, writer = scan_fakes
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\nother.test\n", encoding="utf-8")
    writer.return_value = {report_format: tmp_path / "report.txt"}

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "other.test",
            "EXAMPLE.com",
            "other.test",
            "--authorized",
            "--scope",
            str(scope),
            "--output-dir",
            str(tmp_path),
            "--format",
            report_format,
            "--rate-limit",
            "0",
            "--timeout",
            "2",
            "--max-requests",
            "3",
            "--deep",
            "--allow-private",
            "--verbose",
        ],
    )

    assert result.exit_code == 0, result.output
    config = constructor.call_args.args[0]
    assert config.to_dict() == {
        "authorized": True,
        "scope_file": str(scope),
        "output_dir": str(tmp_path),
        "rate_limit": 0.0,
        "timeout": 2.0,
        "max_requests": 3,
        "max_redirects": 5,
        "max_response_bytes": 1048576,
        "deep": True,
        "allow_private": True,
    }
    constructor.return_value.__enter__.return_value.scan_many.assert_called_once_with(
        [Target("https://other.test"), Target("https://example.com")]
    )
    logger.assert_called_once_with(log_dir="logs", level="DEBUG", console=True)
    assert writer.call_args.kwargs["formats"] == (report_format,)
    assert f"{report_format}: {tmp_path / 'report.txt'}" in result.stdout
    constructor.return_value.__exit__.assert_called_once()
    logger.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize(
    ("failure", "exit_code"),
    [
        (AuthorizationError("denied", "Authorization denied."), 2),
        (SafetyError("blocked", "Target blocked."), 2),
        (ValueError("sensitive"), 1),
        (KeyboardInterrupt(), 130),
    ],
)
@pytest.mark.parametrize("stage", ["construct", "scan", "write"])
def test_expected_failures_are_safe(
    tmp_path: Path,
    scan_fakes: tuple[MagicMock, MagicMock, MagicMock],
    failure: BaseException,
    exit_code: int,
    stage: str,
) -> None:
    constructor, _, writer = scan_fakes
    boundary = {
        "construct": constructor,
        "scan": constructor.return_value.__enter__.return_value.scan_many,
        "write": writer,
    }[stage]
    boundary.side_effect = failure

    result = CliRunner().invoke(
        app, ["scan", "example.com", "--authorized", "--output-dir", str(tmp_path)]
    )

    assert result.exit_code == exit_code, result.output
    assert "sensitive" not in result.output
    assert "Traceback" not in result.output
    assert result.stderr
    if exit_code == 130:
        assert result.stderr == "Interrupted.\n"


def test_advisories_displays_bundled_snapshot() -> None:
    result = CliRunner().invoke(app, ["advisories"], env={"COLUMNS": "180"})

    assert result.exit_code == 0, result.output
    for value in (
        "schema_version",
        "generated_at",
        "CVE-2026-109618",
        "CVE-2026-109619",
        "CVE-2026-115560",
        "8.4.27",
        "9.2",
        "References",
    ):
        assert value in result.stdout


@pytest.mark.parametrize("failure", [ValueError("sensitive"), OSError("sensitive")])
def test_advisory_errors_are_safe(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    monkeypatch.setattr(cli, "load_advisories", MagicMock(side_effect=failure), raising=False)

    result = CliRunner().invoke(app, ["advisories"])

    assert result.exit_code == 1
    assert "Error:" in result.stderr
    assert "sensitive" not in result.output


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("up", ["up", "-d", "--wait", "--wait-timeout", "60"]),
        ("down", ["down", "-v", "--remove-orphans"]),
        ("status", ["ps"]),
    ],
)
@pytest.mark.parametrize("has_env_file", [False, True])
def test_lab_uses_fixed_compose_arguments(
    monkeypatch: pytest.MonkeyPatch, command: str, args: list[str], has_env_file: bool
) -> None:
    compose = Path(cli.__file__).resolve().parents[2] / "lab" / "compose.yaml"
    env_file = compose.with_name(".env")
    monkeypatch.setattr(Path, "is_file", lambda path: has_env_file and path == env_file)
    run = MagicMock(
        return_value=subprocess.CompletedProcess(
            [], 0, stdout="lab output\n", stderr="lab diagnostic\n"
        )
    )
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(cli.subprocess, "run", run)

    result = CliRunner().invoke(app, ["lab", command])

    assert result.exit_code == 0, result.output
    env_args = ["--env-file", str(env_file)] if has_env_file else []
    run.assert_called_once_with(
        ["/usr/bin/docker", "compose", "-f", str(compose), *env_args, *args],
        check=False,
        text=True,
        capture_output=True,
        timeout=300,
        shell=False,
    )
    assert "lab output" in result.stdout
    assert "lab diagnostic" in result.stderr
    if command == "up":
        assert "DEFAULT ports" in result.stdout
        assert "./lab/scripts/up.sh" in result.stdout
        assert "http://127.0.0.1:18080" in result.stdout
        assert "http://127.0.0.1:18081" in result.stdout
        assert "down -v" in result.stdout
        assert "lab/.env" in result.stdout
        assert "php2shell-audit lab down" in result.stdout
        assert "docker compose down -v --remove-orphans" in result.stdout


@pytest.mark.parametrize("returncode", [1, 17])
def test_lab_failure_reports_captured_output(
    monkeypatch: pytest.MonkeyPatch, returncode: int
) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        MagicMock(
            return_value=subprocess.CompletedProcess([], returncode, stdout="out", stderr="err")
        ),
    )

    result = CliRunner().invoke(app, ["lab", "up"])

    assert result.exit_code == 1
    assert "out" in result.stderr and "err" in result.stderr
    assert (
        f"Error: docker compose up -d --wait --wait-timeout 60 exited {returncode}."
        in result.stderr
    )


def test_lab_requires_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    run = MagicMock(side_effect=AssertionError("Docker must not run"))
    monkeypatch.setattr(cli.subprocess, "run", run)

    result = CliRunner().invoke(app, ["lab", "status"])

    assert result.exit_code == 1
    assert result.stderr == "Error: docker is not installed or not on PATH.\n"
    run.assert_not_called()


def test_tui_calls_lazy_entrypoint(monkeypatch: pytest.MonkeyPatch) -> None:
    module = ModuleType("php2shell_audit.tui")
    run = MagicMock()
    setattr(module, "run_tui", run)
    monkeypatch.setitem(sys.modules, "php2shell_audit.tui", module)

    result = CliRunner().invoke(app, ["tui"])

    assert result.exit_code == 0, result.output
    run.assert_called_once_with()


def test_tui_missing_import_is_clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "php2shell_audit.tui", None)

    result = CliRunner().invoke(app, ["tui"])

    assert result.exit_code == 1
    assert "Error:" in result.stderr
    assert "TUI" in result.stderr
