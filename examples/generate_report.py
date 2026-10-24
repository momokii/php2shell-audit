"""Generate synthetic reports offline using the installed project's public APIs.

Run from the checkout: ``uv run python examples/generate_report.py``.
No target input is accepted. ``--portfolio`` explicitly replaces the checked-in
Markdown example; ordinary runs only create collision-safe report artifacts.
"""

from pathlib import Path
from typing import Annotated, Final

import httpx
import typer

from php2shell_audit.models import ScanConfig, Target
from php2shell_audit.reporting import write_all
from php2shell_audit.scanner import Scanner

_BANNERS: Final = {
    "affected.example.test": "PHP/8.4.26",
    "fixed.example.test": "PHP/8.4.27",
    "hidden.example.test": "PHP",
}
_INTRODUCTION: Final = """# Synthetic Offline Example Report

> **Synthetic observations only. No external-site scan was performed.**
> All three `.test` hosts and their HTTP responses are fixed in-memory fixtures,
> not real websites or claims about deployed systems. Advisory references below
> describe the bundled rules; they do not authenticate these synthetic banners.

## Reproduce This Example

From a source checkout with dependencies installed:

```bash
uv run python examples/generate_report.py
```

This uses the public `Scanner` and `write_all` APIs with `httpx.MockTransport`
and a constant injected resolver. No real DNS, HTTP, Docker, or audit log is
used. Each fixture receives exactly one simulated root `GET`; deep probes are
disabled. Artifacts are created under ignored `reports/demo/` with a shared
`synthetic-example` stem and collision suffixes, without replacing earlier runs.
Use `--output-dir DIRECTORY` to select another artifact directory.

To explicitly regenerate and replace this portfolio Markdown from the current
renderer, run:

```bash
uv run python examples/generate_report.py --portfolio
```

The dossier below is the actual writer output with this introduction prepended,
not a hand-authored set of findings. PHP 8.4.26 demonstrates an affected-version
match, 8.4.27 the corresponding fixed-version match, and a versionless PHP banner
an unknown version. Configuration-dependent CVE-2026-115560 remains unknown in
all three cases. No exploitation, installed-runtime verification, or real-site
audit is demonstrated. Timestamps and measured timings vary between runs;
fixture inputs and expected verdicts are reproducible, not byte-identical output.
No full response body is retained in the reports.

---

"""


def _fixture_response(request: httpx.Request) -> httpx.Response:
    """Serve only the fixed synthetic root requests; never open a connection."""
    if request.method != "GET" or request.url.path != "/" or request.url.query:
        raise httpx.UnsupportedProtocol("Synthetic fixtures accept only root GET requests")
    return httpx.Response(
        200,
        headers={
            "X-Powered-By": _BANNERS[request.url.host],
            "Content-Type": "text/html; charset=utf-8",
        },
        text="<html><body>Synthetic fixture body, not retained in evidence.</body></html>",
    )


def generate_report(output_dir: Path) -> dict[str, Path]:
    """Write four collision-safe synthetic artifacts without real DNS or HTTP."""
    with Scanner(
        ScanConfig(authorized=True, rate_limit=0, max_requests=1, deep=False),
        transport=httpx.MockTransport(_fixture_response),
        resolver=lambda host: ("93.184.216.34",),
    ) as scanner:
        report = scanner.scan_many(Target(f"https://{host}/") for host in _BANNERS)
    paths = write_all(report, output_dir, stem="synthetic-example")
    markdown = paths["markdown"]
    markdown.write_text(_INTRODUCTION + markdown.read_text(encoding="utf-8"), encoding="utf-8")
    return paths


def main(
    output_dir: Annotated[Path, typer.Option(help="Synthetic artifact directory.")] = Path(
        "reports/demo"
    ),
    portfolio: Annotated[
        bool,
        typer.Option(help="Explicitly replace docs/example-report.md with this synthetic run."),
    ] = False,
) -> None:
    """Generate synthetic observations only; no external-site scan is performed."""
    paths = generate_report(output_dir)
    for name, path in paths.items():
        typer.echo(f"Synthetic observations only (no external-site scan), {name}: {path}")
    if portfolio:
        destination = Path(__file__).resolve().parents[1] / "docs" / "example-report.md"
        destination.write_text(paths["markdown"].read_text(encoding="utf-8"), encoding="utf-8")
        typer.echo(f"Synthetic observations only (no external-site scan), portfolio: {destination}")


if __name__ == "__main__":
    typer.run(main)
