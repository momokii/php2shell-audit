import json
from pathlib import Path

import httpx

from php2shell_audit.models import ScanConfig, Target, Verdict
from php2shell_audit.reporting import write_all
from php2shell_audit.scanner import Scanner


def handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    version = "8.4.27" if host == "fixed.example.test" else "8.4.26"
    return httpx.Response(
        200,
        headers={"X-Powered-By": f"PHP/{version}", "Server": "Apache/2.4"},
        content=b"lab fixture",
    )


def test_scan_and_write_all_report_formats(tmp_path: Path) -> None:
    config = ScanConfig(authorized=True, deep=False)
    targets = [
        Target("https://vulnerable.example.test/"),
        Target("https://fixed.example.test/"),
    ]
    transport = httpx.MockTransport(handler)

    def resolver(host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    with Scanner(config, transport=transport, resolver=resolver) as scanner:
        report = scanner.scan_many(targets)

    assert len(report.results) == 2
    vulnerable, fixed = report.results
    assert vulnerable.verdict is Verdict.VULNERABLE_VERSION
    assert vulnerable.php.version == "8.4.26"
    assert fixed.verdict is Verdict.NOT_VULNERABLE_VERSION
    assert fixed.php.version == "8.4.27"

    for result in report.results:
        assert len(result.assessments) == 3
        assert result.assessments[2].cve_id == "CVE-2026-115560"
        assert result.assessments[2].configuration_dependent is True
        assert result.error is None

    paths = write_all(report, tmp_path, formats=("json", "jsonl", "markdown", "csv"))

    assert set(paths) == {"json", "jsonl", "markdown", "csv"}
    for path in paths.values():
        assert path.exists()
        assert path.is_relative_to(tmp_path)

    json_report = json.loads(paths["json"].read_text())
    assert json_report["schema_version"] == 1
    assert len(json_report["results"]) == 2

    jsonl_lines = [line for line in paths["jsonl"].read_text().splitlines() if line]
    jsonl_records = [json.loads(line) for line in jsonl_lines]
    assert jsonl_records[0]["type"] == "report"
    assert len(jsonl_records) == 3

    markdown = paths["markdown"].read_text()
    assert "not proof of exploitability" in markdown
    assert "CVE-2026-109618" in markdown

    csv_lines = paths["csv"].read_text().splitlines()
    assert csv_lines[0] == (
        "target,verdict,php_detected,php_version,sapi,waf,assessments,findings,requests_made,error"
    )
    assert len(csv_lines) == 3
