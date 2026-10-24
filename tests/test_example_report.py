import json
import runpy
import socket
from datetime import datetime
from hashlib import sha256

# False positive under requires-python >=3.12; tracked under TASK-002.
# nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "examples" / "generate_report.py"


@pytest.fixture
def artifacts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, Path]:
    with (
        patch.object(socket, "getaddrinfo", side_effect=AssertionError("Real DNS forbidden")),
        patch.object(
            socket.socket, "connect", side_effect=AssertionError("Real network forbidden")
        ),
        patch.object(
            httpx.HTTPTransport,
            "handle_request",
            side_effect=AssertionError("Real HTTP forbidden"),
        ),
        patch("sys.argv", [str(SCRIPT), "--output-dir", str(tmp_path)]),
        pytest.raises(SystemExit) as exited,
    ):
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert exited.value.code == 0
    paths = {path.suffix: path for path in tmp_path.iterdir()}
    output = capsys.readouterr().out
    assert all(str(path) in output for path in paths.values())
    assert all("Synthetic observations only" in line for line in output.splitlines())
    return paths


@pytest.mark.parametrize(
    ("index", "host", "version", "verdict"),
    [
        (0, "affected", "8.4.26", "VULNERABLE_VERSION"),
        (1, "fixed", "8.4.27", "NOT_VULNERABLE_VERSION"),
        (2, "hidden", None, "POTENTIALLY_VULNERABLE_VERSION_UNKNOWN"),
    ],
)
def test_fixture_outcomes_when_network_is_forbidden(
    artifacts: dict[str, Path], index: int, host: str, version: str | None, verdict: str
) -> None:
    report = json.loads(artifacts[".json"].read_text(encoding="utf-8"))

    result = report["results"][index]

    assert result["target"]["url"] == f"https://{host}.example.test/"
    assert result["php"]["detected"] is True
    assert result["php"]["version"] == version
    assert result["verdict"] == verdict
    assert result["requests_made"] == 1
    assert result["error"] is None
    assessments = {item["cve_id"]: item for item in result["assessments"]}
    assert set(assessments) == {"CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"}
    for cve_id in ("CVE-2026-109618", "CVE-2026-109619"):
        assert assessments[cve_id]["verdict"] == verdict
        assert assessments[cve_id]["fixed_version"] == ("8.4.27" if version else None)
    configuration = assessments["CVE-2026-115560"]
    assert configuration["configuration_dependent"] is True
    assert configuration["verdict"] == "POTENTIALLY_VULNERABLE_VERSION_UNKNOWN"


def test_artifacts_when_generated_are_labeled_without_raw_body(artifacts: dict[str, Path]) -> None:
    assert set(artifacts) == {".json", ".jsonl", ".md", ".csv"}
    assert len({path.stem for path in artifacts.values()}) == 1
    for path in artifacts.values():
        assert path.stem.startswith("synthetic-example")
        assert "Synthetic fixture body" not in path.read_text(encoding="utf-8")
    assert (
        artifacts[".md"]
        .read_text(encoding="utf-8")
        .startswith("# Synthetic Offline Example Report\n")
    )


def test_provenance_when_generated_identifies_actual_advisory_snapshot(
    artifacts: dict[str, Path],
) -> None:
    snapshot = files("php2shell_audit").joinpath("data/php2shell.json").read_bytes()
    source = json.loads(snapshot)

    report = json.loads(artifacts[".json"].read_text(encoding="utf-8"))

    assert report["advisory"] == {
        "schema_version": source["schema_version"],
        "snapshot_date": source["generated_at"],
        "snapshot_sha256": sha256(snapshot).hexdigest(),
    }


def test_evidence_when_generated_links_assessments_to_simulated_root_request(
    artifacts: dict[str, Path],
) -> None:
    report = json.loads(artifacts[".json"].read_text(encoding="utf-8"))

    results = report["results"]

    for result in results:
        php_evidence = result["php"]["evidence"]
        assert php_evidence[0]["source"] == "header:x-powered-by"
        request = php_evidence[0]["request"]
        assert request["method"] == "GET"
        assert request["requested_url"] == request["final_url"] == result["target"]["url"]
        assert request["status_code"] == 200
        assert request["body_prefix_bytes"] > 0
        assert request["body_truncated"] is False
        assert (
            datetime.fromisoformat(report["started_at"])
            <= datetime.fromisoformat(request["observed_at"])
            <= datetime.fromisoformat(report["finished_at"])
        )
        for assessment in result["assessments"][:2]:
            assert assessment["evidence"] == php_evidence
            assert assessment["basis"] == "observed_version"
            assert assessment["observed_version"] == result["php"]["version"]
            assert assessment["remediation"]
            assert assessment["verification"]
            assert assessment["references"]
        configuration = result["assessments"][2]
        assert configuration["basis"] == "unverified_configuration"
        assert configuration["evidence"] == []


def test_generator_when_repeated_preserves_existing_artifacts(tmp_path: Path) -> None:
    occupied = tmp_path / "synthetic-example.json"
    occupied.write_text("existing report", encoding="utf-8")

    with (
        patch("sys.argv", [str(SCRIPT), "--output-dir", str(tmp_path)]),
        pytest.raises(SystemExit) as exited,
    ):
        runpy.run_path(str(SCRIPT), run_name="__main__")

    assert exited.value.code == 0
    assert occupied.read_text(encoding="utf-8") == "existing report"
    assert {path.name for path in tmp_path.iterdir()} == {
        "synthetic-example.json",
        "synthetic-example-1.json",
        "synthetic-example-1.jsonl",
        "synthetic-example-1.md",
        "synthetic-example-1.csv",
    }


def test_generator_when_given_target_rejects_it_before_writing(tmp_path: Path) -> None:
    with (
        patch("sys.argv", [str(SCRIPT), "https://outside.test", "--output-dir", str(tmp_path)]),
        pytest.raises(SystemExit) as exited,
    ):
        runpy.run_path(str(SCRIPT), run_name="__main__")

    assert exited.value.code == 2
    assert list(tmp_path.iterdir()) == []
