"""Check local lab assets offline, optionally validating them with Compose."""

import json
import os
import shutil
import subprocess
import sys
from ipaddress import IPv4Address
from pathlib import Path
from typing import Final

import pytest

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
LAB_ROOT: Final = PROJECT_ROOT / "lab"


@pytest.mark.parametrize(
    "required_text",
    [
        "name: php2shell-lab",
        "vulnerable:",
        "fixed:",
        "php:8.4.26-apache",
        "php:8.4.27-apache",
        '"127.0.0.1:${LAB_VULNERABLE_PORT:-18080}:80"',
        '"127.0.0.1:${LAB_FIXED_PORT:-18081}:80"',
        "./www:/var/www/html:ro",
        "./healthcheck.php:/usr/local/bin/lab-healthcheck.php:ro",
        'test: ["CMD", "php", "/usr/local/bin/lab-healthcheck.php"]',
        "interval: 2s",
        "timeout: 3s",
        "retries: 15",
        "start_period: 5s",
        'restart: "no"',
        "no-new-privileges:true",
    ],
)
def test_compose_contains_required_local_configuration(required_text: str) -> None:
    compose = LAB_ROOT / "compose.yaml"

    content = compose.read_text(encoding="utf-8")

    assert required_text in content


@pytest.mark.parametrize(
    "forbidden_text",
    [str(IPv4Address(0)), "privileged:", "network_mode:", "secrets:", "LAB_BIND_ADDRESS"],
)
def test_compose_excludes_unsafe_configuration(forbidden_text: str) -> None:
    compose = LAB_ROOT / "compose.yaml"

    content = compose.read_text(encoding="utf-8")

    assert forbidden_text not in content


def test_index_exposes_version_for_detector_validation() -> None:
    index = LAB_ROOT / "www" / "index.php"

    content = index.read_text(encoding="utf-8")

    assert content.startswith("<?php declare(strict_types=1);")
    assert "PHP_VERSION" in content
    assert "X-Powered-By" in content
    assert "Content-Type: text/plain; charset=utf-8" in content


def test_phpinfo_exposes_only_general_information() -> None:
    phpinfo = LAB_ROOT / "www" / "phpinfo.php"

    content = phpinfo.read_text(encoding="utf-8")

    assert content.startswith("<?php declare(strict_types=1);")
    assert "phpinfo(INFO_GENERAL);" in content


def test_lab_instructions_include_teardown_and_loopback_warning() -> None:
    readme = LAB_ROOT / "README.md"

    content = readme.read_text(encoding="utf-8")

    assert "docker compose -f lab/compose.yaml down -v" in content
    assert "loopback-only" in content.lower()


def test_healthcheck_uses_only_local_php_http_readiness() -> None:
    content = (LAB_ROOT / "healthcheck.php").read_text(encoding="utf-8")

    assert content.startswith("<?php declare(strict_types=1);")
    assert "fsockopen('127.0.0.1', 80," in content
    assert ", 2);" in content
    assert r"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n" in content
    assert "fgets(" in content
    assert "'200'" in content
    assert "STDERR" in content
    assert "exit(0);" in content
    assert "exit(1);" in content
    for forbidden in ("curl", "exec(", "system(", "shell_exec(", "passthru(", "popen(", "`"):
        assert forbidden not in content


def test_env_example_overrides_only_host_ports() -> None:
    content = (LAB_ROOT / ".env.example").read_text(encoding="utf-8")

    settings = [line for line in content.splitlines() if line and not line.startswith("#")]
    assert settings == ["LAB_VULNERABLE_PORT=18080", "LAB_FIXED_PORT=18081"]
    assert "LAB_BIND_ADDRESS" not in content


def test_lifecycle_scripts_are_executable_and_have_valid_bash_syntax() -> None:
    scripts = [LAB_ROOT / "scripts" / name for name in ("up.sh", "down.sh", "verify.sh")]
    for script in scripts:
        assert script.stat().st_mode & 0o111
        content = script.read_text(encoding="utf-8")
        assert content.startswith("#!/usr/bin/env bash\nset -euo pipefail\n")
        assert "eval " not in content
        assert "source " not in content
        assert "LAB_BIND_ADDRESS" not in content
        result = subprocess.run(  # noqa: S603 - Fixed syntax-only arguments, no shell.
            ["bash", "-n", str(script)],  # noqa: S607 - Standard Bash executable.
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
            timeout=30,
        )

        assert result.returncode == 0, result.stdout + result.stderr


def test_lifecycle_scripts_wait_cleanup_and_verify_both_verdicts() -> None:
    up = (LAB_ROOT / "scripts" / "up.sh").read_text(encoding="utf-8")
    down = (LAB_ROOT / "scripts" / "down.sh").read_text(encoding="utf-8")
    verify = (LAB_ROOT / "scripts" / "verify.sh").read_text(encoding="utf-8")

    assert "--wait --wait-timeout 60" in up
    assert "down -v --remove-orphans" in down
    assert "VULNERABLE_VERSION" in verify
    assert "NOT_VULNERABLE_VERSION" in verify
    assert "KEEP_LAB" in verify
    assert "trap " in verify
    assert "reports/qa/lab-vulnerable" in verify
    assert "reports/qa/lab-fixed" in verify


@pytest.mark.parametrize("optimized", [False, True])
@pytest.mark.parametrize("evidence_port", [28080, 28081])
@pytest.mark.parametrize(
    "scenario",
    [
        "success",
        "wrong-verdict",
        "wrong-target",
        "stale",
        "duplicate",
        "cleanup-failure",
        "keep-lab",
        "failure-and-cleanup-failure",
        "missing-php",
        "wrong-version",
        "php-not-detected",
        "missing-assessments",
        "missing-assessment",
        "wrong-assessment",
        "duplicate-assessment",
    ],
)
def test_verify_when_using_offline_commands(
    tmp_path: Path, scenario: str, optimized: bool, evidence_port: int
) -> None:
    scripts = tmp_path / "lab" / "scripts"
    scripts.mkdir(parents=True)
    for name in ("up.sh", "down.sh", "verify.sh"):
        shutil.copy2(LAB_ROOT / "scripts" / name, scripts / name)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        'printf "%s\\n" "$*" >> "$DOCKER_CALLS"\n'
        'case "$4" in\n'
        'port) if [[ "$5" == vulnerable ]]; then echo 127.0.0.1:28080; '
        "else echo 127.0.0.1:28081; fi ;;\n"
        'down) exit "$CLEANUP_STATUS" ;;\nesac\n',
        encoding="utf-8",
    )
    uv = binaries / "uv"
    uv.write_text(
        f"#!{sys.executable}\n"
        + """import json
import os
import sys
from pathlib import Path

if sys.argv[2] == "python":
    os.execv(sys.executable, [sys.executable, *sys.argv[3:]])
if "--help" in sys.argv:
    raise SystemExit(0)
directory = Path(sys.argv[sys.argv.index("--output-dir") + 1])
directory.mkdir(parents=True, exist_ok=True)
mode = os.environ["SCAN_MODE"]
if mode == "stale":
    raise SystemExit(0)
url = sys.argv[4]
verdict = "VULNERABLE_VERSION" if url.endswith(":28080") else "NOT_VULNERABLE_VERSION"
if mode == "wrong-verdict":
    verdict = "UNREACHABLE"
if mode == "wrong-target":
    url = "http://127.0.0.1:1"
php = {"detected": True, "version": "8.4.26" if url.endswith(":28080") else "8.4.27"}
assessments = [
    {"cve_id": cve_id, "verdict": verdict}
    for cve_id in ("CVE-2026-109618", "CVE-2026-109619")
]
assessments.append({
    "cve_id": "CVE-2026-115560", "verdict": "POTENTIALLY_VULNERABLE_VERSION_UNKNOWN"
})
result = {"target": {"url": url}, "verdict": verdict, "php": php, "assessments": assessments}
if url.endswith(":" + os.environ["EVIDENCE_PORT"]):
    if mode == "missing-php":
        del result["php"]
    if mode == "wrong-version":
        php["version"] = "8.4.28"
    if mode == "php-not-detected":
        php["detected"] = False
    if mode == "missing-assessments":
        del result["assessments"]
    if mode == "missing-assessment":
        assessments.pop(1)
    if mode == "wrong-assessment":
        assessments[1]["verdict"] = "POTENTIALLY_VULNERABLE_VERSION_UNKNOWN"
    if mode == "duplicate-assessment":
        assessments.append(assessments[0].copy())
payload = json.dumps({"results": [result]})
(directory / "new.json").write_text(payload, encoding="utf-8")
if mode == "duplicate":
    (directory / "extra.json").write_text(payload, encoding="utf-8")
""",
        encoding="utf-8",
    )
    for executable in (docker, uv):
        executable.chmod(0o755)
    for fixture, port, verdict in (
        ("vulnerable", 28080, "VULNERABLE_VERSION"),
        ("fixed", 28081, "NOT_VULNERABLE_VERSION"),
    ):
        directory = tmp_path / "reports" / "qa" / f"lab-{fixture}"
        directory.mkdir(parents=True)
        (directory / "old.json").write_text(
            json.dumps(
                {"results": [{"target": {"url": f"http://127.0.0.1:{port}"}, "verdict": verdict}]}
            ),
            encoding="utf-8",
        )
    environment = os.environ.copy()
    environment.update(
        PATH=f"{binaries}{os.pathsep}{os.environ['PATH']}",
        DOCKER_CALLS=str(tmp_path / "docker-calls"),
        CLEANUP_STATUS="17" if "cleanup-failure" in scenario else "0",
        KEEP_LAB="1" if scenario == "keep-lab" else "0",
        SCAN_MODE="wrong-verdict" if scenario == "failure-and-cleanup-failure" else scenario,
        PYTHONOPTIMIZE="1" if optimized else "0",
        EVIDENCE_PORT=str(evidence_port),
    )

    result = subprocess.run(  # noqa: S603 - Isolated copied script with fake commands, no shell.
        [str(scripts / "verify.sh")],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )

    expected_code = (
        17 if scenario == "cleanup-failure" else (0 if scenario in {"success", "keep-lab"} else 1)
    )
    assert result.returncode == expected_code, result.stdout + result.stderr
    assert (" down -v --remove-orphans" in (tmp_path / "docker-calls").read_text()) == (
        scenario != "keep-lab"
    )
    if expected_code:
        assert "FAIL:" in result.stderr
        assert "Traceback" not in result.stderr
    else:
        assert result.stdout.count("PASS:") == 2
        assert "http://127.0.0.1:28080" in result.stdout
        assert "http://127.0.0.1:28081" in result.stdout
    if "cleanup-failure" in scenario:
        assert "cleanup exited 17" in result.stderr
    for fixture in ("vulnerable", "fixed"):
        directory = tmp_path / "reports" / "qa" / f"lab-{fixture}"
        assert (directory / "old.json").is_file()
        assert len(list(directory.glob("run.*"))) == 1
        assert f"reports/qa/lab-{fixture}/run." in result.stdout


@pytest.mark.parametrize("override", [False, True], ids=["defaults", "port-overrides"])
def test_compose_config_when_docker_compose_is_available(override: bool) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is not installed")
    availability = subprocess.run(  # noqa: S603 - Trusted resolved binary, fixed arguments, no shell.
        [docker, "compose", "version"],
        capture_output=True,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )
    if availability.returncode != 0:
        pytest.skip("Docker Compose is unavailable")

    environment = os.environ.copy()
    environment["LAB_VULNERABLE_PORT"] = "28080" if override else ""
    environment["LAB_FIXED_PORT"] = "28081" if override else ""
    result = subprocess.run(  # noqa: S603 - Trusted resolved binary, fixed arguments, no shell.
        [docker, "compose", "-f", "lab/compose.yaml", "config", "--format", "json"],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    services = json.loads(result.stdout)["services"]
    assert set(services) == {"vulnerable", "fixed"}
    for name, image, port in (
        ("vulnerable", "php:8.4.26-apache", 28080 if override else 18080),
        ("fixed", "php:8.4.27-apache", 28081 if override else 18081),
    ):
        service = services[name]
        assert service["image"] == image
        assert len(service["ports"]) == 1
        assert service["ports"][0]["host_ip"] == "127.0.0.1"
        assert int(service["ports"][0]["published"]) == port
        assert service["ports"][0]["target"] == 80
        assert service["restart"] == "no"
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["healthcheck"] == {
            "test": ["CMD", "php", "/usr/local/bin/lab-healthcheck.php"],
            "interval": "2s",
            "timeout": "3s",
            "retries": 15,
            "start_period": "5s",
        }
        mounts = {mount["target"]: mount for mount in service["volumes"]}
        for target, source in (
            ("/var/www/html", LAB_ROOT / "www"),
            ("/usr/local/bin/lab-healthcheck.php", LAB_ROOT / "healthcheck.php"),
        ):
            assert mounts[target]["type"] == "bind"
            assert mounts[target]["source"] == str(source)
            assert mounts[target]["read_only"] is True
