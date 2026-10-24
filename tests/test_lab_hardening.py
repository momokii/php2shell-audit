"""Check least-privilege lab settings through offline Compose rendering."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Final

import pytest

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def rendered_compose() -> str:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is not installed")
    availability = subprocess.run(  # noqa: S603 - Resolved Docker executable, fixed offline arguments.
        [docker, "compose", "version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if availability.returncode != 0:
        pytest.skip("Docker Compose is unavailable")
    result = subprocess.run(  # noqa: S603 - Resolved Docker executable, fixed offline arguments.
        [docker, "compose", "-f", "lab/compose.yaml", "config", "--format", "json"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize("service_name", ["vulnerable", "fixed", "static"])
@pytest.mark.parametrize(
    "requirement",
    [
        ("cap_drop", ["ALL"]),
        ("cap_add", []),
        ("read_only", True),
        ("cpus", 0.5),
        ("pids_limit", 128),
        ("sysctls", {"net.ipv4.ip_unprivileged_port_start": "0"}),
    ],
)
def test_service_hardening_when_compose_is_rendered(
    rendered_compose: str,
    service_name: str,
    requirement: tuple[str, str | list[str] | bool | int | float | dict[str, str]],
) -> None:
    setting, expected = requirement

    service = json.loads(rendered_compose)["services"][service_name]

    assert service.get(setting, [] if setting == "cap_add" else None) == expected


@pytest.mark.parametrize(
    ("service_name", "user"),
    [("vulnerable", "33:33"), ("fixed", "33:33"), ("static", "65534:65534")],
)
def test_service_user_when_compose_is_rendered(
    rendered_compose: str, service_name: str, user: str
) -> None:
    service = json.loads(rendered_compose)["services"][service_name]

    assert service["user"] == user


@pytest.mark.parametrize("service_name", ["vulnerable", "fixed", "static"])
def test_memory_is_bounded_when_compose_is_rendered(
    rendered_compose: str, service_name: str
) -> None:
    expected_bytes = 256 * 1024 * 1024

    service = json.loads(rendered_compose)["services"][service_name]

    assert int(service["mem_limit"]) == expected_bytes


def test_static_writable_state_when_root_is_read_only(rendered_compose: str) -> None:
    service = json.loads(rendered_compose)["services"]["static"]
    mounts = {
        target: set(options.split(","))
        for target, options in (mount.split(":", 1) for mount in service["tmpfs"])
    }

    assert mounts == {"/tmp": {"mode=1777", "size=64m"}}  # noqa: S108 - Container mount, not host temporary I/O.


@pytest.mark.parametrize("service_name", ["vulnerable", "fixed"])
def test_writable_state_when_root_is_read_only(rendered_compose: str, service_name: str) -> None:
    expected_mounts = {
        "/tmp": {"mode=1777", "size=64m"},  # noqa: S108 - Container mount, not host temporary I/O.
        "/var/run/apache2": {"uid=33", "gid=33", "mode=0755", "size=16m"},
        "/var/lock/apache2": {"uid=33", "gid=33", "mode=0755", "size=16m"},
    }

    service = json.loads(rendered_compose)["services"][service_name]
    mounts = {
        target: set(options.split(","))
        for target, options in (mount.split(":", 1) for mount in service["tmpfs"])
    }

    assert mounts == expected_mounts
