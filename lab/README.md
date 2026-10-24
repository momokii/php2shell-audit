# Local PHP Detector Lab

This minimal trio validates version detection against PHP 8.4.26 and PHP
8.4.27, plus a static control fixture with no PHP at all, not exploitation.
Version exposure evidence is not proof of exploitability. Scan only systems you
own or are explicitly authorized to assess.
Never publish or forward the vulnerable lab to a public interface.

## Prerequisites

Run commands from the project root of a **source checkout**. The lab assets are
not included in the installed wheel.

- Deployment and cleanup need Bash, Docker, a running Docker daemon, and Docker
  Compose with support for `--wait` and `--wait-timeout`.
- Docker-only deployment does not require Python or `uv` on the lab host.
- Automated verification and the optional application CLI require `uv` and
  Python 3.12. Run `uv sync` from the checkout before using them.
- The pinned images are pulled on first use; allow network access and disk space
  for `php:8.4.26-apache`, `php:8.4.27-apache`, and `busybox:1.36.1`.

## Deploy

```bash
./lab/scripts/up.sh
```

The script runs Docker Compose with `up -d --wait --wait-timeout 60`, waits for
healthy services, and prints the **actual URLs** discovered from published ports,
including any overrides. The defaults are:

| Service | Image | Default URL | Purpose |
|---|---|---|---|
| `vulnerable` | `php:8.4.26-apache` | `http://127.0.0.1:18080` | Affected-version detection |
| `fixed` | `php:8.4.27-apache` | `http://127.0.0.1:18081` | Fixed-version detection |
| `static` | `busybox:1.36.1` | `http://127.0.0.1:18082` | Non-PHP control (`NOT_PHP`) |

Both PHP containers use a PHP-based healthcheck that sends `HEAD /` to Apache
and expects HTTP 200; the static fixture uses a `wget` status check instead.
No host `curl` is required for readiness. All bindings are fixed to
`127.0.0.1`. Webroots and the healthcheck script are mounted read-only. All
services retain `no-new-privileges:true` and have automatic restart disabled.
Do not weaken these controls to troubleshoot startup.

The PHP services run as `www-data` (UID/GID 33) and the static fixture as
`nobody` (UID/GID 65534), all with Linux capabilities dropped and read-only
root filesystems. Bounded temporary filesystems provide only runtime state and
`/tmp`. Each service is limited to 256 MiB RAM, 0.5 CPU, and 128 processes.
The network-namespace setting `net.ipv4.ip_unprivileged_port_start=0` lets the
non-root servers bind their internal ports without adding a capability; it does
not change the host's port policy.
These controls do not make intentionally old PHP safe for public deployment.

### Customize Host Ports

Before starting, copy the example and edit the three port values in `lab/.env`:

```bash
cp lab/.env.example lab/.env
```

Set `LAB_VULNERABLE_PORT`, `LAB_FIXED_PORT`, and `LAB_STATIC_PORT` to different
available host ports. Do not change the loopback binding. The scripts and CLI
pass this file to Compose
as `--env-file`; **never source the file** or execute it as a shell script.
Use the URLs printed by `up.sh`, not the default examples, after customization.

## Automated Verification

With `uv`, Python 3.12, and the project environment available:

```bash
uv sync
./lab/scripts/verify.sh
```

The script starts the lab, discovers all three actual loopback URLs, and scans
each with `--authorized --allow-private --deep --format json`. Authorization
confirms existing permission; it does not grant it. Each invocation creates
fresh per-run subdirectories beneath `reports/qa/lab-vulnerable/`,
`reports/qa/lab-fixed/`, and `reports/qa/lab-static/` and prints their paths,
so stale reports cannot satisfy the checks.

For each directory it requires exactly one JSON report and one target result,
then checks the expected target URL and verdict. The PHP fixtures additionally
check the detected flag, the exact PHP version, and one matching assessment
for each version-mapped CVE. The static fixture must report `NOT_PHP` with no
detected version and no CVE assessments. Missing, duplicate, or incorrect
evidence fails verification. Expected results are:

| Fixture | Expected verdict |
|---|---|
| PHP 8.4.26 | `VULNERABLE_VERSION` |
| PHP 8.4.27 | `NOT_VULNERABLE_VERSION` |
| Static control | `NOT_PHP` (no version, no assessments) |

The version-mapped issues are CVE-2026-109618 and CVE-2026-109619.
CVE-2026-115560 remains configuration-dependent/unknown for both PHP fixtures;
the fixed version does not prove that configuration issue resolved. The script
checks version evidence and version-mapped assessments, not exploitability or
that configuration-dependent runtime condition.

Successful checks print `PASS` for each URL. Once lab startup is attempted,
an exit trap automatically tears down the lab on success, failure, or interruption.
A cleanup failure is reported and makes an otherwise successful run fail.
Dependency/CLI preflight failures occur before that trap is installed; if a lab
was already running, use the cleanup command below.

To retain containers for investigation, including after a failed check:

```bash
KEEP_LAB=1 ./lab/scripts/verify.sh
```

Reports remain on disk after container cleanup. Review them before sharing and
keep generated evidence out of source control.

## Optional Manual Inspection and CLI

With the lab running, these default-port examples provide a quick HTTP check
if `curl` is available. Substitute the actual URLs printed by `up.sh` when needed:

```bash
curl -sS http://127.0.0.1:18080/
curl -sS http://127.0.0.1:18081/
curl -sS http://127.0.0.1:18082/
```

The PHP index provides a lab banner, PHP version, and matching `X-Powered-By`
header. `/phpinfo.php` provides general PHP information for optional deep-probe
validation. The static fixture serves a plain page with no PHP indicators at all.

The application also exposes Compose lifecycle commands from the checkout:

```bash
uv run php2shell-audit lab up
uv run php2shell-audit lab status
uv run php2shell-audit lab down
```

`lab up` waits for health but labels its displayed URLs as **defaults**, not
actual overridden URLs. Prefer `./lab/scripts/up.sh` for actual URL discovery.

## Remote Host Through SSH Only

On an authorized remote lab host, use a source checkout and
`./lab/scripts/up.sh`. Only Docker deployment prerequisites are needed there.
Keep the remote published ports on `127.0.0.1`; do not open firewall ports or
publish the fixtures through a reverse proxy.

For the default remote ports, run this on your workstation and leave it open:

```bash
ssh -N -L 127.0.0.1:18080:127.0.0.1:18080 -L 127.0.0.1:18081:127.0.0.1:18081 -L 127.0.0.1:18082:127.0.0.1:18082 user@lab-host
```

Then scan workstation loopback from your local source checkout:

```bash
uv run php2shell-audit scan http://127.0.0.1:18080 --authorized --allow-private --deep --format json --output-dir reports/remote-lab-vulnerable
uv run php2shell-audit scan http://127.0.0.1:18081 --authorized --allow-private --deep --format json --output-dir reports/remote-lab-fixed
uv run php2shell-audit scan http://127.0.0.1:18082 --authorized --allow-private --deep --format json --output-dir reports/remote-lab-static
```

If remote ports were overridden, update each SSH destination port; if local ports
are occupied, select unused local forward ports and update the scan URLs.
Keep SSH listeners loopback-only; never enable public forwarding or use `-g`.
The verification script manages a local Docker lab, not this remote tunnel.
Stop SSH with Ctrl-C and run cleanup on the remote host when finished.

## Cleanup

```bash
./lab/scripts/down.sh
```

This uses the same optional `lab/.env` and runs Compose
`down -v --remove-orphans`, removing containers, networks, volumes, and orphan
services for this lab project. It does not delete generated reports or logs.
Run it explicitly after `KEEP_LAB=1` or a standalone deployment.

The basic direct Compose teardown is `docker compose -f lab/compose.yaml down -v`;
prefer the script for consistent env-file handling and orphan removal.

## Troubleshooting

| Symptom | Action |
|---|---|
| Docker missing or daemon unreachable | Install Docker/Compose, start the daemon, and check authorized access with `docker info`. |
| Unknown `--wait` or `--wait-timeout` option | Check `docker compose version` and upgrade Compose to a version supporting both options; do not bypass readiness. |
| Port already allocated | Stop the conflicting lab/service or edit the three host ports in `lab/.env`; rerun `up.sh` and use its printed URLs. |
| Startup times out or a service is unhealthy | Inspect `docker compose -f lab/compose.yaml ps -a` and `docker compose -f lab/compose.yaml logs --tail 100 vulnerable fixed static`. Keep healthchecks and `no-new-privileges` enabled. |
| Verification fails or containers disappear before inspection | Retry with `KEEP_LAB=1 ./lab/scripts/verify.sh`, inspect status/logs and the printed fresh report paths, then run `down.sh`. |
| CLI or Python unavailable | Use Python 3.12 and run `uv sync` in the checkout; deployment alone can still use the Docker-only scripts. |

For direct Compose diagnostic commands when using `lab/.env`, add
`--env-file lab/.env` after `-f lab/compose.yaml` to match the scripts.
`uv run php2shell-audit lab status` is also available with the project environment.

## Fixture Scope and Safety

The reference [dimasma0305/php2shell](https://github.com/dimasma0305/php2shell)
inspired deployment patterns only. No PoC, WordPress, or other exploit fixtures
were copied. These fixtures contain no exploit payloads, command execution,
uploads, or user-input handlers. The intentionally exposed `phpinfo.php`
endpoint is for private detector validation only. Never deploy these fixtures
publicly or forward the vulnerable lab to public listeners, even temporarily.
