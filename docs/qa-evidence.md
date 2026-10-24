# QA Evidence — php2shell-audit 0.1.0

Local verification date: 2026-10-24 (Asia/Jakarta). Scan timestamps are UTC.

Scope: the loopback Docker lab only. No public or third-party target was scanned.
This document records detection and reporting evidence, not exploitability proof.

## Environment

- Python 3.12 via `uv`.
- Lab: `php:8.4.26-apache` on `127.0.0.1:18080` and
  `php:8.4.27-apache` on `127.0.0.1:18081`.
- Both services were bound to loopback only and ran with
  `no-new-privileges:true` and a read-only web root.
- Teardown was verified after evidence capture; `docker compose -f lab/compose.yaml down -v`
  exited 0 and removed both containers and the lab network.

```text
$ docker compose -f lab/compose.yaml config
exit 0

$ docker compose -f lab/compose.yaml ps
NAME                         IMAGE               SERVICE      STATUS       PORTS
php2shell-lab-fixed-1        php:8.4.27-apache   fixed        Up 6 hours   127.0.0.1:18081->80/tcp
php2shell-lab-vulnerable-1   php:8.4.26-apache   vulnerable   Up 6 hours   127.0.0.1:18080->80/tcp
```

Observed headers:

```text
$ curl -sS -I http://127.0.0.1:18080/
HTTP/1.1 200 OK
Server: Apache/2.4.69 (Debian)
X-Powered-By: PHP/8.4.26
Content-Type: text/plain; charset=utf-8

$ curl -sS -I http://127.0.0.1:18081/
HTTP/1.1 200 OK
Server: Apache/2.4.69 (Debian)
X-Powered-By: PHP/8.4.27
Content-Type: text/plain; charset=utf-8
```

## CLI smoke tests

```text
$ uv run php2shell-audit --help
exit 0

$ uv run php2shell-audit scan --help
exit 0

$ uv run php2shell-audit advisories
exit 0

$ uv run php2shell-audit scan http://127.0.0.1:18080
exit 2
Error: explicit authorization is required; pass --authorized.
```

Dry run makes no DNS or HTTP requests:

```text
$ uv run php2shell-audit scan http://127.0.0.1:18080 \
    --authorized --allow-private --dry-run
exit 0

Targets            http://127.0.0.1:18080
rate_limit         1.0
timeout            10.0
max_requests       20
max_redirects      5
max_response_bytes 1048576
deep               False
allow_private      True
authorized         True
scope_file         None
output_dir         reports
format             all
max_targets        10
fail_on            never
verbose            False
Dry run: no DNS resolution or HTTP requests were made.
```

## Lab scan evidence

Two scans were started in parallel so they would share the same UTC timestamp
second. Both exited 0 and made four requests each.

```text
$ uv run php2shell-audit scan http://127.0.0.1:18080 \
    --authorized --allow-private --deep --format all --output-dir reports/qa
exit 0

$ uv run php2shell-audit scan http://127.0.0.1:18081 \
    --authorized --allow-private --deep --format all --output-dir reports/qa
exit 0
```

Results:

| Target | Observed PHP | Verdict | Requests | Report stem |
|---|---|---|---|---|
| `http://127.0.0.1:18080` | 8.4.26 | `VULNERABLE_VERSION` | 4 | `20261024T005324Z-1` |
| `http://127.0.0.1:18081` | 8.4.27 | `NOT_VULNERABLE_VERSION` | 4 | `20261024T005324Z` |

The vulnerable scan started at `2026-10-24T00:53:24.180347+00:00`; the fixed
scan started at `2026-10-24T00:53:24.169949+00:00`. Despite sharing the same
second, each scan produced a complete four-format set under a distinct stem:

```text
reports/qa/20261024T005324Z-1.{json,jsonl,md,csv}
reports/qa/20261024T005324Z.{json,jsonl,md,csv}
```

Audit logs were also distinct:

```text
logs/php2shell-audit-20261024T005324167529Z.jsonl
logs/php2shell-audit-20261024T005324178247Z.jsonl
```

### Report excerpts

Vulnerable JSON result (`20261024T005324Z-1.json`):

```json
{
  "target": {"url": "http://127.0.0.1:18080"},
  "verdict": "VULNERABLE_VERSION",
  "php": {
    "detected": true,
    "version": "8.4.26",
    "sapi": "mod_php",
    "evidence": [{"source": "header:x-powered-by", "value": "PHP/8.4.26"}]
  },
  "assessments": [
    {"cve_id": "CVE-2026-109618", "verdict": "VULNERABLE_VERSION",
     "fixed_version": "8.4.27", "configuration_dependent": false},
    {"cve_id": "CVE-2026-109619", "verdict": "VULNERABLE_VERSION",
     "fixed_version": "8.4.27", "configuration_dependent": false},
    {"cve_id": "CVE-2026-115560",
     "verdict": "POTENTIALLY_VULNERABLE_VERSION_UNKNOWN",
     "fixed_version": null, "configuration_dependent": true}
  ],
  "requests_made": 4,
  "error": null
}
```

Fixed Markdown excerpt (`20261024T005324Z.md`):

```text
| Target | Verdict | PHP | SAPI | WAF | Requests | Error |
| --- | --- | --- | --- | --- | --- | --- |
| http://127.0.0.1:18081 | NOT_VULNERABLE_VERSION | 8.4.27 | mod_php | none | 4 |  |
```

Vulnerable CSV excerpt (`20261024T005324Z-1.csv`):

```text
target,verdict,php_detected,php_version,sapi,waf,assessments,findings,requests_made,error
http://127.0.0.1:18080,VULNERABLE_VERSION,True,8.4.26,mod_php,none,CVE-2026-109618=VULNERABLE_VERSION; CVE-2026-109619=VULNERABLE_VERSION; CVE-2026-115560=POTENTIALLY_VULNERABLE_VERSION_UNKNOWN,info:PHP version disclosed; low:Missing baseline security headers; high:phpinfo page may be exposed,4,
```

The structured log records one valid JSON object per line, including
`scan.start`, each `scan.request`, and `scan.result`. No cookies, authorization
headers, full response bodies, or secrets were recorded.

### Same-second collision regression

Before the fix, two scans started at `2026-10-23T18:48:09Z` wrote the same
`20261023T184809Z.*` filenames; the fixed scan overwrote the vulnerable scan.
The pre-fix artifacts are preserved under `reports/qa-pre-fix/` and
`logs/pre-fix/`; the overwritten vulnerable report is not recoverable.

The regression is covered by `tests/test_reporting.py` and
`tests/test_logging.py`, including shared-stem behavior across all selected
formats and distinct default log filenames.

## TUI smoke test

Textual pilot coverage passed: 15 tests. The broader reporting/logging/TUI
group passed 59 tests. A real PTY launch was also exercised:

```text
$ ( sleep 4; printf '\021' ) | timeout 20 script -qec \
    'uv run php2shell-audit tui' /tmp/opencode/php2shell-tui-smoke2.txt
exit 0
```

The 80x24 terminal rendered the authorization notice, target input, Deep
checks and Allow private controls, Scan/Export/Quit actions, results table,
detail pane, and progress/audit pane. `Ctrl+Q` exited cleanly. No target was
entered and no network scan was performed in this smoke test.

## Automated verification

```text
$ uv run pytest
474 passed, 2 warnings in 8.28s

$ uv run pytest tests/test_tui.py tests/test_reporting.py tests/test_logging.py
59 passed in 7.60s

$ uv run ruff check .
All checks passed!

$ uv run ruff format --check .
25 files already formatted

$ uv run mypy src
Success: no issues found in 12 source files
```

The two pytest warnings are third-party deprecation warnings; they do not
affect pass/fail status.

## Build artifact

```text
$ uv build --out-dir dist
exit 0

dist/php2shell_audit-0.1.0-py3-none-any.whl
dist/php2shell_audit-0.1.0.tar.gz
```

The same wheel was also built to `/tmp/opencode/php2shell-build-final3` for the
pre-install artifact check.

Wheel inspection:

```text
data json: True   (php2shell_audit/data/php2shell.json)
py.typed: True
Name: php2shell-audit
Version: 0.1.0
Summary: Authorization-gated CLI/TUI for detection-only defensive PHP exposure auditing.
Requires-Python: >=3.12
entry point: php2shell-audit = php2shell_audit.cli:app
```

Installed-wheel smoke test in a clean venv:

```text
$ uv venv /tmp/opencode/php2shell-wheel-venv
$ uv pip install --python /tmp/opencode/php2shell-wheel-venv/bin/python \
    dist/php2shell_audit-0.1.0-py3-none-any.whl
exit 0

$ /tmp/opencode/php2shell-wheel-venv/bin/php2shell-audit advisories
exit 0

$ /tmp/opencode/php2shell-wheel-venv/bin/php2shell-audit --help
exit 0
```

The wheel does not include the `lab/` fixtures. Use the source checkout for
`docker compose -f lab/compose.yaml`.

## Security review notes

- No exploit code, PoCs, payloads, uploads, or write methods were added.
- Target validation rejects non-HTTP(S), embedded credentials, private,
  loopback, link-local, reserved, and metadata addresses unless the explicit
  lab-only `--allow-private` path applies; metadata remains blocked.
- Recon uses bounded `GET`/`HEAD`, redirect limits, a per-target request budget,
  no cookies/auth headers, and `trust_env=False`.
- Reports and logs redact sensitive values; full response bodies are not stored.
- CLI and TUI error paths avoid tracebacks and Rich markup injection; TUI detail
  text uses `markup=False`.
- Lab subprocess calls use fixed argument lists without a shell.
- Residual risk: DNS validation and connection resolution are separate steps, so
  DNS rebinding between them remains a documented TOCTOU risk in `SECURITY.md`.
- No independent security audit has been performed.

## Limitations

- Lab-only evidence; the user's actual site has not been scanned.
- A version match is exposure evidence, not proof of exploitability.
- CVE-2026-115560 remains configuration-dependent and unknown remotely.
- Reverse proxies, WAFs, hidden banners, and distro backports can change results.
- Reports and logs are not tamper-proof evidence stores.

## Deployable lab follow-up (2026-10-24)

The lab now has PHP-only HTTP healthchecks, port overrides, and executable
start/verify/cleanup scripts. The bind address stays hard-coded to loopback.
No exploit client or application exploit fixtures from the reference repository
were copied. These fixtures validate detection rather than exploit reproduction.

### Live QA matrix

All commands below ran against local development fixtures. Transcript paths
under `/tmp/opencode/` are local session artifacts; JSON reports stay under
`reports/qa/`. No real website was scanned.

| Scenario | Command / action | Observed | Evidence | Verdict |
|---|---|---|---|---|
| Default deployment and verification | `APP_ENV=development ./lab/scripts/verify.sh` | Both services healthy; PHP 8.4.26 vulnerable, PHP 8.4.27 fixed; four requests per target; automatic teardown | `/tmp/opencode/php2shell-lab-deploy-default.txt` | PASS |
| Custom ports and retention | `APP_ENV=development KEEP_LAB=1 LAB_VULNERABLE_PORT=28080 LAB_FIXED_PORT=28081 ./lab/scripts/verify.sh` | Both expected verdicts at overridden URLs; services left running | `/tmp/opencode/php2shell-lab-deploy-custom.txt` | PASS |
| CLI readiness | `LAB_VULNERABLE_PORT=28080 LAB_FIXED_PORT=28081 uv run php2shell-audit lab up` | Waited for both healthy; output correctly labeled default URLs rather than claiming overridden URLs | `/tmp/opencode/php2shell-lab-cli-up.txt` | PASS |
| CLI status after retention | Same overrides with `uv run php2shell-audit lab status` | Both services healthy, published only on 127.0.0.1:28080/28081 | `/tmp/opencode/php2shell-lab-cli-status.txt` | PASS |
| Explicit cleanup | Same overrides with `uv run php2shell-audit lab down` | Both containers and project network removed | `/tmp/opencode/php2shell-lab-cli-down.txt` | PASS |

Default run evidence:

```text
PASS: http://127.0.0.1:18080: VULNERABLE_VERSION
reports/qa/lab-vulnerable/run.nx6vHDFS9g/20261024T021802Z.json
PASS: http://127.0.0.1:18081: NOT_VULNERABLE_VERSION
reports/qa/lab-fixed/run.xSybANIUaP/20261024T021802Z.json
```

Custom-port run evidence:

```text
PASS: http://127.0.0.1:28080: VULNERABLE_VERSION
reports/qa/lab-vulnerable/run.AEB8zSwzRO/20261024T021819Z.json
PASS: http://127.0.0.1:28081: NOT_VULNERABLE_VERSION
reports/qa/lab-fixed/run.WuAYWKuhQQ/20261024T021819Z.json
```

Each verification run creates fresh report directories and checks both target
URLs and verdicts with explicit failures. Old reports cannot satisfy a new run,
and Python optimization does not disable these checks. Cleanup failures are
reported and make a successful scan run fail; an original failing status is
preserved. `KEEP_LAB=1` intentionally disables automatic teardown.

Additional checks performed:

- Invoked the start script from `/tmp/opencode/`, not the checkout; both custom
  port endpoints responded with the expected PHP versions, and cleanup succeeded.
- Rendered Compose defaults and port overrides are tested as JSON, including
  loopback host IPs, healthchecks, image tags, and read-only mounts.
- Every Bash script is individually syntax-checked.
- `uv run pytest`: **505 passed**, two existing Typer/Click deprecation warnings.
- `uv run ruff check .`: all checks passed.
- `uv run ruff format --check .`: 25 files already formatted.
- `uv run mypy src`: no issues in 12 source files.
- Targeted CLI/lab suite: **105 passed**. Offline subprocess scenarios cover
  wrong verdicts, wrong targets, stale and duplicate reports, failed cleanup,
  combined validation/cleanup failure, and retained labs, in normal and
  optimized Python modes.
- `uv build --out-dir dist`: wheel and source distribution built successfully.
  The updated wheel was reinstalled in the isolated wheel-test environment;
  `php2shell-audit advisories` succeeded from outside the source checkout.

SSH-tunnel access is documented for a remote lab host but was not exercised
against a remote machine. This is not a production deployment: the intentionally
old PHP fixtures and diagnostic endpoint must not be exposed publicly. Image
tags pin versions, not immutable image digests.

### Final review corrections and rerun

The first gate review rejected two gaps: accepting an aggregate verdict without
version/CVE evidence, and running the stock Apache images with their root
defaults. Both were corrected before the final live rerun.

The verifier now requires `php.detected=true`, the exact fixture version, and
exactly one correctly classified assessment for each of CVE-2026-109618 and
CVE-2026-109619. Tests reject missing PHP evidence, incorrect versions, undetected
PHP, missing or duplicate assessments, and incorrect assessment verdicts for
either fixture, including optimized Python. CVE-2026-115560 stays unknown.

Both services explicitly run as UID/GID 33, drop all Linux capabilities, and
have read-only roots. Writable state is limited to size-bounded tmpfs mounts.
Each has 256 MiB memory, 0.5 CPU, and 128-process bounds. The namespaced
unprivileged-port sysctl permits internal port 80 without adding a capability.

| Final-tree scenario | Evidence | Result |
|---|---|---|
| Default verify, both healthy, exact PHP/CVE checks, automatic cleanup | `/tmp/opencode/php2shell-lab-hardened-default.txt` | PASS |
| Ports 28080/28081 with `KEEP_LAB=1`, both exact PHP/CVE checks, retained healthy | `/tmp/opencode/php2shell-lab-hardened-custom.txt` | PASS |
| Runtime user, read-only roots, capability/resource limits, healthy state | `/tmp/opencode/php2shell-lab-hardened-inspect.txt` | PASS |
| CLI readiness, status, and final teardown on overridden ports | `/tmp/opencode/php2shell-lab-hardened-cli-up.txt`, `/tmp/opencode/php2shell-lab-hardened-cli-status.txt`, `/tmp/opencode/php2shell-lab-hardened-cli-down.txt` | PASS |

The runtime inspection reported for each fixture:

```text
user=33:33 readonly=true capdrop=["ALL"] memory=268435456
nano_cpus=500000000 pids=128 health=healthy
```

Direct `docker compose exec -T <service> id` checks for both services returned
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`.

Final-tree JSON evidence:

```text
Default vulnerable: reports/qa/lab-vulnerable/run.CLqRgGNGsk/20261024T023422Z.json
Default fixed: reports/qa/lab-fixed/run.LaQN9YXgrj/20261024T023422Z.json
Custom vulnerable: reports/qa/lab-vulnerable/run.2IVxWxGqME/20261024T023514Z.json
Custom fixed: reports/qa/lab-fixed/run.E2QtnG71Im/20261024T023515Z.json
```

The final main-session full suite passed **567 tests** with the same two
pre-existing Typer/Click warnings. Ruff lint passed, format checking reported
26 files already formatted, and strict mypy found no issues in 12 source files.
These results supersede earlier counts in this historical evidence document.

Final internal gate review: **APPROVE**, high confidence, no remaining blockers.
The reviewer inspected the corrected files and live artifacts and independently
reran 108 offline lab tests. This is an internal engineering review, not an
independent third-party security audit. The final distribution build also passed.
