# php2shell-audit

`php2shell-audit` is a detection-only PHP2Shell exposure auditor for authorized
websites. It collects bounded HTTP evidence, fingerprints PHP where observable,
maps disclosed versions to a bundled advisory snapshot, and records findings and
remediation. It does not exploit vulnerabilities, execute code on targets, upload
files, or prove exploitability.

## Status

Implemented and locally verified against the bundled mock suite and the
loopback Docker lab. The security contract is enforced by the CLI, TUI, scanner,
and report writers; local QA evidence is recorded in
[docs/qa-evidence.md](docs/qa-evidence.md). No independent security audit has
been performed, and no license file has been established yet; no license grant
is claimed here.

## Features

- CLI and Textual TUI with an authorization gate.
- Safe recon using `GET`/`HEAD`, target validation, budgets, and rate limits.
- PHP version, SAPI, and WAF/intermediary fingerprinting.
- Version-to-CVE mapping and a separate configuration-dependent assessment.
- JSON, JSONL, Markdown, and CSV reports with redacted evidence.
- Structured JSONL audit log and console progress.
- Local Docker lab comparing vulnerable and fixed PHP versions.

## Requirements and Install

- Python 3.12.
- `uv` for environment and command management.
- Docker with Compose only if using the local lab.

From the project root:

```bash
uv sync
```

## Quickstart

Use only a site you own or have explicit written permission to assess.
`--authorized` confirms existing permission; it does not grant permission.

```bash
uv run php2shell-audit version
uv run php2shell-audit advisories
uv run php2shell-audit scan https://your-site.example --authorized --output-dir reports
uv run php2shell-audit tui
```

In the TUI, confirm authorization with its checkbox before scanning.
Launching the interface alone does not authorize network activity.

Preview a scan without network requests or DNS resolution:

```bash
uv run php2shell-audit scan https://your-site.example --authorized --dry-run
```

Expected: dry run prints a validated scan plan without fetching the target.
Captured local command output is in [docs/qa-evidence.md](docs/qa-evidence.md).

## Scan Options

The command accepts one or more targets: `scan TARGET...`.
Only use multiple targets when all are explicitly authorized.

| Option | Meaning |
|---|---|
| `--authorized` | Required confirmation of permission; omission exits 2. |
| `--scope FILE` | Restrict targets with one host or URL per line; ignore blanks and `#` comments. |
| `--output-dir DIR` | Report directory; default `reports`. |
| `--format FORMAT` | `all` (default), `json`, `jsonl`, `markdown`/`md`, or `csv`. |
| `--rate-limit N` | Request rate; default 1 request/second; `0` disables pacing. |
| `--timeout N` | Positive request timeout; default 10 seconds. |
| `--max-requests N` | Per-target request budget; default 20. |
| `--max-targets N` | Target cap; default 10, maximum 50, after normalization/deduplication. |
| `--deep` | Optional status-only checks for `/.user.ini` and `phpinfo.php`; off by default. |
| `--allow-private` | Permit RFC1918/loopback for the local lab; metadata remains blocked. |
| `--dry-run` | Validate and print the plan without DNS, HTTP, logs, or reports. |
| `--fail-on MODE` | CI policy: `vulnerable`, `unknown`, or `never` (default); matching policy exits 1. |
| `--verbose` | DEBUG audit logging and console detail without disabling redaction. |

The CLI defaults to 10 targets and caps at 50 after normalization/deduplication.
An optional scope file restricts authorization, never grants it. The TUI applies
the same 10-target cap and keeps scanning disabled until its authorization
checkbox is checked.

## Reports and Audit Log

Reports are written under `--output-dir`, normally `reports/`, with UTC-timestamped
filenames such as `20261024T121516Z.json`. If that stem is already present, the
writer uses `20261024T121516Z-1`, `-2`, and so on; all selected formats for one
scan share the same stem. The default is all four formats, so `--format` is
optional.

| Format | Intended use |
|---|---|
| JSON | Structured scan report with target results, evidence, and assessments. |
| JSONL | Line-oriented JSON for downstream processing. |
| Markdown | Summary, per-target details, evidence, remediation, and limitations. |
| CSV | Tabular results for review and comparison. |

The structured audit log is separate:
`logs/php2shell-audit-<UTC timestamp with microseconds>.jsonl`. If that exact
default filename exists, the logger appends `-1`, `-2`, and so on; an explicit
`filename=` keeps append semantics.
Reports and logs are redacted by the tool, but review them before sharing and
keep them out of source control. Neither format nor redaction provides a
tamper-proof evidence store.

## Local Lab

The minimal PHP 8.4.26/8.4.27 pair validates version detection, not exploitation.
Default URLs are `http://127.0.0.1:18080` (vulnerable) and
`http://127.0.0.1:18081` (fixed). Bindings stay on `127.0.0.1`; never publish or
forward the vulnerable lab publicly. A source checkout is required: lab assets
are not included in the wheel.

Both fixtures run non-root with dropped capabilities, read-only root filesystems,
healthchecks, and memory/CPU/process limits. They are still private test targets,
not production services.

```bash
./lab/scripts/up.sh
./lab/scripts/down.sh
```

Deployment needs only Bash and Docker with Compose: `up.sh` uses
`--wait --wait-timeout 60` and prints actual URLs; `down.sh` uses
`down -v --remove-orphans`. To customize ports, run
`cp lab/.env.example lab/.env` and edit the port values; never source that file.

For automated verification, also install `uv` and Python 3.12:

```bash
uv sync
./lab/scripts/verify.sh
```

Verification starts the lab, scans both actual URLs with
`--authorized --allow-private --deep --format json`, and checks the expected
target URL, exact PHP version, and per-CVE verdicts in fresh per-run directories beneath
`reports/qa/lab-vulnerable/` and `reports/qa/lab-fixed/`. For both
CVE-2026-109618 and CVE-2026-109619, expect `VULNERABLE_VERSION` on PHP 8.4.26
and `NOT_VULNERABLE_VERSION` on PHP 8.4.27. CVE-2026-115560 remains
configuration-dependent/unknown. Verification automatically tears down the lab;
use `KEEP_LAB=1 ./lab/scripts/verify.sh` to retain it for investigation, then
run `down.sh` explicitly.

The CLI also provides `uv run php2shell-audit lab up`, `lab status`, and
`lab down`; `lab up` labels URLs as defaults, while `up.sh` prints actual
overrides. See the [full lab guide](lab/README.md) for healthchecks, safety
controls, troubleshooting, and private remote-host access through SSH loopback
forwarding. The reference `dimasma0305/php2shell` inspired deployment patterns
only; no PoC, WordPress, or other exploit fixtures were copied.

## Safety and Limitations

- Detection-only: no exploit payloads, uploads, write methods, or credential tests.
- Version evidence is not exploit proof; observed banners can be incomplete or stale.
- Hidden PHP versions produce unknown-version verdicts when PHP is detected.
- WAF presence is informational, not proof of protection.
- Reverse proxies, shared hosting, and distro backports complicate interpretation.
- Remote evidence cannot confirm the runtime condition for CVE-2026-115560.

Patch the two version-mapped issues to the fixed branch release and restart all
serving workers. Separately apply `session.upload_progress.enabled=0` for the
third issue before request parsing and restart workers. Temporary mitigations
are partial; verify the actual runtime and vendor patch status locally.

## Testing

Developer verification commands:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv build
```

Local QA evidence, including the lab scans and report excerpts, is recorded in
[docs/qa-evidence.md](docs/qa-evidence.md). The lab command resolves
`lab/compose.yaml` from a source checkout; an installed wheel may not include
the lab assets, so use `docker compose -f lab/compose.yaml` from the checkout.

## Project Layout

| Path | Purpose |
|---|---|
| `src/php2shell_audit/` | CLI/TUI, safety, recon, assessment, reporting, and domain modules. |
| `src/php2shell_audit/models.py` | Shared targets, evidence, findings, assessments, verdicts, and configuration. |
| `src/php2shell_audit/data/php2shell.json` | Authoritative bundled advisory snapshot and references. |
| `tests/` | Unit, integration, and interface checks specified by the plan. |
| `lab/` | Loopback-only Compose services and detector fixtures. |
| `docs/` | Research documentation and captured QA evidence. |
| `reports/` | Generated evidence; intended to be gitignored. |
| `logs/` | Generated structured audit logs; intended to be gitignored. |

## Further Reading

- [Research snapshot and fixed-version matrix](docs/php2shell-research.md).
- [Authorized use and evidence handling](AUTHORIZED_USE.md).
- [Security policy, controls, and private reporting](SECURITY.md).
- [Local lab guide](lab/README.md).
