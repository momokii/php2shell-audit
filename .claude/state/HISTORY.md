# History

Append-only. Newest entries at the top. One entry per completed or paused session.

## 2026-10-24 - Docs accuracy sweep for the static control

Fixed stale "pair / both services" wording in README, ENVIRONMENT_GUIDE, and
verify/how-to references so every doc describes the three-fixture lab.
Re-verified end to end: 653 tests, all guardrails green, live verify.sh passes
all three fixtures, lab torn down with no leftovers.

## 2026-10-24 - Non-PHP lab control fixture completed

Added a hardened busybox static fixture proving the `NOT_PHP` path against a
live target. Prototyped and rejected an nginx variant after Trivy reported 69
fixable image findings; minimalism won on evidence. Live verify.sh passes all
three fixtures; 653 tests green with all guardrails.

## 2026-10-24 - Portfolio publication readiness completed

Added MIT LICENSE (holder from the user's git identity), recorded a dated
maintainer security self-review with explicit non-independence, and confirmed
the advisory snapshot is current as of the upstream verification. README and
SECURITY.md updated to point at both documents.

## 2026-10-24 - TASK-002 automated guardrails completed

Implemented pre-commit (hooks, Gitleaks 8.30.1, locked Ruff/mypy), pip-audit
2.10.1 over exported uv.lock, Semgrep 1.182.1 `--config auto --error`, Trivy
0.76.1 digest-pinned fixture scans, and CI with SHA-pinned actions. Remediated
pip-audit finding by upgrading pytest 8 to 9 (608 tests green). Triaged four
Semgrep findings honestly; verified Trivy flag-vs-config behavior empirically.

**Checks:** 608 tests passed with 2 pre-existing Typer warnings; Ruff lint/format
clean (30 files), strict mypy clean (14 files), `uv build` succeeds. Gitleaks,
pip-audit, Semgrep, and Trivy gates all green and fail-closed. Full backlog DONE.

## 2026-10-24 - Evidence-backed remote reports completed

Implemented additive schema-1 evidence linkage, cited affected-range comparison,
request context, advisory provenance, redacted Markdown/JSON/JSONL, and an offline
synthetic portfolio example. Corrected unsupported advisory ranges and clarified
the bundled snapshot as project-maintained synthesis.

**Checks:** 608 tests passed with 2 pre-existing Typer warnings; Ruff lint/format
clean (30 files), strict mypy clean (14 source files), offline `uv build` succeeds.
Offline QA driver and example generator verify affected, fixed, hidden, unsupported,
non-PHP, blocked, and empty outcomes without DNS/HTTP. No real target scanned and
no lab services started.

## 2026-10-24 - User-authorized local Git initialization

Initialized `main` with the existing Git identity and organized the current project
as focused conventional-English snapshot commits, pairing implementation and tests.
This is an initial snapshot, not reconstructed development history or per-commit
test provenance. Added `.omo/` to `.gitignore`; all existing exclusions remain.
No source changes, remote setup, push, Git configuration edits or hook bypass.

**Checks:** 567 tests passed with 2 pre-existing Typer warnings; Ruff lint clean,
26 files formatted, strict mypy clean on 12 source files. Candidate review used
filename-only credential-pattern searches and synthetic fixture inspection; no actual
credentials identified. Gitleaks/trufflehog were unavailable and were not installed;
the limited review does not replace a dedicated secret-scanner audit. Markdown and
ignore-file LSP diagnostics are unavailable. No `.env` or generated reports/logs
were read, no external targets scanned and no lab services started.

**Workflow:** The user requests focused commits for subsequent completed work;
no automatic push. Automated guardrails remain a separately approved task.

## 2026-10-24 - Deployable lab final gate completed

Resolved initial review findings by requiring detected PHP, exact runtime versions,
and unique matching per-CVE assessments in verification, and by running both Apache
fixtures non-root with all capabilities dropped, read-only roots, bounded tmpfs,
and memory/CPU/process limits. Repeated default and custom-port verification,
retention, CLI lifecycle, runtime inspection, and cleanup on the final configuration.

**Outcomes:** 567 tests passed with two pre-existing Typer warnings; Ruff lint and
format clean (26 files), strict mypy clean (12 source files), and distribution build
successful. Final internal gate APPROVE with no remaining blockers. TASK-003 is DONE;
unapproved guardrail automation remains separate. No lab containers remain running.
Reports are preserved, no real website was scanned, and remote SSH instructions
were documented but not exercised against a remote host. See `docs/qa-evidence.md`.

## 2026-10-24 - Auditor and private lab implementation; final review pending

Established the detection-only authorized PHP auditor using Python 3.12, uv, Typer,
Rich, Textual, and httpx, with pytest, Ruff, strict mypy, and setuptools packaging.
CLI/TUI authorization, bounded recon, fingerprinting, advisory assessment, redacted
reports, and audit logging are implemented. Added the private PHP 8.4.26/8.4.27 lab
with loopback-only Compose services, healthchecks, safe up/down/verify scripts,
configurable ports, fresh-run report checks, and optional `KEEP_LAB=1` retention.
Reference deployment patterns were used without copying exploits or real app stacks;
the lab work added no dependencies.

**Main-session evidence:** 505 tests pass with 2 pre-existing Typer warnings; Ruff lint
and format checks clean on 25 files; mypy clean on 12 files; `uv build` produces
distribution artifacts in `dist/`. Live default verification passes for both targets
and cleans up. Custom ports 28080/28081 with `KEEP_LAB=1` pass and retain services;
CLI up/status/down passes with healthy services, followed by cleanup. No lab containers
remain running. No real website was scanned and no target URL was supplied.

**Outcomes:** Foundation implemented; deployable lab implementation and local QA complete,
but TASK-003 remains IN PROGRESS for the pending Oracle review gate. Main session will
record completion after that result. No independent security audit is claimed. Updated
eight owned governance/state files in one batch; permissions and unrelated guardrail
automation remain unchanged and require approval before implementation.

## 2026-10-22 — Infrastructure bootstrap

Created the root `CLAUDE.md` entry point with four always-loaded imports, the `.claude/`
governance files (agent rules, coding standards, security standards, environment guide,
resume protocol), three slash commands, four state files, and four task templates.
Established a security-first permission baseline in `.claude/settings.json` with secret
and destructive-command denies, network and production-affecting asks, and minimal
development allows. Defined the Compose base/override/prod pattern and the `.env.example`
contract. No product code exists yet; the first task is TASK-001 (establish the project
foundation) once the user confirms purpose and stack.

**Outcomes:** context loads automatically every session; all files are stack-agnostic and
ready to be sharpened; security and environment discipline are defined before the first
commit.
