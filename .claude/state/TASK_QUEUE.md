# Task Queue

Ordered backlog. One task in progress at a time. Pick the top unblocked task unless the
user directs otherwise. Statuses: `TODO`, `IN PROGRESS`, `DONE`, `BLOCKED`.

## TASK-001 — Establish project foundation

| Field | Value |
|---|---|
| Task ID | TASK-001 |
| Name | Establish project foundation |
| Priority | High |
| Status | DONE |
| Complexity | M |
| Depends On | Purpose and stack established by implemented authorized auditor |
| Scope | Python 3.12/uv foundation with Typer, Rich, Textual, httpx; pytest, Ruff lint/format, strict mypy, and setuptools build. Application implemented; commands recorded in `CLAUDE.md`. Private lab follow-through tracked separately in TASK-003. |
| Acceptance Criteria | CLI/TUI entrypoint available; 567 tests pass; Ruff checks clean on 26 files; mypy clean on 12 files; `uv build` succeeds. |
| Security Concerns | Stack choices affect the attack surface. Verify, pin, and audit new dependencies. No secrets in configuration. Container images run non-root with pinned tags. Do not loosen permissions without approval. |
| Notes | Foundation implemented. Permissions unchanged; any stack-specific allow-list requires approval under TASK-002. Lab images are test fixtures, not satisfaction of production-hardening requirements. |

## TASK-003 - Deployable private lab and final review

| Field | Value |
|---|---|
| Task ID | TASK-003 |
| Name | Deployable private lab and final review |
| Priority | High |
| Status | DONE |
| Complexity | M |
| Depends On | TASK-001 |
| Scope | Complete: Compose non-root/capability/resource hardening; Bash up/down/verify scripts; healthchecks; configurable host ports; fresh-run exact PHP/CVE JSON validation; optional retention; deployment guide and QA evidence. |
| Acceptance Criteria | Final hardened default verification and cleanup pass; custom 28080/28081 with `KEEP_LAB=1` passes and retains services; CLI up/status/down passes with healthy services then cleanup; 567 tests pass; final internal review APPROVE. |
| Security Concerns | Hardcoded loopback bindings; no exploits; old PHP images are not production hardened. Do not expose publicly or loosen permissions. |
| Notes | No containers running after main-session cleanup. No real website scanned or target URL supplied. Final internal gate approved; no new dependencies. Evidence in `docs/qa-evidence.md`. |

## TASK-004 - Initialize local version control

| Field | Value |
|---|---|
| Task ID | TASK-004 |
| Name | Initialize local version control |
| Priority | High |
| Status | DONE |
| Complexity | S |
| Depends On | Explicit user authorization |
| Scope | Initialize `main` using existing identity; focused conventional-English initial snapshot commits; preserve exclusions and ignore `.omo/`; no remote or push. |
| Acceptance Criteria | Reviewed candidate paths and credential-pattern matches; 567 tests pass; Ruff lint/format and strict mypy clean; focused local history. |
| Security Concerns | No environment secrets, generated evidence, local overrides or session artifacts tracked. Gitleaks/trufflehog unavailable; limited pattern/manual review only, no tools installed. |
| Notes | User requests focused commits for subsequent completed work, without automatic push. No source changes, external scans or lab startup. |

## TASK-005 - Evidence-backed remote assessment reports

| Field | Value |
|---|---|
| Task ID | TASK-005 |
| Name | Evidence-backed remote assessment reports |
| Priority | High |
| Status | DONE |
| Complexity | M |
| Depends On | TASK-001, TASK-004, explicit user authorization |
| Scope | Additive schema-1 evidence contract, cited range comparison, request context, provenance, redacted Markdown/JSON/JSONL, synthetic offline example and portfolio docs. No exploits, local agent, new probes, dependencies, remote, or push. |
| Acceptance Criteria | Affected, fixed, hidden, unsupported, non-PHP, blocked, and failure outcomes report evidence chains with citations and verification; 608 tests pass; Ruff and strict mypy clean; offline build succeeds; synthetic example reproduces without DNS/HTTP. |
| Security Concerns | No response bodies retained; all nested evidence redacted; provenance is data identity, not authenticity; unsupported branches stay unknown; authorization and target controls unchanged. |
| Notes | Delegated workers hit model usage limits; main session completed verification and commits. Generated `reports/demo/` remains ignored; `docs/example-report.md` is the labeled synthetic output. |

## TASK-002 — Add automated security guardrails

| Field | Value |
|---|---|
| Task ID | TASK-002 |
| Name | Add automated security guardrails |
| Priority | High |
| Status | DONE |
| Complexity | M |
| Depends On | TASK-001 |
| Scope | Propose and, with user confirmation, add pre-commit secret scanning, dependency audit, static analysis, container image scanning if containerized, and a CI pipeline running tests, lint, type checks, and these scans. |
| Acceptance Criteria | Each guardrail runs locally or in CI and fails the build on a violation. Tool versions are pinned. The workflow is documented in `.claude/README.md` and the commands are listed in `CLAUDE.md`. |
| Security Concerns | Tooling must not receive or print secrets. CI logs must not expose environment values. Actions and images are pinned to immutable versions. Least-privilege tokens for CI. |
| Notes | User authorized completion 2026-10-24. All gates green locally: pre-commit, Gitleaks, pip-audit (after pytest 8 to 9 remediation), Semgrep, Trivy, 608 tests, Ruff/mypy clean, offline build. CI added with SHA-pinned actions. |

## TASK-006 - Portfolio publication readiness

| Field | Value |
|---|---|
| Task ID | TASK-006 |
| Name | Portfolio publication readiness |
| Priority | Medium |
| Status | DONE |
| Complexity | S |
| Depends On | TASK-005, explicit user authorization for license choice |
| Scope | Add MIT LICENSE with the user's git identity; record a dated maintainer security self-review (explicitly not independent); confirm advisory snapshot freshness against upstream sources. No code or behavior changes. |
| Acceptance Criteria | LICENSE grants MIT terms; self-review documents scope, method, findings, residual risks, and non-independence; snapshot generated_at matches the upstream-verified date with no refresh needed. |
| Security Concerns | License choice is the user's; self-review must never be presented as an independent audit. No secrets involved. |
| Notes | Completed 2026-10-24 in one pass per user authorization. Advisory snapshot current as verified; refresh process remains documented in README. |

## TASK-007 - Non-PHP control fixture for the lab

| Field | Value |
|---|---|
| Task ID | TASK-007 |
| Name | Non-PHP control fixture for the lab |
| Priority | Medium |
| Status | DONE |
| Complexity | S |
| Depends On | TASK-003, explicit user request for a non-PHP lab target |
| Scope | Hardened busybox static fixture on 127.0.0.1:18082; verify.sh asserts NOT_PHP with no version and no assessments; lab tests, CLI message, Trivy gate, and lab/main docs updated. No source behavior changes. |
| Acceptance Criteria | Fixture serves clean 200 responses with no PHP indicators; live verify.sh passes all three fixtures; 653 tests pass; Ruff, strict mypy, and all guardrails green. |
| Security Concerns | Loopback-only preserved; fixture ships no package database (Trivy no-op documented); hardening asserted by unit tests. Rejected nginx alternative would have added 69 fixable image CVEs. |
| Notes | Completed 2026-10-24 with live verification before commit. |

## Task Template

```markdown
| Field               | Value                                               |
|---------------------|-----------------------------------------------------|
| Task ID             | TASK-XXX                                            |
| Name                | [Task name]                                         |
| Priority            | High / Medium / Low                                 |
| Status              | TODO / IN PROGRESS / DONE / BLOCKED                 |
| Complexity          | S / M / L                                           |
| Depends On          | [Task IDs]                                          |
| Scope               | [Exact description of what must be built]           |
| Acceptance Criteria | [Measurable definition of done]                     |
| Security Concerns   | [Security considerations for this task]             |
```
