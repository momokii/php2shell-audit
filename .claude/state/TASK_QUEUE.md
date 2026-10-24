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

## TASK-002 — Add automated security guardrails

| Field | Value |
|---|---|
| Task ID | TASK-002 |
| Name | Add automated security guardrails |
| Priority | High |
| Status | TODO |
| Complexity | M |
| Depends On | TASK-001 |
| Scope | Propose and, with user confirmation, add pre-commit secret scanning, dependency audit, static analysis, container image scanning if containerized, and a CI pipeline running tests, lint, type checks, and these scans. |
| Acceptance Criteria | Each guardrail runs locally or in CI and fails the build on a violation. Tool versions are pinned. The workflow is documented in `.claude/README.md` and the commands are listed in `CLAUDE.md`. |
| Security Concerns | Tooling must not receive or print secrets. CI logs must not expose environment values. Actions and images are pinned to immutable versions. Least-privilege tokens for CI. |
| Notes | Do not add tooling silently; present the proposal and wait for approval. |

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
