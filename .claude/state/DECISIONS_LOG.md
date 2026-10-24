# Decisions Log

Significant decisions and their rationale. Append new entries at the top. Keep entries
short but complete enough for someone who was not in the session.

---

**Decision:** Implement TASK-002 guardrails with pinned tools and triaged findings.

**Date:** 2026-10-24

**Context:** Only TASK-002 remained open. The user authorized completion ("continue
until done, no mistakes"). All third-party versions and action SHAs were verified
against upstream releases before pinning; the Trivy supply-chain incident
(GHSA-69fq-xp46-6x23) was reviewed and the safe trivy-action 0.35.0 commit
confirmed independently.

**Rationale:** Pre-commit (4.7.0) runs hygiene hooks, Gitleaks 8.30.1, and locked
Ruff/mypy. pip-audit 2.10.1 audits an exported `uv.lock` snapshot (requirements
scope), which exposed PYSEC-2026-1845 in pytest 8; remediated by upgrading pytest
8 to 9 and pytest-cov 6 to 7 with a green 608-test suite. A filelock CVE that
appeared mid-task was proven to be scanner-tool closure noise (absent from
`uv.lock`), which motivated the requirements scope. Semgrep 1.182.1 runs
`--config auto --error`; three findings triaged honestly (uv `exclude-newer`
hardening added; two Python-3.7-compat false positives suppressed inline; one
Django XSS false positive on test data excluded by full check ID after proving
inline nosemgrep does not anchor to taint findings). Trivy 0.76.1 (digest-pinned)
scans both lab fixtures with `--ignore-unfixed` (a CLI-only flag in 0.76, no
config key exists) plus `.trivyignore` for one fixture-only libbrotli finding;
Compose files are a verified Trivy no-op, so hardening stays in unit tests.

**Security Implications:** Every gate fails closed locally and in CI. Registry
rule drift was observed live (a new Semgrep rule fired between runs); the gate
caught it and it was triaged, not waived. No secrets were encountered; Gitleaks
is clean. No dependency changes beyond the pytest major bump and lockfile.

**Impact:** TASK-002 DONE. CI (`.github/workflows/ci.yml`, SHA-pinned actions)
enforces tests, lint, types, build, and all four scans on push/PR.

---

**Decision:** Implement evidence-backed remote reports with fail-closed version rules.

**Date:** 2026-10-24

**Context:** The user wants a personal portfolio tool that produces credible,
comprehensive reports without proving exploitability. Delegated workers hit model
usage limits before finishing.

**Rationale:** Keep report schema version 1 with additive evidence, per-CVE range
comparison, advisory provenance, and verification guidance. Only documented PHP
8.2-8.5 branches support decisive verdicts; older, prerelease, unlisted, hidden,
and configuration-dependent cases stay unknown. Reports label the bundled snapshot
as project-maintained synthesis and identify bytes by SHA-256 without claiming
authenticity.

**Security Implications:** No response bodies retained; nested evidence redacted;
no new probes, credentials, dependencies, or relaxed authorization. Synthetic
fixtures use `.example.test` hosts and never contact real systems.

**Impact:** Affected-version findings show HTTP evidence, rule comparison,
references, remediation, and owner verification. TASK-005 is DONE.

---

**Decision:** Establish local `main` with focused initial snapshot commits.

**Date:** 2026-10-24

**Context:** The user explicitly requested repository initialization and focused
commits, including subsequent completed work. The existing project had no Git history.

**Rationale:** Group the existing snapshot by dependency and responsibility, pairing
implementation with tests. These commits capture current files, not historic steps
or evidence that each intermediate snapshot was tested. Use the existing Git identity.

**Security Implications:** Ignore `.omo/` entirely and preserve existing secret,
local-override and generated-output exclusions. Filename-only credential-pattern
searches and fixture review identified no actual credentials; gitleaks/trufflehog
were unavailable, so this is a limited review, not a dedicated scanner audit.
No tools installed, Git configuration changed, remote configured or push authorized.

**Impact:** Keep subsequent completed work in focused commits under the user's
request; never push automatically. Existing security and permission rules remain.

---

**Decision:** Use a local-only, detection-validation PHP lab with safe deployment patterns.

**Date:** 2026-10-24

**Context:** The implemented Python 3.12/uv auditor needs reproducible vulnerable/fixed
version evidence, not an exploit environment. `dimasma0305/php2shell` informed safe
deployment patterns only; no exploit fixtures, PoCs, WordPress, or real application stacks
were copied. No new dependencies were added for the lab work.

**Rationale:** `lab/compose.yaml` uses `php:8.4.26-apache` and `php:8.4.27-apache` version
tags, not immutable digests. Bind addresses are hardcoded to `127.0.0.1`; only
`LAB_VULNERABLE_PORT`/`LAB_FIXED_PORT` are configurable. Healthchecks and a 60-second
readiness deadline prevent scanning before startup. Scripts pass local `lab/.env`
explicitly with `--env-file` and never source it. Verification uses fresh per-run report
directories and checks the exact target URL, PHP version/detected flag, and per-CVE
verdicts with explicit failures, not Python `assert`. Default cleanup is automatic;
`KEEP_LAB=1` deliberately retains services.

**Alternatives Rejected:** Copying exploitation or real application stacks (unneeded attack
surface); public bindings or configurable bind addresses (unsafe exposure); sourcing env
files (shell execution); accepting stale reports (false verification). No production
override is supplied because this Compose file is a private test fixture, not an app deployment.

**Security Implications:** The lab overrides stock image defaults with UID/GID 33,
all capabilities dropped, read-only roots, bounded temporary state, and memory/CPU/PID
limits. A namespaced port sysctl permits internal port 80 without a capability grant.
These controls do not make intentionally old PHP suitable for production. Version
detection does not prove exploitability; immutable-image requirements remain and the
lab is not an independent security audit.
`APP_ENV` is session safety metadata, not an implemented runtime gate; the scanner uses
authorization and target safety controls. Existing permissions are unchanged.

**Impact:** Use the lab scripts from a source checkout and SSH loopback forwarding only
for remote access. The earlier generic three-file Compose decision remains guidance for
future application deployment, not a description of this lab. Final internal review approved
after hardening and exact-evidence checks; default/custom live reruns and cleanup passed.

---

**Decision:** Use the root `CLAUDE.md` as the single auto-loaded entry point with four imports.

**Date:** 2026-10-22

**Context:** Claude Code auto-loads only `CLAUDE.md` (and `CLAUDE.local.md`); other files in `.claude/` are not loaded automatically. The agent needs rules and security standards in every session without manual re-briefing.

**Rationale:** Importing four compact files gives every session the behavioral rules, coding standards, security standards, and current state, while keeping the launch context bounded. Deeper references stay on demand.

**Alternatives Rejected:** Putting everything in `CLAUDE.md` (too much context, harder to maintain); relying on `.claude/README.md` or `HOW_TO_RESUME.md` being auto-loaded (they are not); enabling `.claude/rules/` now (another always-on layer before there is a stack to scope it to).

**Security Implications:** The Security Gate is present in every session, which reduces the chance that security guidance is missed. Imported files must never contain secrets because they are loaded and transmitted as context.

**Impact:** The four imported files must stay concise. Any change to them affects every future session.

---

**Decision:** Adopt a security-first permission baseline in `.claude/settings.json` without setting `permissions.defaultMode`.

**Date:** 2026-10-22

**Context:** The repository needs guardrails before any code exists, but the user must retain control of the permission mode.

**Rationale:** Deny rules block secrets and the most destructive commands. Ask rules prompt for network access, force pushes, history-clearing operations, volume deletion, and CI workflow edits. Allow rules cover only routine, low-risk development actions. Evaluation is deny, then ask, then allow, so deny wins.

**Alternatives Rejected:** Pinning `defaultMode` (removes user control and is explicitly out of scope); broad allow-lists or `Bash(*)` (not a security boundary and too permissive); a wildcard `.env.*` deny (would also block `.env.example`, which the agent must edit).

**Security Implications:** These rules are guardrails, not an enforcement boundary. Bash rules match command text as written, so alternate invocation forms can bypass them. Read and Edit denies cover built-in file tools and recognized redirects, but not indirect readers or arbitrary scripts. OS-level sandboxing is the stronger control and must be evaluated with the user before enabling.

**Impact:** Stack-specific commands are not pre-approved. Once the stack is chosen, the agent proposes an allow-list and adds it only with confirmation. Writes to `.claude/` will prompt because it is a protected path.

---

**Decision:** Use a three-file Docker Compose layout: `compose.yaml`, `compose.override.yaml`, and `compose.prod.yaml`.

**Date:** 2026-10-22

**Context:** Development needs hot reload and debug ports, while production needs hardened, reproducible containers. The two configurations must not drift.

**Rationale:** `compose.override.yaml` is loaded automatically by `docker compose up`, so development is the easy default. Production requires explicit `-f compose.yaml -f compose.prod.yaml`, which disables automatic override loading and forces a deliberate production invocation.

**Alternatives Rejected:** A single file with profiles (easier to run the wrong configuration accidentally); unrelated development and production files (drift and duplicated definitions).

**Security Implications:** Production overrides exclude source mounts, debug ports, and development tooling; use pinned image tags, resource limits, read-only filesystems where feasible, and a non-root user. Compose commands that are not clearly development require confirmation.

**Impact:** The agent must ask before any non-development Compose command. If the project chooses different file names, document them in `ENVIRONMENT_GUIDE.md` and follow the existing convention.

---

## Entry Template

Copy this block for each new decision; newest entry at the top.

```markdown
---
**Decision:** [What was decided]
**Date:** [YYYY-MM-DD]
**Context:** [Why it was needed]
**Rationale:** [Why this option]
**Alternatives Rejected:** [Other options and why not]
**Security Implications:** [Any security impact]
**Impact:** [What it affects downstream]
---
```
