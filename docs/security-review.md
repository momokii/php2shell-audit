# Security Self-Review

Date: 2026-10-24
Reviewer: project maintainer (the author).
Status: maintainer self-review — **not an independent audit**.

No external reviewer has examined this project. This document records what the
maintainer checked, what was found, and what remains unverified, so a reader
can judge the claims instead of trusting them.

## Scope

Detection-only authorized PHP exposure auditor: CLI/TUI authorization gates,
target validation, bounded HTTP recon, fingerprinting, advisory assessment,
redacted reports, structured audit logging, and the loopback-only lab.
Explicitly out of scope for this review: the lab fixture images themselves
(scanned separately by Trivy), upstream PHP, and operator-side authorization
validity (the tool records the operator's assertion; it cannot verify it).

## Method

- Read `safety.py`, `recon.py`, `scanner.py`, `reporting.py`, `logging.py`,
  `advisory.py`, `cli.py`, and `tui.py` end to end against
  `SECURITY.md` and the task acceptance criteria.
- Ran the full automated gates: 608 tests, Ruff, strict mypy, `uv build`,
  Gitleaks, pip-audit, Semgrep, and Trivy fixture scans — all green at review
  time (see [qa-evidence](qa-evidence.md) for the captured baseline).
- Reviewed every Semgrep and Trivy finding individually; suppressions and
  ignores are documented where they live, each with a justification.

## Findings

No blocking findings. Design strengths confirmed by reading:

- Authorization precedes DNS, HTTP, iteration, and logging in both `scan` and
  `scan_many`; absence exits 2 (CLI) or disables scanning (TUI).
- Target validation allow-lists schemes and hosts, blocks metadata destinations
  (including resolved IPs), and revalidates every redirect hop; DNS failures
  fail closed.
- Recon sends no cookies, auth headers, or arbitrary headers; response bodies
  are bounded and never retained; evidence keeps only sanitized fingerprints.
- Reports and audit logs are redacted at the writer/logger boundary, including
  nested assessment evidence and request URLs; filenames resist traversal.
- Advisory comparison is fail-closed: only documented PHP 8.2–8.5 branch rules
  support decisive verdicts; EOL, prerelease, unlisted, hidden, and
  configuration-dependent cases stay unknown.

## Residual Risks (accepted, documented)

- DNS time-of-check/time-of-use: hostname validation and the HTTP client's
  later resolution are not atomically pinned. Scan only authorized targets
  with controlled DNS (see [SECURITY](../SECURITY.md)).
- Banners can be forged, stale, or vendor-backported. Reports state this and
  require local runtime and vendor verification; they never claim exploit proof.
- The bundled advisory snapshot is dated project-maintained synthesis, not a
  live feed. Last verified against upstream sources on 2026-10-24; refresh via
  the process in the [README](../README.md).
- Automated guardrails reduce risk but are not a substitute for review: SAST
  rules drift (one new rule fired mid-development and was triaged), and the
  vulnerability database changes daily.

## What Would Strengthen This

- An independent review by someone who did not write the code.
- Signed reports or append-only evidence storage (currently explicitly
  disclaimed: redaction is not integrity).
- A scheduled advisory-refresh check with a freshness assertion in CI.

## Verdict

Fit for its stated purpose — authorized, detection-only exposure triage with
honest uncertainty — subject to the residual risks above. Not certified,
audited, or warranted for any other use.
