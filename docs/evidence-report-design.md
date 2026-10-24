# Evidence-Backed Remote Assessment Reports

## Goal

Make this personal security-engineering project useful to authorized operators
and understandable to portfolio visitors. A report must explain its conclusion
from collected observations and cited advisory rules, rather than offer an
unsupported vulnerability label.

## Approved Scope

- Remote, detection-only assessment of owned or explicitly authorized targets.
- A traceable chain from the HTTP observation to the version comparison,
  per-CVE conclusion, remediation, and owner-side verification steps.
- Report-visible advisory snapshot provenance and primary-source references.
- Comprehensive Markdown and structured JSON/JSONL detail; CSV remains a summary.
- Professional onboarding and a clearly labeled synthetic example report.
- Focused commits for completed logical changes, without automatic push.

No exploit requests, local agent, credential collection, additional scan paths,
new dependencies, or relaxation of authorization and target controls are included.

## Evidence And Claims

An observed header or sanitized generator fingerprint establishes what a remote
response disclosed, not the installed package identity or exploitability. Report
the request method, redacted requested/final URLs, response status, and collection
time alongside the fingerprint used by each version assessment.

An affected-version conclusion must show the observed version, documented branch
range, fixed release, comparison rationale, and relevant advisory references.
Unsupported branches and unrecognized versions remain inconclusive. End-of-life
status is a remediation concern, not independent proof of a specific CVE.

The configuration-dependent CVE must remain separate: a remote version cannot
establish the required configuration and application behavior. A fixed-version
result for another CVE is not a general security clearance. No detected PHP
fingerprint is not proof that PHP is absent.

The bundled snapshot is a project-maintained synthesis of upstream advisories,
not an upstream advisory or live vulnerability feed. Its date and content identity
must be visible. An identity hash identifies the data used; it is not a signature
or attestation that evidence is authentic.

## Verification

Use the existing public model, assessment, scanner, and writer test seams.
Exercise affected, fixed, hidden-version, unsupported-branch, non-PHP,
configuration-dependent, blocked, and failed-request outcomes. Verify additive
serialization compatibility and redaction of every new evidence location.

Run the complete test suite, Ruff lint/format, strict mypy, and the offline
isolated build. Manually generate and inspect reports through the public scanner
and writer APIs using controlled HTTP fixtures, with no real target scan. The
portfolio example must come from that report path and be explicitly synthetic.

## Source Review

Primary references checked on 2026-10-24:

- [PHP security announcement](https://www.php.net/archive/2026.php#2026-10-21-5).
- [OOM corruption advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w).
- [Stale global state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
- [Session upload progress notice](https://www.php.net/archive/2026.php#2026-10-23-1).

The two full advisories support fixed releases 8.2.35, 8.3.36, 8.4.27, and
8.5.12. Do not extrapolate that matrix to an unlisted branch. PHP's announcement
identifies older branches as unsupported and describes minimal source backports
for 7.4, 8.0, and 8.1; it does not establish this project's former 5.4 lower bound.
The third issue has an informational notice rather than a published fixed-version
matrix or PHP severity score. Any project-assigned rating must be labeled as such.
