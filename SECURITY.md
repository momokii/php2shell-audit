# Security Policy

## Scope and Status

`php2shell-audit` is a detection-only exposure auditor. The controls below are
the implemented security contract; local QA is recorded in
[docs/qa-evidence.md](docs/qa-evidence.md). No independent security review has
been performed. A maintainer self-review is recorded in
[docs/security-review.md](docs/security-review.md); it is not an independent
audit and must not be described as one.

Use only with explicit owner authorization. Read [Authorized Use](AUTHORIZED_USE.md)
before scanning, and treat every remote response as untrusted input.

## Threat Model

| Threat | Required controls and residual considerations |
|---|---|
| SSRF | Allow only HTTP/HTTPS; validate hosts and all resolved IPs; block special-use destinations and metadata services; revalidate every redirect hop. |
| DNS rebinding | Resolve and validate before each request and redirect hop. `httpx` resolves again, so a narrow time-of-check/time-of-use window remains; scan only authorized targets with controlled DNS. |
| Redirect abuse | Validate every hop against URL/IP safety and authorized scope; bound redirects. |
| Secret leakage | No cookies or auth headers sent; redact sensitive evidence and URLs; bound bodies and never retain full responses. |
| Report tampering | Restrict local write access and preserve originals; reports have no specified cryptographic integrity guarantee. |
| Lab exposure | Bind only to loopback; never publish or forward intentionally vulnerable services. |
| Dependency compromise | Review dependencies and lockfile changes; pin ranges, lock exact resolutions, and audit releases. |

The operator's machine, report directory, and dependency sources are trust
boundaries. A remote banner may be forged or stale; a report is evidence of an
observation, not attestation of the target's installed runtime.

## Target and Transport Controls

- Accept only `http` and `https`; reject URL userinfo and fragments.
- Reject private, loopback, link-local, multicast, reserved, and unspecified IPs
  by default, including any prohibited address among a host's resolved addresses.
- Block cloud-metadata destinations; `169.254.169.254` is never permitted.
- Resolve and validate the target before each request; validate every redirect
  destination before following it, not after fetching.
- Accept that hostname validation and the HTTP client's later resolution are not
  atomically pinned; treat DNS rebinding as a residual risk and scan only
  authorized, controlled targets.
- Use `trust_env=False` so environment proxy settings do not reroute scans.
- Send no cookies, authorization headers, API keys, or arbitrary user headers.
- Do not replay cookies received from targets.
- Permit `GET`/`HEAD` only, with a fixed identifying User-Agent.
- Apply timeouts, redirect limits, a per-target request budget, and rate limits.

`--allow-private` permits RFC1918 and loopback destinations for the local lab.
It must not disable metadata blocking or permit every special-use address.
Do not use it to bypass permission or scope restrictions.

## Safe Defaults and Authorization Gate

The CLI requires `--authorized`; absence is an authorization failure, exit 2.
The TUI requires an authorization checkbox before its scan button is enabled.
These are operator confirmations, not legal authorization or identity checks.

| Domain-model default | Value |
|---|---|
| Authorization | Off |
| Private access / deep checks | Off / off |
| Rate limit | 1 request per second |
| Timeout | 10 seconds |
| Request budget | 20 per target |
| Maximum redirects | 5 |
| Maximum response bytes | 1,048,576 |
| Output directory | `reports` |

The CLI defaults to a target cap of 10 with a hard maximum of 50; the TUI uses
the same 10-target cap. An optional scope file further restricts targets. Dry
run validates the plan without network requests or DNS resolution.

## Evidence and Redaction

Keep observations minimal and distinguish evidence, findings, and assessments.
Cookie names may support detection; cookie values must not be retained.
Redact `Set-Cookie`, `Authorization`, `Proxy-Authorization`, `X-Api-Key`, and
header names containing `token`, `secret`, `key`, or `auth`.

Remove query strings and fragments from recorded URLs. Do not retain full
response bodies. Inspect only bounded prefixes for fingerprinting; deep checks
for `/.user.ini` and `phpinfo.php` record status only, never body content.

Redact before writing reports and structured logs. Verbose output must not
disable redaction. Review artifacts before sharing, including hostnames and paths.
Store sensitive reports with restricted access and an agreed retention policy.

Report stems are UTC timestamps; an existing stem is extended with `-1`, `-2`,
and so on, and all selected formats for one scan share a stem. Default audit-log
filenames use microseconds and also avoid collisions. This prevents a second scan
from silently overwriting the first scan's evidence, but it is not an integrity
control.

Report tampering is not solved by redaction. The implementation does not provide
signed reports, checksums, or append-only storage. Preserve original files in
controlled storage; do not describe the JSONL audit log as tamper-proof.

## Intentionally Out of Scope

- Exploit development, exploit verification, and proof-of-concept payloads.
- RCE, command execution on targets, webshells, and persistence.
- Brute force, credential attacks, session hijacking, and evasion.
- Uploads, write methods, exfiltration, denial of service, and mass scanning.

A matching version is not proof of exploitability. A hidden version is not proof
of safety. WAF presence and SAPI inference cannot replace patch verification.

Evidence-backed reports separate HTTP observations from advisory comparisons.
Request context records the method, redacted URLs, response status, collection
time, and bounded-prefix metadata, never a retained response body. Per-CVE
references and the advisory snapshot date identify the basis for a conclusion.
The snapshot SHA-256 identifies the exact advisory bytes used; it does not
authenticate a response, sign the report, or establish exploitability.

Only documented branch rules support decisive version comparisons. Unsupported
or unlisted branches require owner/vendor verification rather than numerical
extrapolation. The configuration-dependent issue remains unverified remotely.

## Reporting a Vulnerability in This Tool

Open a private security report with the repository owner using the repository's
private reporting facility when available. If none is available, arrange a
private channel with the repository owner before sharing sensitive details.
Do not place secrets or unpatched vulnerability details in a public issue.

Include the affected tool version, environment, expected and actual behavior,
impact, and a minimal non-destructive reproduction using mocks or the local lab.
Redact target identifiers and credentials; share only data you may disclose.
Coordinate remediation and publication with the repository owner.
No response-time or supported-release guarantee has been established yet.

## Dependency and Release Hygiene

- Use bounded, pinned dependency ranges and review additions for legitimacy.
- Maintain exact resolutions with `uv lock`; review and retain `uv.lock`.
- Run `pip-audit` or `uv audit` when available, before release and periodically.
- Review lockfile changes and advisory data updates, including source provenance.
- Run tests, lint, and type checks before release; inspect packaged advisory data.
- Keep secrets, local configuration, generated reports, and logs out of the repo.

These are maintenance requirements, not claims that an audit was run for this
documentation change. No network or execution is needed to read this policy.

## Lab Safety

The lab pairs PHP 8.4.26 with PHP 8.4.27 for detector validation, plus a
static no-PHP control fixture. Keep published ports bound to `127.0.0.1`; the
default ports are 18080, 18081, and 18082.
Never expose them through public interfaces, public tunnels, or public port
forwarding. An authenticated SSH tunnel between explicitly loopback-bound
listeners on an authorized workstation and lab host is the only documented
remote-access path; see the lab guide. Do not enable wildcard SSH forwarding.

The PHP web root is read-only and contains an intentionally exposed `phpinfo.php`.
The PHP services explicitly use UID/GID 33 and the static fixture uses UID/GID
65534; all drop Linux capabilities, have read-only root filesystems with bounded
writable temporary state, and enforce memory, CPU, and process limits. Non-root
port binding is enabled only inside the container network namespace, not on the
host. These controls do not remove the risks of intentionally old PHP versions.
Do not deploy those fixtures to a public service or put secrets in them.
No exploit code belongs in the lab. Tear it down after use as described in
[lab/README.md](lab/README.md).
