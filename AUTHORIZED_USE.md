# Authorized Use

## Purpose

`php2shell-audit` is for owner-authorized exposure checks only.
It observes public HTTP evidence and compares disclosed PHP versions with a
bundled advisory snapshot. It is not an exploitation tool.

This policy applies to the CLI, TUI, local lab, reports, and audit logs.
The implementation preserves this boundary across all of those surfaces.

## Authorization Is Required

Obtain explicit authorization before any scan. For a site you do not own,
obtain written permission from the party entitled to authorize the assessment.
Document the hosts, allowed paths, timing, request volume, and evidence handling.

`--authorized` confirms that you already have permission. It is not permission,
a legal basis, a waiver, or evidence that the target belongs to you.
Missing CLI authorization stops a scan with exit code 2.

The TUI requires its authorization checkbox before scanning. Launching the TUI
does not authorize a target; the scan button remains disabled until confirmed.
Neither interface can determine whether your assertion is legally valid.

## Permitted Targets

- Your own website, within the systems and services you control.
- A website you have explicit written permission to test, within that scope.
- The loopback-only local lab supplied with this repository.

Owning an application does not automatically authorize testing its hosting
provider, shared tenants, CDN, or unrelated infrastructure.
Stop if a redirect or destination falls outside the authorized scope.

## Prohibited Activity

- Testing third-party sites without explicit written authorization.
- Mass scanning, indiscriminate target discovery, or internet-wide sweeps.
- Exploitation, proof-of-concept requests, or remote code execution attempts.
- Evasion of safety gates, access controls, WAFs, or rate limits.
- Credential attacks, brute force, password guessing, or session hijacking.
- Data exfiltration, secret collection, or collection of unrelated personal data.
- Denial of service, resource exhaustion, or destructive requests.
- Any write method, file upload, webshell, reverse shell, or persistence.

Only `GET` and `HEAD` requests are permitted. A read method does not guarantee
that an application endpoint is free of side effects; choose authorized paths
carefully and stop if unexpected behavior occurs.

## Scope Files

Use `--scope FILE` to further restrict the targets you are already authorized
to assess. A scope file has one host or URL per line. Blank lines and lines
starting with `#` are ignored.

Example contents, using placeholder domains:

```text
# Only explicitly approved targets
your-site.example
https://staging.your-site.example
```

Example invocation:

```bash
uv run php2shell-audit scan https://your-site.example --authorized --scope scope.txt --dry-run
```

A scope file narrows permission; it cannot grant permission. Do not assume
wildcards, subdomain inheritance, or path-prefix rules not defined by the tool.
Review the dry-run plan before making requests. Dry run makes no network
requests and performs no DNS resolution.

## Request Limits

Keep the request budget and rate limit appropriate to the written permission.
Use `--max-requests`, `--rate-limit`, and `--timeout` to constrain activity.
The CLI target cap is 10 by default, with an absolute maximum of 50.
It is a guardrail, not permission to scan that many systems.

`--deep` adds status-only checks for `/.user.ini` and `phpinfo.php`.
Use it only when those paths are authorized; it does not enable exploitation.

## Private Networks and the Lab

Private and special-use destinations are blocked by default.
Use `--allow-private` only for the authorized local lab; it is not a general
internal-network discovery option. Cloud metadata at `169.254.169.254` remains
blocked even with that flag.

Keep lab ports on `127.0.0.1`, never forward them publicly, and tear down the lab
after validation. See [the lab guide](lab/README.md).

## Logging and Evidence Handling

Reports belong in the selected output directory, normally `reports/`.
Report stems are UTC timestamps; if a stem already exists, the writer uses
`-1`, `-2`, and so on so a second scan cannot overwrite the first scan's
evidence. All selected formats for one scan share a stem.
Structured audit logs use
`logs/php2shell-audit-<UTC timestamp with microseconds>.jsonl`; default
filenames also avoid collisions. These paths are intended to be gitignored, not
treated as public artifacts.

- Retain only evidence needed for the authorized assessment.
- Never retain cookie values, authorization headers, API keys, or full bodies.
- Review redaction before sharing; even paths and hostnames can be sensitive.
- Limit access to the operator and authorized remediation staff.
- Use an agreed retention period and secure storage when evidence is sensitive.
- Preserve original reports separately from annotations or edited copies.

Redaction is not anonymization, encryption, or an integrity guarantee.
Do not publish a target's exposure details without the owner's approval.

## Responding to a Finding

If the tool finds a vulnerable version, notify the authorized owner, patch to a
fixed release, and restart all serving workers. Preserve reports for remediation
tracking; do not attempt exploitation to confirm the finding.

Review the third CVE separately and disable `session.upload_progress.enabled`
before request parsing where required. Hidden versions require owner-side
verification, not more aggressive probes.

Stop scanning if permission is withdrawn, the service becomes unstable, or the
observed destination is unexpected. Coordinate next steps with the owner.

## Legal and Ownership Note

Authorization and privacy laws vary. The operator is responsible for obtaining
valid permission and complying with applicable law and provider agreements.
This document is not legal advice.

For ownership or permission questions about this project, contact the repository
owner. For a vulnerability in the tool, follow [Security](SECURITY.md).
