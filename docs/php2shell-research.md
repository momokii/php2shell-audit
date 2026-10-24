# PHP2Shell Research

Date: 2026-10-24
Status: research snapshot

## Executive Summary

The bundled advisory snapshot describes two critical PHP2Shell vulnerabilities:
CVE-2026-109618 and CVE-2026-109619, each rated CVSS v4.0 9.2.
Patching and restarting all serving workers are the complete fix for these two
issues. Temporary mitigations and a WAF are not substitutes.

A third issue, CVE-2026-115560, depends on configuration and application behavior.
It has no out-of-band patch in this snapshot. Disable session upload progress
before request parsing and restart workers. The fixed-version matrix for the
first two CVEs does not establish remediation of the third.

This document summarizes `src/php2shell_audit/data/php2shell.json`; both are a
dated, project-maintained synthesis of the cited sources, not an upstream
authority, live advisory feed or exploitation guide. Version mapping is limited
to the explicitly covered PHP 8.2-8.5 branches, without extrapolating affected or
fixed status to older or newer unlisted branches.

## CVE Matrix

| CVE | Issue | CVSS v4.0 | Affected branches | Fixed version | Notes |
|---|---|---|---|---|---|
| CVE-2026-109618 | Memory corruption during out-of-memory handling | 9.2 | 8.2.0-8.2.34; 8.3.0-8.3.35; 8.4.0-8.4.26; 8.5.0-8.5.11 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | Critical; unsupported older branches require separate vendor verification. |
| CVE-2026-109619 | Use-after-free through stale request-owned global state | 9.2 | 8.2.0-8.2.34; 8.3.0-8.3.35; 8.4.0-8.4.26; 8.5.0-8.5.11 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | Critical; same version matrix as CVE-2026-109618. |
| CVE-2026-115560 | Configuration-dependent session upload progress issue | 9.2, project-supplied | Not established by the informational advisory | No out-of-band patch | Disable `session.upload_progress.enabled`; do not apply the other CVEs' matrix. |

For CVE-2026-115560, both the critical label and score are supplied project
classifications, not upstream ratings. PHP had not published a full advisory,
severity, CVSS rating or affected-version range for this CVE as of the snapshot
date. Its references are PHP's October 23 informational notice and CERT-EU;
GHSA-6wmf-4rv5-p3rp is the advisory for CVE-2026-109619, not a full advisory for
the third CVE, even where its mitigation guidance is related.

The stated condition is an application starting with `session.serialize_handler`
set to `php_binary` or `php_serialize`, then switching it to `php` at runtime
before `session_start()`, while `session.upload_progress.enabled=1`.
A remote version or SAPI observation cannot confirm that condition.

PHP <=8.1 is unsupported and has no upstream fixed release for the two
version-mapped CVEs. PHP provides minimal source backports for 7.4, 8.0 and 8.1;
these are not upstream fixed releases. Vendor backports may exist and require
verification with that vendor. These support and backport notes do not establish
a verified affected range or a lower affected-version bound for older branches;
in particular, a PHP 5.4 lower bound is not verified. Prefer migration to a
supported branch.

## What the Tool Observes

- Response headers and HTTP status codes.
- Cookie names, such as `PHPSESSID`, never cookie values in retained evidence.
- Generator meta tags and bounded response-body prefixes for fingerprinting.
- PHP version disclosures, conservative SAPI hints, and WAF/intermediary hints.

Body inspection is bounded; full response bodies are not retained in reports.
Optional deep checks record status only for `/.user.ini` and `phpinfo.php`,
never their bodies. These checks are not exploit probes.

## What the Tool Does Not Prove

- It does not prove exploitability or successful compromise.
- It does not execute code on targets or upload files.
- It does not prove a hidden PHP version or inspect local PHP configuration.
- It does not confirm CVE-2026-115560's runtime condition remotely.
- It does not establish that a WAF or a particular SAPI makes a target safe.

## Detection Methodology

1. Require authorization and validate target, DNS/IP destinations, and scope.
2. Make budgeted, rate-limited `GET`/`HEAD` observations.
3. Fingerprint PHP using headers, cookie names, and generator metadata.
4. Map an observed version to the bundled CVE ranges and branch-specific fixes.
5. Record bounded, redacted evidence separately from CVE assessments and findings.
6. Report uncertainty instead of inferring an undisclosed version.

`VULNERABLE_VERSION` is version exposure evidence, not exploit proof.
`NOT_VULNERABLE_VERSION` is not a general security clearance and does not resolve
the third CVE. PHP detected without a version yields an unknown-version outcome,
`POTENTIALLY_VULNERABLE_VERSION_UNKNOWN`.

## Limitations

| Condition | Effect on interpretation |
|---|---|
| `expose_php=Off` | PHP version headers may be absent. |
| WAF header stripping | Disclosures can be removed; absence does not establish safety. |
| Reverse proxies | Edge headers may not describe the backend runtime. |
| Shared hosting | One observation may not represent other pools or tenants. |
| Distribution backports | A version string alone may not reflect vendor security fixes. |

All web-serving SAPIs require review, including mod_php, PHP-FPM, php-cgi,
LiteSpeed, and FrankenPHP. The snapshot identifies mod_php as highest risk;
SAPI inference alone does not establish exploitability or safety.

## Remediation

1. Upgrade to the fixed release for the branch, or a supported newer release.
2. Restart PHP-FPM and/or Apache workers, plus every other serving PHP worker.
3. Verify the installed runtime with `php -v` on the host or container and compare
   it with the fixed-version matrix. Separately confirm the web workers use that
   runtime: the CLI binary can differ from the serving SAPI.
4. Verify distribution backports with the vendor rather than trusting a banner.
5. For CVE-2026-115560, apply `session.upload_progress.enabled=0` in configuration
   before request parsing, then restart every worker. Do not rely on a runtime
   `ini_set()` change or FPM `.user.ini` for this mitigation.
6. Recheck authorized endpoints and preserve the before/after reports.

If patching cannot be completed, isolate affected internet-facing services.
Request-size limits and other temporary measures are partial mitigations only.
Disabling upload progress also only partially mitigates CVE-2026-109619; it does
not replace patching the two critical version-mapped issues.

## Public PoCs

Public proof-of-concept repositories exist and were deliberately not used.
This project is detection-only. It includes no PoC links, payloads, or exploit
validation procedure.

## References

The bundled JSON is a project-maintained synthesis, not the authority for these
claims. Source checks for this correction verified the PHP October 21 disclosure,
October 23 informational notice and both PHP GHSAs. The remaining references are
retained supporting guidance, not independently revalidated in this correction:

- [PHP disclosure, 2026-10-21](https://www.php.net/archive/2026.php#2026-10-21-5)
- [PHP informational update, 2026-10-23](https://www.php.net/archive/2026.php#2026-10-23-1)
- [PHP security advisory GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP security advisory GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [CISA patching alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
- [CERT-EU advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [NCSC-NL PHP2Shell guidance](https://github.com/NCSC-NL/php2shell)

## Safety and Legal Note

Use only on systems you own or have explicit written permission to assess.
Authorization and privacy requirements vary by jurisdiction; the operator is
responsible for compliance. Read [Authorized Use](../AUTHORIZED_USE.md) and
[Security](../SECURITY.md) before collecting evidence.
