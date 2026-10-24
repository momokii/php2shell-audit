# Synthetic Offline Example Report

> **Synthetic observations only. No external-site scan was performed.**
> All three `.test` hosts and their HTTP responses are fixed in-memory fixtures,
> not real websites or claims about deployed systems. Advisory references below
> describe the bundled rules; they do not authenticate these synthetic banners.

## Reproduce This Example

From a source checkout with dependencies installed:

```bash
uv run python examples/generate_report.py
```

This uses the public `Scanner` and `write_all` APIs with `httpx.MockTransport`
and a constant injected resolver. No real DNS, HTTP, Docker, or audit log is
used. Each fixture receives exactly one simulated root `GET`; deep probes are
disabled. Artifacts are created under ignored `reports/demo/` with a shared
`synthetic-example` stem and collision suffixes, without replacing earlier runs.
Use `--output-dir DIRECTORY` to select another artifact directory.

To explicitly regenerate and replace this portfolio Markdown from the current
renderer, run:

```bash
uv run python examples/generate_report.py --portfolio
```

The dossier below is the actual writer output with this introduction prepended,
not a hand-authored set of findings. PHP 8.4.26 demonstrates an affected-version
match, 8.4.27 the corresponding fixed-version match, and a versionless PHP banner
an unknown version. Configuration-dependent CVE-2026-115560 remains unknown in
all three cases. No exploitation, installed-runtime verification, or real-site
audit is demonstrated. Timestamps and measured timings vary between runs;
fixture inputs and expected verdicts are reproducible, not byte-identical output.
No full response body is retained in the reports.

---

# PHP2Shell Audit Report

Scan started: 2026-10-24T08:10:19.310013+00:00

Scan finished: 2026-10-24T08:10:19.313503+00:00

Generated UTC: 2026-10-24T08:10:19.317652+00:00

> Detection-only: A version match is exposure evidence, not proof of exploitability.

## Advisory Provenance

| Snapshot schema | Snapshot date | Snapshot SHA-256 |
| --- | --- | --- |
| 1 | 2026-10-24 | 21acedf4dc55ff3e183cdeda3613fa1048447c03f0ad150cd32c25867c4fd55f |

The advisory snapshot is a project-maintained synthesis, not a live source. Its hash identifies snapshot bytes; it is not an authenticity signature. Citations and classifications below come only from the attached assessment data.

## Summary

| Target | Verdict | PHP | SAPI | WAF | Requests | Error |
| --- | --- | --- | --- | --- | --- | --- |
| https://affected.example.test/ | VULNERABLE\_VERSION | 8.4.26 | unknown | none | 1 |  |
| https://fixed.example.test/ | NOT\_VULNERABLE\_VERSION | 8.4.27 | unknown | none | 1 |  |
| https://hidden.example.test/ | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN | detected; version unknown | unknown | none | 1 |  |

## Target: https://affected.example.test/

Verdict: VULNERABLE_VERSION. Observed version matches an affected rule; not proof of exploitability.

### PHP Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP/8.4.26 | GET | https://affected.example.test/ | https://affected.example.test/ | 200 | 2026-10-24T08:10:19.311648+00:00 | 75 | no |

### Assessments

| CVE | Verdict | Reason | Fixed version |
| --- | --- | --- | --- |
| CVE-2026-109618 | VULNERABLE\_VERSION | Observed PHP 8.4.26 is within affected range &gt;=8.4.0 &lt;8.4.27; fixed release 8.4.27. Version evidence is not exploit proof. | 8.4.27 |
| CVE-2026-109619 | VULNERABLE\_VERSION | Observed PHP 8.4.26 is within affected range &gt;=8.4.0 &lt;8.4.27; fixed release 8.4.27. Version evidence is not exploit proof. | 8.4.27 |
| CVE-2026-115560 | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN | Configuration-dependent issue; remote version fingerprinting cannot confirm the required session.serialize\_handler and session.upload\_progress conditions. | not established |

#### CVE-2026-109618: PHP memory corruption during out-of-memory handling

| Assessment detail | Value |
| --- | --- |
| Conclusion | VULNERABLE\_VERSION |
| Severity | critical |
| Rating provenance | not established |
| Assessment basis | observed\_version |
| Observed version | 8.4.26 |
| Affected range | &gt;=8.4.0 &lt;8.4.27 |
| Affected range match | yes |
| Branch fixed version | 8.4.27 |
| Configuration dependent | no |
| Source-described conditions | not established |
| Reasoning | Observed PHP 8.4.26 is within affected range &gt;=8.4.0 &lt;8.4.27; fixed release 8.4.27. Version evidence is not exploit proof. |

A version match is not proof of exploitability; configuration conditions require local verification.

##### Bound HTTP Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP/8.4.26 | GET | https://affected.example.test/ | https://affected.example.test/ | 200 | 2026-10-24T08:10:19.311648+00:00 | 75 | no |

##### Recommended Action

- Upgrade to the fixed release for the branch or a supported newer release; verify distribution backports with the vendor and restart workers.
- Temporary measures reduce exposure but are not a complete fix. Isolate affected internet-facing services if patching cannot be completed.
- At administrator level, consider memory\_limit=-1 with container or cgroup availability limits. Allocation failures remain a risk; do not substitute RLIMIT\_AS or RLIMIT\_DATA.
- Set post\_max\_size to 8M without uploads or 32M when uploads are required; keep upload\_max\_filesize smaller. Apply decoded request-size and input-count limits at the proxy or web server.

##### Verification

- Confirm the PHP version of the web-serving runtime locally, not only the CLI or remote banner.
- Check vendor security notices and installed package revisions for backported fixes.
- Restart every serving worker after patching, then rescan the authorized endpoint; a banner alone cannot verify a backport.

##### Authoritative References (Attached Snapshot)

- https://www.php.net/archive/2026.php\#2026-10-21-5
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- https://cert.europa.eu/publications/security-advisories/2026-018/
- https://github.com/NCSC-NL/php2shell

#### CVE-2026-109619: PHP use-after-free through stale request-owned global state

| Assessment detail | Value |
| --- | --- |
| Conclusion | VULNERABLE\_VERSION |
| Severity | critical |
| Rating provenance | not established |
| Assessment basis | observed\_version |
| Observed version | 8.4.26 |
| Affected range | &gt;=8.4.0 &lt;8.4.27 |
| Affected range match | yes |
| Branch fixed version | 8.4.27 |
| Configuration dependent | no |
| Source-described conditions | not established |
| Reasoning | Observed PHP 8.4.26 is within affected range &gt;=8.4.0 &lt;8.4.27; fixed release 8.4.27. Version evidence is not exploit proof. |

A version match is not proof of exploitability; configuration conditions require local verification.

##### Bound HTTP Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP/8.4.26 | GET | https://affected.example.test/ | https://affected.example.test/ | 200 | 2026-10-24T08:10:19.311648+00:00 | 75 | no |

##### Recommended Action

- Upgrade to the fixed release for the branch or a supported newer release; verify distribution backports with the vendor and restart workers.
- Set session.upload\_progress.enabled=0 before request parsing in php.ini, the FPM pool or server configuration; restart every worker. Do not rely on ini\_set\(\) or FPM .user.ini. This is partial mitigation only.
- On PHP 8.5 set fatal\_error\_backtraces=0 and restart workers; this only mitigates the confirmed fatal-backtrace path.
- Remove invalid or deprecated per-request settings that emit early diagnostics; remediate reachable fatal errors and execution timeouts. Hiding diagnostics does not mitigate the issue.

##### Verification

- Confirm the PHP version of the web-serving runtime locally, not only the CLI or remote banner.
- Check vendor security notices and installed package revisions for backported fixes.
- Restart every serving worker after patching, then rescan the authorized endpoint; a banner alone cannot verify a backport.

##### Authoritative References (Attached Snapshot)

- https://www.php.net/archive/2026.php\#2026-10-21-5
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- https://cert.europa.eu/publications/security-advisories/2026-018/
- https://github.com/NCSC-NL/php2shell

#### CVE-2026-115560: PHP configuration-dependent session upload progress issue

| Assessment detail | Value |
| --- | --- |
| Conclusion | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN |
| Severity | critical |
| Rating provenance | Project-supplied classification only: critical and CVSS v4.0 9.2 are not upstream ratings. PHP has no published upstream severity, CVSS rating or affected range for this CVE and has not published a full advisory as of generated\_at. |
| Assessment basis | unverified\_configuration |
| Observed version | not established |
| Affected range | not established |
| Affected range match | unknown |
| Branch fixed version | not established |
| Configuration dependent | yes |
| Source-described conditions | application sets session.serialize\_handler to php\_binary or php\_serialize, then switches to php at runtime with ini\_set\(\) before session\_start\(\), with session.upload\_progress.enabled=1 |
| Reasoning | Configuration-dependent issue; remote version fingerprinting cannot confirm the required session.serialize\_handler and session.upload\_progress conditions. |

A version match is not proof of exploitability; configuration conditions require local verification.

##### Bound HTTP Evidence

No supporting observation attached.

##### Recommended Action

- session.upload\_progress.enabled=0
- Apply the setting before request parsing and restart every worker until the next regular bugfix release. No out-of-band patch is planned.

##### Verification

- Inspect effective session.upload\_progress.enabled and session.serialize\_handler in the web-serving runtime locally.
- Review application code for runtime session.serialize\_handler switches before session\_start\(\); remote version evidence does not establish this behavior.
- Verify session.upload\_progress.enabled=0 is applied before request parsing and restart every serving worker.
- Check vendor updates and rescan the authorized endpoint for observations only; remote rescanning cannot confirm the local configuration condition.

##### Authoritative References (Attached Snapshot)

- https://www.php.net/archive/2026.php\#2026-10-23-1
- https://cert.europa.eu/publications/security-advisories/2026-018/

### Findings

| Severity | Title | Description | Mitigation |
| --- | --- | --- | --- |
| info | PHP version disclosed | A PHP version banner was observed; this is not proof of exploitability. | Disable expose\_php or remove the version header. |
| low | Missing baseline security headers | Missing: strict-transport-security, content-security-policy, x-content-type-options, x-frame-options, referrer-policy. Separate from CVE version assessments. | Configure security headers appropriate for the application. |

### Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP/8.4.26 | GET | https://affected.example.test/ | https://affected.example.test/ | 200 | 2026-10-24T08:10:19.311648+00:00 | 75 | no |
| response:status | 200 | not established | not established | not established | not established | not established | not established | not established |
| response:final\_url | https://affected.example.test/ | not established | not established | not established | not established | not established | not established | not established |
| header:x-powered-by | PHP/8.4.26 | GET | https://affected.example.test/ | https://affected.example.test/ | 200 | 2026-10-24T08:10:19.311648+00:00 | 75 | no |

## Target: https://fixed.example.test/

Verdict: NOT_VULNERABLE_VERSION. Version rule indicates a fixed release, not an all-clear. Configuration-dependent exposure may remain unknown.

### PHP Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP/8.4.27 | GET | https://fixed.example.test/ | https://fixed.example.test/ | 200 | 2026-10-24T08:10:19.312854+00:00 | 75 | no |

### Assessments

| CVE | Verdict | Reason | Fixed version |
| --- | --- | --- | --- |
| CVE-2026-109618 | NOT\_VULNERABLE\_VERSION | Observed PHP 8.4.27 is outside affected range &gt;=8.4.0 &lt;8.4.27; fixed release 8.4.27. Version evidence is not exploit proof. | 8.4.27 |
| CVE-2026-109619 | NOT\_VULNERABLE\_VERSION | Observed PHP 8.4.27 is outside affected range &gt;=8.4.0 &lt;8.4.27; fixed release 8.4.27. Version evidence is not exploit proof. | 8.4.27 |
| CVE-2026-115560 | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN | Configuration-dependent issue; remote version fingerprinting cannot confirm the required session.serialize\_handler and session.upload\_progress conditions. | not established |

#### CVE-2026-109618: PHP memory corruption during out-of-memory handling

| Assessment detail | Value |
| --- | --- |
| Conclusion | NOT\_VULNERABLE\_VERSION |
| Severity | critical |
| Rating provenance | not established |
| Assessment basis | observed\_version |
| Observed version | 8.4.27 |
| Affected range | &gt;=8.4.0 &lt;8.4.27 |
| Affected range match | no |
| Branch fixed version | 8.4.27 |
| Configuration dependent | no |
| Source-described conditions | not established |
| Reasoning | Observed PHP 8.4.27 is outside affected range &gt;=8.4.0 &lt;8.4.27; fixed release 8.4.27. Version evidence is not exploit proof. |

A version match is not proof of exploitability; configuration conditions require local verification.

##### Bound HTTP Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP/8.4.27 | GET | https://fixed.example.test/ | https://fixed.example.test/ | 200 | 2026-10-24T08:10:19.312854+00:00 | 75 | no |

##### Recommended Action

- Upgrade to the fixed release for the branch or a supported newer release; verify distribution backports with the vendor and restart workers.
- Temporary measures reduce exposure but are not a complete fix. Isolate affected internet-facing services if patching cannot be completed.
- At administrator level, consider memory\_limit=-1 with container or cgroup availability limits. Allocation failures remain a risk; do not substitute RLIMIT\_AS or RLIMIT\_DATA.
- Set post\_max\_size to 8M without uploads or 32M when uploads are required; keep upload\_max\_filesize smaller. Apply decoded request-size and input-count limits at the proxy or web server.

##### Verification

- Confirm the PHP version of the web-serving runtime locally, not only the CLI or remote banner.
- Check vendor security notices and installed package revisions for backported fixes.
- Restart every serving worker after patching, then rescan the authorized endpoint; a banner alone cannot verify a backport.

##### Authoritative References (Attached Snapshot)

- https://www.php.net/archive/2026.php\#2026-10-21-5
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- https://cert.europa.eu/publications/security-advisories/2026-018/
- https://github.com/NCSC-NL/php2shell

#### CVE-2026-109619: PHP use-after-free through stale request-owned global state

| Assessment detail | Value |
| --- | --- |
| Conclusion | NOT\_VULNERABLE\_VERSION |
| Severity | critical |
| Rating provenance | not established |
| Assessment basis | observed\_version |
| Observed version | 8.4.27 |
| Affected range | &gt;=8.4.0 &lt;8.4.27 |
| Affected range match | no |
| Branch fixed version | 8.4.27 |
| Configuration dependent | no |
| Source-described conditions | not established |
| Reasoning | Observed PHP 8.4.27 is outside affected range &gt;=8.4.0 &lt;8.4.27; fixed release 8.4.27. Version evidence is not exploit proof. |

A version match is not proof of exploitability; configuration conditions require local verification.

##### Bound HTTP Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP/8.4.27 | GET | https://fixed.example.test/ | https://fixed.example.test/ | 200 | 2026-10-24T08:10:19.312854+00:00 | 75 | no |

##### Recommended Action

- Upgrade to the fixed release for the branch or a supported newer release; verify distribution backports with the vendor and restart workers.
- Set session.upload\_progress.enabled=0 before request parsing in php.ini, the FPM pool or server configuration; restart every worker. Do not rely on ini\_set\(\) or FPM .user.ini. This is partial mitigation only.
- On PHP 8.5 set fatal\_error\_backtraces=0 and restart workers; this only mitigates the confirmed fatal-backtrace path.
- Remove invalid or deprecated per-request settings that emit early diagnostics; remediate reachable fatal errors and execution timeouts. Hiding diagnostics does not mitigate the issue.

##### Verification

- Confirm the PHP version of the web-serving runtime locally, not only the CLI or remote banner.
- Check vendor security notices and installed package revisions for backported fixes.
- Restart every serving worker after patching, then rescan the authorized endpoint; a banner alone cannot verify a backport.

##### Authoritative References (Attached Snapshot)

- https://www.php.net/archive/2026.php\#2026-10-21-5
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- https://cert.europa.eu/publications/security-advisories/2026-018/
- https://github.com/NCSC-NL/php2shell

#### CVE-2026-115560: PHP configuration-dependent session upload progress issue

| Assessment detail | Value |
| --- | --- |
| Conclusion | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN |
| Severity | critical |
| Rating provenance | Project-supplied classification only: critical and CVSS v4.0 9.2 are not upstream ratings. PHP has no published upstream severity, CVSS rating or affected range for this CVE and has not published a full advisory as of generated\_at. |
| Assessment basis | unverified\_configuration |
| Observed version | not established |
| Affected range | not established |
| Affected range match | unknown |
| Branch fixed version | not established |
| Configuration dependent | yes |
| Source-described conditions | application sets session.serialize\_handler to php\_binary or php\_serialize, then switches to php at runtime with ini\_set\(\) before session\_start\(\), with session.upload\_progress.enabled=1 |
| Reasoning | Configuration-dependent issue; remote version fingerprinting cannot confirm the required session.serialize\_handler and session.upload\_progress conditions. |

A version match is not proof of exploitability; configuration conditions require local verification.

##### Bound HTTP Evidence

No supporting observation attached.

##### Recommended Action

- session.upload\_progress.enabled=0
- Apply the setting before request parsing and restart every worker until the next regular bugfix release. No out-of-band patch is planned.

##### Verification

- Inspect effective session.upload\_progress.enabled and session.serialize\_handler in the web-serving runtime locally.
- Review application code for runtime session.serialize\_handler switches before session\_start\(\); remote version evidence does not establish this behavior.
- Verify session.upload\_progress.enabled=0 is applied before request parsing and restart every serving worker.
- Check vendor updates and rescan the authorized endpoint for observations only; remote rescanning cannot confirm the local configuration condition.

##### Authoritative References (Attached Snapshot)

- https://www.php.net/archive/2026.php\#2026-10-23-1
- https://cert.europa.eu/publications/security-advisories/2026-018/

### Findings

| Severity | Title | Description | Mitigation |
| --- | --- | --- | --- |
| info | PHP version disclosed | A PHP version banner was observed; this is not proof of exploitability. | Disable expose\_php or remove the version header. |
| low | Missing baseline security headers | Missing: strict-transport-security, content-security-policy, x-content-type-options, x-frame-options, referrer-policy. Separate from CVE version assessments. | Configure security headers appropriate for the application. |

### Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP/8.4.27 | GET | https://fixed.example.test/ | https://fixed.example.test/ | 200 | 2026-10-24T08:10:19.312854+00:00 | 75 | no |
| response:status | 200 | not established | not established | not established | not established | not established | not established | not established |
| response:final\_url | https://fixed.example.test/ | not established | not established | not established | not established | not established | not established | not established |
| header:x-powered-by | PHP/8.4.27 | GET | https://fixed.example.test/ | https://fixed.example.test/ | 200 | 2026-10-24T08:10:19.312854+00:00 | 75 | no |

## Target: https://hidden.example.test/

Verdict: POTENTIALLY_VULNERABLE_VERSION_UNKNOWN. Exposure is unknown; establish the runtime, applicable rule and configuration locally.

### PHP Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP | GET | https://hidden.example.test/ | https://hidden.example.test/ | 200 | 2026-10-24T08:10:19.313395+00:00 | 75 | no |

### Assessments

| CVE | Verdict | Reason | Fixed version |
| --- | --- | --- | --- |
| CVE-2026-109618 | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN | No PHP version was observed; exposure cannot be ruled out. | not established |
| CVE-2026-109619 | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN | No PHP version was observed; exposure cannot be ruled out. | not established |
| CVE-2026-115560 | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN | Configuration-dependent issue; remote version fingerprinting cannot confirm the required session.serialize\_handler and session.upload\_progress conditions. | not established |

#### CVE-2026-109618: PHP memory corruption during out-of-memory handling

| Assessment detail | Value |
| --- | --- |
| Conclusion | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN |
| Severity | critical |
| Rating provenance | not established |
| Assessment basis | observed\_version |
| Observed version | not established |
| Affected range | not established |
| Affected range match | unknown |
| Branch fixed version | not established |
| Configuration dependent | no |
| Source-described conditions | not established |
| Reasoning | No PHP version was observed; exposure cannot be ruled out. |

A version match is not proof of exploitability; configuration conditions require local verification.

##### Bound HTTP Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP | GET | https://hidden.example.test/ | https://hidden.example.test/ | 200 | 2026-10-24T08:10:19.313395+00:00 | 75 | no |

##### Recommended Action

- Upgrade to the fixed release for the branch or a supported newer release; verify distribution backports with the vendor and restart workers.
- Temporary measures reduce exposure but are not a complete fix. Isolate affected internet-facing services if patching cannot be completed.
- At administrator level, consider memory\_limit=-1 with container or cgroup availability limits. Allocation failures remain a risk; do not substitute RLIMIT\_AS or RLIMIT\_DATA.
- Set post\_max\_size to 8M without uploads or 32M when uploads are required; keep upload\_max\_filesize smaller. Apply decoded request-size and input-count limits at the proxy or web server.

##### Verification

- Confirm the PHP version of the web-serving runtime locally, not only the CLI or remote banner.
- Check vendor security notices and installed package revisions for backported fixes.
- Restart every serving worker after patching, then rescan the authorized endpoint; a banner alone cannot verify a backport.

##### Authoritative References (Attached Snapshot)

- https://www.php.net/archive/2026.php\#2026-10-21-5
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- https://cert.europa.eu/publications/security-advisories/2026-018/
- https://github.com/NCSC-NL/php2shell

#### CVE-2026-109619: PHP use-after-free through stale request-owned global state

| Assessment detail | Value |
| --- | --- |
| Conclusion | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN |
| Severity | critical |
| Rating provenance | not established |
| Assessment basis | observed\_version |
| Observed version | not established |
| Affected range | not established |
| Affected range match | unknown |
| Branch fixed version | not established |
| Configuration dependent | no |
| Source-described conditions | not established |
| Reasoning | No PHP version was observed; exposure cannot be ruled out. |

A version match is not proof of exploitability; configuration conditions require local verification.

##### Bound HTTP Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP | GET | https://hidden.example.test/ | https://hidden.example.test/ | 200 | 2026-10-24T08:10:19.313395+00:00 | 75 | no |

##### Recommended Action

- Upgrade to the fixed release for the branch or a supported newer release; verify distribution backports with the vendor and restart workers.
- Set session.upload\_progress.enabled=0 before request parsing in php.ini, the FPM pool or server configuration; restart every worker. Do not rely on ini\_set\(\) or FPM .user.ini. This is partial mitigation only.
- On PHP 8.5 set fatal\_error\_backtraces=0 and restart workers; this only mitigates the confirmed fatal-backtrace path.
- Remove invalid or deprecated per-request settings that emit early diagnostics; remediate reachable fatal errors and execution timeouts. Hiding diagnostics does not mitigate the issue.

##### Verification

- Confirm the PHP version of the web-serving runtime locally, not only the CLI or remote banner.
- Check vendor security notices and installed package revisions for backported fixes.
- Restart every serving worker after patching, then rescan the authorized endpoint; a banner alone cannot verify a backport.

##### Authoritative References (Attached Snapshot)

- https://www.php.net/archive/2026.php\#2026-10-21-5
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- https://cert.europa.eu/publications/security-advisories/2026-018/
- https://github.com/NCSC-NL/php2shell

#### CVE-2026-115560: PHP configuration-dependent session upload progress issue

| Assessment detail | Value |
| --- | --- |
| Conclusion | POTENTIALLY\_VULNERABLE\_VERSION\_UNKNOWN |
| Severity | critical |
| Rating provenance | Project-supplied classification only: critical and CVSS v4.0 9.2 are not upstream ratings. PHP has no published upstream severity, CVSS rating or affected range for this CVE and has not published a full advisory as of generated\_at. |
| Assessment basis | unverified\_configuration |
| Observed version | not established |
| Affected range | not established |
| Affected range match | unknown |
| Branch fixed version | not established |
| Configuration dependent | yes |
| Source-described conditions | application sets session.serialize\_handler to php\_binary or php\_serialize, then switches to php at runtime with ini\_set\(\) before session\_start\(\), with session.upload\_progress.enabled=1 |
| Reasoning | Configuration-dependent issue; remote version fingerprinting cannot confirm the required session.serialize\_handler and session.upload\_progress conditions. |

A version match is not proof of exploitability; configuration conditions require local verification.

##### Bound HTTP Evidence

No supporting observation attached.

##### Recommended Action

- session.upload\_progress.enabled=0
- Apply the setting before request parsing and restart every worker until the next regular bugfix release. No out-of-band patch is planned.

##### Verification

- Inspect effective session.upload\_progress.enabled and session.serialize\_handler in the web-serving runtime locally.
- Review application code for runtime session.serialize\_handler switches before session\_start\(\); remote version evidence does not establish this behavior.
- Verify session.upload\_progress.enabled=0 is applied before request parsing and restart every serving worker.
- Check vendor updates and rescan the authorized endpoint for observations only; remote rescanning cannot confirm the local configuration condition.

##### Authoritative References (Attached Snapshot)

- https://www.php.net/archive/2026.php\#2026-10-23-1
- https://cert.europa.eu/publications/security-advisories/2026-018/

### Findings

| Severity | Title | Description | Mitigation |
| --- | --- | --- | --- |
| info | PHP detected without a version | Version-based exposure cannot be ruled out. |  |
| low | Missing baseline security headers | Missing: strict-transport-security, content-security-policy, x-content-type-options, x-frame-options, referrer-policy. Separate from CVE version assessments. | Configure security headers appropriate for the application. |

### Evidence

| Source | Value | Method | Requested URL | Final URL | Status | Observed UTC | Body prefix bytes | Body truncated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| header:x-powered-by | PHP | GET | https://hidden.example.test/ | https://hidden.example.test/ | 200 | 2026-10-24T08:10:19.313395+00:00 | 75 | no |
| response:status | 200 | not established | not established | not established | not established | not established | not established | not established |
| response:final\_url | https://hidden.example.test/ | not established | not established | not established | not established | not established | not established | not established |
| header:x-powered-by | PHP | GET | https://hidden.example.test/ | https://hidden.example.test/ | 200 | 2026-10-24T08:10:19.313395+00:00 | 75 | no |

## Remediation

Use each CVE's attached recommended actions and verification steps above. CSV is a compact summary; JSON, JSONL and this Markdown report carry the full detail.

General guidance (not an observation): verify the installed runtime and vendor patches locally, then restart PHP-FPM/Apache workers after remediation. For CVE-2026-115560, review `session.upload_progress.enabled=0` before request parsing; a version-fixed result does not establish remediation of this configuration-dependent issue.

Unknown versions require server-side verification of the runtime and vendor patch status.

## Limitations

Hidden `X-Powered-By`, WAF stripping, reverse proxies, shared hosting, and distro backports can obscure or change version evidence. Banners can be forged or stale. WAF presence does not establish protection, and remote evidence cannot confirm configuration-dependent conditions. Unsupported branches remain unknown, not inferred affected or fixed. Only bounded observations are retained, not full response bodies. Missing request metadata means collection details were not established, not that a request was observed. No heuristic confidence or numeric risk score is inferred.
