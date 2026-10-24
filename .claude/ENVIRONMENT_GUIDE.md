# Environment Guide

## Definitions

| Environment | Purpose | Characteristics |
|---|---|---|
| `development` | Local development | Debug on, verbose logs, hot reload, mock or sandbox services |
| `staging` | Pre-production validation | Production-like config, sandboxed real services, debug off |
| `production` | Live system | Debug off, minimal logs, hardened config, real secrets |

`APP_ENV` identifies the session environment for agent safety policy. If it is missing
or unknown, apply production-safe defaults (fail closed). It is not an implemented
scanner runtime switch: scanning is gated by authorization and target safety controls.
The current project is a Python 3.12/uv CLI/TUI with a private Docker lab, not a deployed
web service. No production lab configuration exists.

## Agent Behavior

**`development`**

- Verbose logging, dev tooling, and debug ports are allowed.
- Seed scripts and migrations are allowed against the local environment.
- Prefer mock or sandbox services; never point local work at production data.

**`staging` and `production`**

- No destructive operation, migration, or configuration change without a written plan
  and explicit user confirmation.
- Never modify live configuration or secrets.
- The agent should not hold production credentials at all. If it detects that it does,
  tell the user and stop using them.
- Present the plan before acting, including the exact commands and the rollback.

**Unknown environment**

- Treat it as production for the purpose of safety.

## Actual Private Lab (Compose v2)

Use `docker compose`, not the legacy `docker-compose`.

- `lab/compose.yaml` is the actual configuration. It runs `php:8.4.26-apache` and
  `php:8.4.27-apache` as detection fixtures, not exploits or real application stacks.
- Bind addresses are hardcoded to `127.0.0.1`; default ports are 18080 (vulnerable) and
  18081 (fixed). Healthchecks and `up --wait --wait-timeout 60` enforce readiness.
- Both services explicitly run as UID/GID 33 with all capabilities dropped, read-only
  roots, bounded temporary filesystems, and 256 MiB/0.5 CPU/128-process limits.
  Webroots are read-only and `no-new-privileges` is set. The low-port sysctl is confined
  to the container network namespace. Old PHP is still not safe for production;
  never publish this lab.
- There is no production override because this is a private test fixture. For future
  application containers, retain the base/development/production separation below:
- `compose.yaml`: future base definitions, environment-agnostic. Do not use the obsolete
  top-level `version:` key.
- `compose.override.yaml`: development overrides (hot reload, debug ports, volume
  mounts). Loaded **automatically** by `docker compose up`.
- `compose.prod.yaml`: production overrides (no source mounts, restart policy, resource
  limits, no debug ports, pinned image tags). Used explicitly.

```bash
# Local lab from the source checkout; Bash and Docker Compose required
./lab/scripts/up.sh
uv run php2shell-audit lab status
docker compose -f lab/compose.yaml logs
./lab/scripts/down.sh

# Automated verification additionally requires uv and Python 3.12
uv sync
./lab/scripts/verify.sh

# Optional retention; explicitly tear down afterwards
KEEP_LAB=1 ./lab/scripts/verify.sh
./lab/scripts/down.sh
```

`up.sh` prints actual URLs, including port overrides. `down.sh` uses
`down -v --remove-orphans` for this disposable lab. The CLI also supports
`uv run php2shell-audit lab up` and `uv run php2shell-audit lab down`; its startup URL
labels describe defaults, so use `up.sh` for actual overridden addresses.

`verify.sh` starts the lab and scans both actual URLs with
`--authorized --allow-private --deep --format json`. It validates exact target URLs and
exact PHP versions and per-CVE verdicts in fresh directories beneath `reports/qa/lab-vulnerable/` and
`reports/qa/lab-fixed/`, failing explicitly on mismatches. Cleanup runs by default;
`KEEP_LAB=1` retains services for investigation and requires explicit teardown.

For a private remote host, use SSH loopback forwarding only, for example
`ssh -N -L 127.0.0.1:18080:127.0.0.1:18080 -L 127.0.0.1:18081:127.0.0.1:18081 user@host`.
Adjust ports to the actual lab bindings. Never use public forwarding or `-g`.

The agent must **always ask** before any Compose command that is not clearly development.
If the project uses different file names, document them here and follow the existing
names.

## Environment Files

The current lab uses `lab/.env.example` (committed port defaults) and optional
`lab/.env` (local, never committed). Copy the example and edit
`LAB_VULNERABLE_PORT`/`LAB_FIXED_PORT` only; the bind address is intentionally not configurable.
Scripts pass an existing file explicitly as `--env-file lab/.env`; never source it as
shell code. For direct Compose commands with local overrides, include the same explicit
`--env-file`, for example `docker compose -f lab/compose.yaml --env-file lab/.env logs`.
No secret values are needed by this lab. The general application env-file contract remains:

```
.env.example      # committed; every variable with placeholder + comment
.env              # never committed; local development values
.env.staging      # never committed
.env.production   # never committed; ideally injected by the deployment platform
```

Development dependencies, debug endpoints, seed data, and admin tools must be **absent or
disabled** in production images and configuration.

## Configuration Rules

- Express environment differences through configuration, never hardcoded branches.
- Required configuration is validated at startup; the application fails closed.
- Secrets are injected at runtime, never baked into images or committed files.
- Every new variable is added to `.env.example` with a placeholder and a description.

> **Self-update:** keep actual lab commands current; future production deployments must
> separately meet the hardening requirements in `SECURITY_STANDARDS.md`.
