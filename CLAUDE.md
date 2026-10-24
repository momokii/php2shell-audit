# Project Instructions

## Project Snapshot

**Purpose:** Detection-only PHP exposure auditor for explicitly authorized websites.
**Stack:** Python 3.12, uv, Typer, Rich, Textual, httpx; pytest, Ruff, strict mypy.
**Phase:** Application and deployable private Docker lab implemented, locally verified, and internally gate-reviewed.
**Environments:** `APP_ENV` is session safety metadata (`development`, `staging`, `production`), not a scanner runtime switch. Runtime safety uses authorization and target checks. The lab is private test infrastructure, never production.

## Always-Loaded Context

The four files below are imported at session start. They are kept compact on purpose.
Everything else in `.claude/` is read on demand (see On-Demand References).

@.claude/AGENT_RULES.md
@.claude/CODING_STANDARDS.md
@.claude/SECURITY_STANDARDS.md
@.claude/state/CURRENT_STATUS.md

If a file above is missing or did not load, read it manually before doing any work.

## Session Protocol (Summary)

1. Confirm context: `CLAUDE.md` and its four imports appear in `/context` under Memory files. Read `.claude/HOW_TO_RESUME.md` for the full protocol.
2. Read `.claude/state/TASK_QUEUE.md`; pick the next unblocked task.
3. Identify the active environment (`APP_ENV`) before running anything. Unknown means production-safety rules apply.
4. Check git state: branch, uncommitted changes, recent commits. Never clobber existing work.
5. Read task-relevant docs, verify the environment, and run the baseline test suite.
6. State a short plan (goal, files, risks, verification) for any non-trivial task.
7. Implement using the matching template in `.claude/templates/`.
8. Verify: tests, lint, type checks, and the Security Gate.
9. Wrap up: one batched write updating state and standards (`/wrap-up`).

## Commands

Run from the project root. Lab commands require Docker Compose and a source checkout.

| Purpose | Command | Status |
|---|---|---|
| Install dependencies | `uv sync` | Defined |
| Run (development) | `uv run php2shell-audit --help`; `uv run php2shell-audit tui` | Implemented |
| Run (production-like) | No production lab deployment | Not applicable to private test fixtures |
| Test | `uv run pytest` | 567 passed; 2 pre-existing Typer warnings |
| Lint | `uv run ruff check .` | Clean |
| Format | `uv run ruff format .` (check: `uv run ruff format --check .`) | 26 files clean |
| Type check | `uv run mypy src` | 12 source files clean |
| Build | `uv build` | Distribution artifacts built in `dist/` |
| Health check | `uv run php2shell-audit lab status` | Local lab services verified healthy, then removed |
| View logs | `docker compose -f lab/compose.yaml logs` | Local lab only |

## On-Demand References

| When you need... | Read |
|---|---|
| The next task or backlog order | `.claude/state/TASK_QUEUE.md` |
| Why a choice was made | `.claude/state/DECISIONS_LOG.md` |
| Environment definitions and the Compose layout | `.claude/ENVIRONMENT_GUIDE.md` |
| The full session-start protocol | `.claude/HOW_TO_RESUME.md` |
| A checklist for features, endpoints, tests, or bugs | `.claude/templates/` |
| How this `.claude/` setup works and why | `.claude/README.md` |
| Past session summaries | `.claude/state/HISTORY.md` |
| Product docs, specs, or architecture decision records | `docs/` (created with the project) |

Use `/resume` to run the session-start protocol, `/wrap-up` to close a task, and
`/security-check` to audit uncommitted changes against the Security Gate.

## Maintenance Rules for This File

- Keep this file under ~150 lines. Link to deeper files instead of duplicating them.
- Update the Snapshot and Commands sections as soon as facts change; a stale entry is a bug.
- Never remove a rule to make a task easier. Extend or sharpen rules instead.
- `.claude/` is a protected path: batch edits there and expect a one-time permission prompt.

<!-- Human maintainer note: imported files load fully at launch; keep them lean. -->
