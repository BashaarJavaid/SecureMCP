# CLAUDE.md

Project-specific context and instructions for SecurMCP, merged with a set of general behavioral guidelines (sections 1-4 below, adapted from [andrej-karpathy-skills/CLAUDE.md](https://github.com/multica-ai/andrej-karpathy-skills/blob/main/CLAUDE.md)) aimed at reducing common LLM coding mistakes: unstated assumptions, speculative complexity, unrelated edits, and vague success criteria.

**Tradeoff:** these guidelines bias toward caution over speed. For trivial tasks, use judgment.

---

## Project

SecurMCP — a zero-trust, risk-aware gateway proxy for the Model Context Protocol (MCP). Full pitch in `README.md`.

## Where things live

- `README.md` — what this is, tech stack, repo layout, demo script. Read this first.
- `ARCHITECTURE.md` — the decision pipeline, every component in depth, failure modes, hardening, observability, benchmarks, testing, CI/CD, deployment. Load this when working on core gateway logic.
- `THREAT_MODEL.md` — what's protected against, what isn't, and the assumptions the design rests on. Load this when working on anything security-relevant (policy engine, risk engine, auth, audit log).
- `docs/adr/` — one file per architecture decision, including why several common alternatives weren't chosen. Load the specific ADR relevant to the component being touched, not all of them by default.
- `ROADMAP.md` — the four-phase build order as a living checklist. Check this at the start of a session to see what's next; update it as items complete.

Don't load `ARCHITECTURE.md`, `THREAT_MODEL.md`, or the ADRs in full for unrelated tasks (e.g. a pure frontend/demo-recording tweak) — pull in only the file relevant to the current task.

## Conventions

- Python 3.12, FastAPI, async throughout. No `localStorage`/browser-storage patterns apply here (backend service).
- No ML-based risk scoring — see `ARCHITECTURE.md`, Risk Engine section, for why this is a deliberate constraint, not a gap to fill in later.
- The policy DSL is deliberately non-Turing-complete: no loops, no recursion, no arbitrary code execution. Don't "helpfully" extend it with those.
- Every terminal decision (allow/deny/challenge/approval) uses the one canonical `Decision` object shape defined in `ARCHITECTURE.md` §4.3 — don't invent a new response shape for a new endpoint.
- Fail-closed is the default posture for any subsystem failure that would silently weaken a security guarantee (see `ARCHITECTURE.md` §5, Failure Modes). If unsure whether something should fail open or closed, it's closed.

## Commands

- `docker compose up -d` — full stack: gateway (port 8000), Postgres 16 (5432), Redis 7 (6379). Copy `.env.example` to `.env` first (optional; compose has matching dev defaults).
- `docker compose run --rm gateway alembic upgrade head` — run migrations in-container; from the host use `DATABASE_URL=postgresql+asyncpg://securmcp:securmcp@localhost:5432/securmcp .venv/bin/alembic upgrade head`.
- Local dev setup: `python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"`
- `.venv/bin/pytest` — tests
- `.venv/bin/ruff check .` — lint
- `.venv/bin/mypy services/` — strict type-check

## Current phase

See `ROADMAP.md`. Phase 1, item 1 (repo scaffold, Compose skeleton, initial migration) is done; item 2 (Session Manager + JSON-RPC Interceptor) is next.

---

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

This project has been through several rounds of adversarial design review already (see `ARCHITECTURE.md`'s changelog and `docs/adr/`) — most ambiguity has already been resolved in writing somewhere in these docs. If a design question comes up, check there first before guessing; if it's genuinely not covered, that's exactly the kind of thing to surface rather than silently decide.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked, and beyond what the current `ROADMAP.md` phase calls for. Don't pull forward a Phase 3 feature while working on Phase 1.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested — e.g. don't turn the Risk Engine's factor list into a real plugin-loading system; `ARCHITECTURE.md` deliberately scoped that down to a common-interface function list for exactly this reason.
- No error handling for impossible scenarios — but do implement the fail-closed handling that `ARCHITECTURE.md` §5 explicitly calls for; that's a stated requirement, not speculative robustness.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the current task or `ROADMAP.md` item.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add the Replay Guard" → "Write a test that replays an identical nonce+timestamp and asserts `DENY_REPLAY`, then make it pass."
- "Fix the drift detector" → "Write a test that reproduces the false-positive, then make it pass."
- "Refactor the Policy Engine" → "Ensure the full adversarial test suite passes before and after."

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification. `ARCHITECTURE.md`'s Testing Strategy section already defines most of the verification criteria for this project's core components — use it as the source of "verify: [check]" rather than inventing new success criteria per task.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, phase boundaries in `ROADMAP.md` stay respected, and clarifying questions come before implementation rather than after mistakes.
