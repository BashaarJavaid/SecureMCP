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

- `python scripts/generate_signing_key.py` — one-time: mint the audit-log ECDSA keypair into gitignored `secrets/`; the gateway fails startup without it.
- `docker compose up -d` — full stack: gateway (port 8000), Postgres 16 (5432), Redis 7 (6379), audit verifier sidecar. Copy `.env.example` to `.env` first (optional; compose has matching dev defaults).
- `docker compose --profile monitoring up -d` — same stack plus Prometheus (9090) and a provisioned Grafana dashboard (3000, anonymous). The gateway/verifier metrics listeners (9100/9101) are compose-internal only — labels carry identity ids and tool names (§7).
- `docker compose run --rm gateway alembic upgrade head` — run migrations in-container; from the host use `DATABASE_URL=postgresql+asyncpg://securmcp:securmcp@localhost:5432/securmcp .venv/bin/alembic upgrade head`.
- Local dev setup: `python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"`
- `.venv/bin/pytest` — tests
- `.venv/bin/ruff check .` — lint
- `.venv/bin/ruff format --check .` — formatting (CI-enforced; fix with `ruff format .`)
- `.venv/bin/mypy services/` — strict type-check
- `.venv/bin/python scripts/verify_audit_chain.py` — walk and verify the audit hash chain (+ signatures when the public key is present)
- `.venv/bin/python scripts/verify_audit_chain.py --diff-policy v3 v4 [--html]` — diff two policy revision snapshots from `policies/revisions/` (no DB needed); `--html` writes a side-by-side `policy-diff-v3-v4.html` (stdlib `difflib.HtmlDiff`)
- `curl -X POST localhost:8000/admin/policy/rollback/<n> -H "X-SecurMCP-Key: <admin key>"` — re-activate a prior policy revision in memory (POLICY_FILE on disk keeps the newer version until the operator updates it; a restart reverts, audited)
- `curl localhost:8000/admin/decisions/<seq> -H "X-SecurMCP-Key: <admin key>"` — Decision Explanation for a past audit row (`<seq>` = the `audit_id` in a client's Decision); non-decision rows (TOOLS_LIST, POLICY_ACTIVATED, …) are 404
- `curl -X POST localhost:8000/admin/decisions/explain -H "X-SecurMCP-Key: <admin key>" -H "Content-Type: application/json" -d '{"identity": "agent-readonly", "tool": "delete_repo", "arguments": {"repo": "acme/prod-api"}, "context": {"hour": 22}}'` — dry-run "what would happen" against the current in-memory policy; no audit rows, no counters, no upstream traffic
- `curl -X POST localhost:8000/admin/policy/simulate -H "X-SecurMCP-Key: <admin key>" -H "Content-Type: application/json" -d '{"candidate_version": 2, "replay_window": "2026-06-01..2026-07-01"}'` — Policy Simulation: replay the window's historical decisions against a candidate revision snapshot (`{"compare_versions": [1, 2], ...}` diffs two revisions instead); read-only, capped at 10k rows
- `.venv/bin/python scripts/audit_verifier_daemon.py [--once]` — incremental checkpointed verification (the compose `verifier` sidecar runs this on a loop)
- `.venv/bin/python -m tests.benchmarks.run [N]` — performance benchmark suite (default N=1000 calls/scenario); needs postgres + redis up (`docker compose up -d postgres redis`) and wipes the dev audit chain like the integration tests do; reports land in gitignored `tests/benchmarks/reports/`
- `python scripts/run_demo.py` then `POLICY_FILE=policies/demo-policy.yaml SECURMCP_DEMO_SIGNING_SECRET=<printed by the script> docker compose up -d --build` (the rogue upstream command lives in the demo policy's `servers:` block, item 35), then `curl -X POST localhost:9800/_admin/apply_mutation` when prompted, then `docker kill -s HUP securemcp-gateway-1` when prompted again — the full seven-beat demo: pruning, a stock-client call (bearer, no `_meta`), drift blocking, re-approval, the signed ci-agent's capture-replay (byte-identical → DENY_REPLAY, forged fresh nonce → 401), and Policy Simulation of a tightened v2 draft over the demo's own traffic (resets the dev audit chain/baselines/risk counters at start)
- CI (`.github/workflows/ci.yml`): lint + format check + mypy + `pytest --cov=services --cov-fail-under=80` + docker build on every push/PR; benchmarks (N=100, report artifact) on pushes to `main` only; `release.yml` pushes `ghcr.io/<owner>/securmcp` on `v*` tags.

## Current phase

See `ROADMAP.md`. Phases 1–3 are complete (items 1–23): the Risk Engine + approval lifecycle (16), ABAC conditions (17, `services/gateway/abac.py`), richer risk telemetry (18), policy versioning + rollback (19, `services/gateway/policy_versions.py`), the Decision Explanation API (20, `services/gateway/decision_explainer.py`), Policy Simulation Mode (21, `services/gateway/policy_simulator.py`), the architecture diagrams + multi-server trust domain discussion in `ARCHITECTURE.md` §4.1/§4.4–§4.7 (22, documented not built), and the expanded adversarial suite (23: `tests/adversarial/test_risk_scoring.py` §11 canary + DENY_RISK with business-hours active, `test_abac_adversarial.py` missing-attribute incl. inside `not(...)` e2e, `test_explanation_accuracy.py`, `test_simulation_accuracy.py` historical-hour replay, `test_tool_poisoning.py`, and `test_concurrent_audit_writes_do_not_collide` at 100 writes; TOCTOU was already covered by `test_risk_approval.py`; hypothesis fuzzing deferred). Phase 4 is underway docs-and-observability-first, deployment deferred: item 24 (Terraform) waits until deployment is actually wanted, and items 26 (ADRs, verified already complete from the item-30 doc split), 27 (scalability write-up in `ARCHITECTURE.md` §10, now citing item 23's experimentally confirmed two-writer chain fork), 29 (the "Beyond v1 — documented, not built" section in `ROADMAP.md`: all six deferred features with triggers, incl. the two-person-activation design sketch `THREAT_MODEL.md` promised), 28 (README finalized: §4.4 diagram embedded, threat-model summary table, benchmarks re-measured at `902341f` with the full Phase-3 pipeline, roadmap section, stale content cleared; the screen recording stays an operator step), and 25 (Prometheus + Grafana: §7's six metrics in `services/gateway/metrics.py`, internal-only listeners 9100/9101, opt-in `monitoring` compose profile with a provisioned five-panel dashboard, `tests/integration/test_metrics.py`) are checked off. Remaining from Phase 4: item 24 (Terraform) when deployment is actually wanted, plus the demo screen recording (operator step).

**Phase 5 (items 31–38) is the active phase** — the adoptability work that came out of the 2026-07-12 adversarial self-review. A docs-only honesty pass has already landed (no behaviour change): `THREAT_MODEL.md` and the README now state that tool poisoning is **not** protected (descriptions are forwarded to the LLM verbatim — `tests/adversarial/test_tool_poisoning.py` asserts exactly that, and a server poisoned at first contact becomes its own approved baseline) and that replay is only **Partial**; the architecture diagram no longer claims multiple upstreams; `LICENSE` (MIT) and `SECURITY.md` were added; benchmark methodology moved into `ARCHITECTURE.md` §9 (which still held a stale TBD table); the metrics listener now defaults to loopback via `METRICS_HOST` (compose sets `0.0.0.0` so Prometheus still scrapes). **Items 31–35 are done** (see their `ROADMAP.md` done notes): sanitizer reject-not-rewrite — `sanitize()` is gone, injection patterns are `DENY_VALIDATION`, and `audit_log.write()` escapes NUL so adversarial arguments can't kill the audit write; single-source risk thresholds — the 40/70/90 bands are compared only in `risk_engine.threshold_outcome()`, which the interceptor now branches on; capped/expiring risk decay — `risk_decay_max` clamps at read time and the decay key carries a refreshed 30-day TTL; per-identity auth posture (34) — `Identity.auth_mode` is `bearer` (default; stock clients work, a volunteered nonce is still fully enforced) or `signed` (non-secret `key_id` in the policy + HMAC secret resolved from `signing_secret_env` at load; every message carries key id/nonce/timestamp/signature in `params._meta`, verified at the HTTP edge in `main.py` → 401, nonce dedup still `DENY_REPLAY` in the interceptor; `admin: true` with `signed` is rejected at load). The test suite's default fixtures are now stock `ClientSession` (bearer); `signed` is exercised via `SignedSession`/`signed_gateway` and `tests/adversarial/test_signed_auth.py`. Server registry (35) — `upstream_command`/`upstream_server_id` are gone: upstreams live in the policy YAML's `servers:` block (`server_id → stdio command`, versioned/rolled back with the policy; a grant naming an unregistered server fails load, `"*"` is reserved), clients connect to `/mcp/{server_id}` (one session = one upstream; unknown id → 404 after auth), and baselines, schema caches, risk freq/decay keys, approvals (`server_id` column, migration 0005, checked at redemption), metrics labels, and audit rows all carry the real per-session `server_id`. The explain API takes an optional `server` (sole-server default); multi-server isolation is proven by `tests/integration/test_multi_server.py`.

**Rule for this phase: never make a `THREAT_MODEL.md` row more optimistic than the code.** A row moves only when the item that earns it is actually built and its `verify:` check passes — that inversion (claims outrunning implementation) is the exact failure Phase 5 exists to correct, and re-introducing it is worse than the original bug. Build order, and it is deliberate: 31–33 landed first and fast (defects, not features), 34 (the centrepiece) and 35 (the invasive refactor — the server registry, now real) are in, so **item 36 is next** (description integrity), then 37 (step-up auth, promoted out of Beyond-v1; depends on 34's `signed` mode, which now exists), 38 (first-run state reset).

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
