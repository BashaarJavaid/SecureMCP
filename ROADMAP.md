# Roadmap

The build order for SecurMCP, sequenced across four phases so there's always something demoable at the end of each phase rather than a long stretch with nothing to show. Kept as a living checklist — update this file as items complete rather than letting it drift from reality.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for what each item actually means and [`docs/adr/`](./docs/adr/) for the reasoning behind deferred items (Kubernetes, Terraform-first, OPA, etc.).

---

## Build Order — Four Phases

**Phase 1 — Core gateway (get something real working end-to-end)**
1. ~~Repo scaffold, Docker Compose skeleton, Postgres schema + Alembic migration for `audit_log` and `policies`~~ — **done**: the "policies" table is `policy_versions` per `ARCHITECTURE.md` §4.8 (YAML files remain the policy content store); `audit_log.signature` is nullable until ECDSA signing lands in Phase 2, item 11.
2. ~~Session Manager + JSON-RPC Interceptor wired to a single hardcoded upstream server, full passthrough, no policy yet — includes the `lifespan`/SIGTERM subprocess-cleanup handler (with per-subprocess `ProcessLookupError`/`OSError` handling) and the Redis-TTL session idle timeout from day one, since both are cheap to add while there's only one subprocess type to manage and easy to forget once more moving pieces exist.~~ — **done**: client-facing transport is Streamable HTTP rather than SSE (the MCP spec deprecated standalone SSE in 2025-03; README tech-stack table updated); upstream is a per-session stdio subprocess set via `UPSTREAM_COMMAND`.
3. ~~Policy Engine (RBAC only for now) + Schema Pruner — identity-scoped `tools/list`~~ — **done**: RBAC is also enforced on every `tools/call` per §4.1's point-of-action principle (pruning is not the boundary); identity comes from a temporary unverified `X-SecurMCP-Identity` header until item 4 replaces it with key auth.
4. Auth layer (API key → identity, hash-and-lookup, no HMAC/JWT).
5. Audit log writer with hash chaining (Redis-cached `latest_audit_hash`, updated atomically via Lua script/`WATCH`-`MULTI`, to avoid a `SELECT MAX(seq)` on every write; signing comes in Phase 2) + basic verifier.
6. Parameter Validator on `tools/call`.
7. **Cache invalidation (schema TTL, ETags, policy hot-reload)** — moved up from Phase 2: real MCP clients (Claude Desktop, Cursor) poll or re-fetch `tools/list` more than a naive baseline assumes, and caching bugs discovered late are hard to distinguish from "the core proxy is broken." Getting this right before Phase 2 hardening begins means Phase 2 testing debugs one thing at a time, not two at once.
8. `sample_target/overscoped_server.py` + first recorded demo (schema pruning only).

**Phase 2 — Drift detection, hardening, and proof it's fast enough**
9. Drift Detector with severity classification (Low/Medium/High/Critical) and `canonicaljson` (pinned version) for RFC 8785 canonicalization, plus the key-reordering smoke test — this is where "block on any change" becomes "block on the changes that matter."
10. Replay Guard (nonce + timestamp + Redis dedup).
11. ECDSA signing added to the audit log; verifier daemon checks signatures and chain math incrementally from a `last_verified_seq` checkpoint, not a full scan from `seq=1`.
12. Performance benchmark suite + first published latency numbers in the README, including the `tools/list` payload-size reduction metric.
13. Structured logging (structlog) end to end.
14. `sample_target/rogue_server.py` with a real `POST /_admin/apply_mutation` endpoint (no timer) + updated demo recording (schema pruning + drift blocking, admin mutation visible on-screen).
15. CI/CD pipeline (lint, typecheck, test, coverage gate, benchmark-on-merge, build).

**Phase 3 — Risk-aware, expressive policy, and the standout features**
16. Risk Engine v1 (factor-list scoring: tool sensitivity, blast radius, business hours, call frequency, drift-in-review) plus the risk decay feedback loop (per-identity/tool calibration counter on approval, behavioral factors only, never the static sensitivity tier).
17. ABAC conditions layered onto the policy engine (embedded expression evaluator; explicitly no loops/recursion/arbitrary code; missing-attribute references evaluate the whole condition as not-satisfied, never injected as a raw boolean into a `not`).
18. Richer risk telemetry: prior-denial-rate, drift-history, and an auth-failure counter added to the Auth Layer.
19. Policy versioning (version stamping, revision snapshots, rollback) plus the `--diff-policy` terminal mode and `--html` side-by-side diff flag (`difflib.HtmlDiff`, no new dependency).
20. **Decision Explanation** (`GET /admin/decisions/{id}`, `POST /admin/decisions/explain`) — build this right after the Risk Engine and Policy Engine exist, since it's mostly just exposing data they already compute.
21. **Policy Simulation Mode** — build alongside Decision Explanation; both reuse the same underlying decision/audit data.
22. Component, deployment, and data-flow diagrams; multi-server trust domain discussion written up in `ARCHITECTURE.md` (documented, not built).
23. Expanded adversarial test suite covering risk scoring, ABAC conditions (including missing-attribute cases, specifically inside `not(...)`), decision explanation accuracy, simulation accuracy, the approval-mismatch (TOCTOU) path, and `test_concurrent_audit_writes_do_not_collide`.

**Phase 4 — Production infra, admin surface, and roadmap items**
24. Terraform (VPC, RDS, ElastiCache, ECS Fargate, ALB, Secrets Manager) — infra work starts here, not before.
25. Prometheus + Grafana dashboard.
26. ADRs written up in `docs/adr/`, including the "Why Not Envoy/OPA/Kong/NGINX/Sidecars/client-SDK-middleware" page, with the OPA entry leading with auditability rather than scale.
27. Scalability discussion written up (Postgres write amplification, Redis at scale, stateless replica scaling) — design notes, not load-tested.
28. README finalized: architecture diagrams, threat model table, real (not estimated) benchmark numbers, demo GIF/recording of the full narrative, explicit roadmap section.
29. Documented-only roadmap for anything not built: OAuth 2.1 On-Behalf-Of token exchange, OPA/Cedar integration if policy complexity outgrows the embedded evaluator, a real step-up auth challenge flow, an admin UI, two-person policy activation approval for the insider-admin threat gap, and multi-server trust scoring.
30. ~~Deferred: split this single spec into separate files~~ — **done as of this revision**: split into `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `docs/adr/*.md`, and `ROADMAP.md`.

