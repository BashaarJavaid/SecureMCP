# SecurMCP

**A zero-trust, risk-aware gateway proxy for the Model Context Protocol (MCP)**

SecurMCP sits as a transparent proxy between MCP clients and real MCP servers, enforcing identity-scoped tool visibility, detecting schema drift ("rug pull" attacks), scoring the risk of individual tool calls, and producing a tamper-evident, signed audit trail — without requiring changes to either the client or the upstream servers.

## Documentation

This README is intentionally short. Deeper detail lives in dedicated files so an AI coding agent (or a human) only loads what's relevant to the task at hand, rather than the entire design on every session:

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — core architecture, decision pipeline, all components, failure modes, security hardening, observability, cache invalidation, performance benchmarks, scalability, testing strategy, CI/CD, deployment
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — what's protected against, what isn't, and the assumptions the whole model rests on
- [`docs/adr/`](./docs/adr/) — one file per consequential architecture decision, including why several common alternatives (Envoy, OPA, Kong, NGINX, sidecars, client-SDK middleware) weren't chosen for v1
- [`ROADMAP.md`](./ROADMAP.md) — the four-phase build order, kept as a living checklist

---

## Problem Statement

MCP defines a JSON-RPC 2.0 transport for connecting LLM clients (Claude Desktop, Cursor, custom agents) to tool servers, but the spec deliberately leaves authorization, auditability, and integrity verification out of scope — it assumes the deploying org handles that layer itself. In practice almost nobody does. This creates three concrete, exploitable gaps:

1. **No identity-scoped tool visibility.** Any client that can reach a server sees the server's full `tools/list` response. There's no native concept of "this session/user should only see a subset of tools."
2. **Tool Poisoning.** A malicious or compromised server can embed adversarial instructions inside a tool's `description` field — text the LLM reads as trusted context when deciding how to call the tool.
3. **Rug Pull Attacks.** A server can change a tool's schema, description, or behavior *after* a human has already approved it in a prior session, with no mechanism to detect the drift.

SecurMCP sits as a transparent proxy between MCP clients and real MCP servers, intercepting the JSON-RPC 2.0 conversation to enforce policy, detect drift, and produce a tamper-evident audit trail — without requiring changes to either the client or the upstream servers.

---


---

## Tech Stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.12 | Matches your existing stack (ProdRescue), avoids context-switching cost of Go |
| Web/proxy framework | FastAPI + Starlette | Async-native, plays well with SSE and WebSocket transports |
| MCP protocol handling | `mcp` official Python SDK | Don't hand-roll JSON-RPC 2.0 framing — use the reference client/server primitives and intercept at the session layer |
| Database | PostgreSQL 16 | Audit log, policy store, schema cache — relational integrity matters for a hash chain |
| ORM / migrations | SQLAlchemy 2.0 (async) + Alembic | Standard, typed, migration-safe |
| Caching / session state | Redis 7 | In-flight session state, rate-limit counters, short-TTL schema cache |
| Policy definition | YAML + Pydantic models | Human-readable, git-diffable, validated at load time |
| Auth (v1) | Static API-key → identity mapping, high-entropy secret compared by hash | No JWT or HMAC signing needed for v1 — a random 32-byte key stored as its SHA-256 hash is sufficient; see the Auth Layer component description for the exact scheme |
| Auth (roadmap) | OAuth 2.1 + On-Behalf-Of token exchange | Documented as Phase 4 roadmap, not blocking MVP |
| Policy expressions | Small hand-rolled boolean expression evaluator over Pydantic-typed attributes (identity, tool, context, risk_score) | Gives ABAC-style conditions without pulling in a full policy-as-code engine |
| Policy language (roadmap) | OPA/Rego or Cedar | Documented as Phase 4 roadmap only — not built; embedded evaluator above is sufficient at this scale |
| Risk Engine | Rule-based scoring function (Phase 1: weighted heuristics; Phase 3: optionally a small learned model) | Answers "should this run right now," not just "is this identity allowed" |
| Transport | Server-Sent Events (SSE) + stdio subprocess passthrough | Covers both remote and local MCP server patterns — **but see the stateless-replica caveat in `ARCHITECTURE.md` §4.5**: stdio ties an upstream process to the specific gateway replica that spawned it, which constrains multi-replica deployment to SSE-connected servers only |
| Replay protection | Nonce + timestamp window, deduped in Redis | Standard defense for a system fronting side-effecting calls |
| Containerization | Docker + Docker Compose (local + MVP prod), multi-stage build | Isolated subprocess execution per session |
| Orchestration (post-MVP) | AWS ECS Fargate; Kubernetes explicitly deferred | Compose + ECS is enough to prove the system works; K8s adds ops overhead with no proportional signal for v1 |
| IaC (post-MVP) | Terraform | Added after the gateway itself works — VPC, RDS, ElastiCache, ECS, ALB, Secrets Manager |
| Observability (post-MVP) | Prometheus + Grafana, structured JSON logs (structlog) | structlog ships in MVP; Prometheus/Grafana added once the gateway logic is stable, not before |
| Testing | pytest, pytest-asyncio, hypothesis (for schema fuzzing), httpx test client | Unit + integration + adversarial suites |
| CI/CD | GitHub Actions | Lint (ruff), type-check (mypy strict), test, coverage gate, build, push to ECR/GHCR |
| Secrets | AWS Secrets Manager / HashiCorp Vault (local: `.env` + docker secrets) | Never plaintext in repo or logs |
| Cryptography | Python `hashlib` (SHA-256) for the chain, `cryptography` (ECDSA, P-256) for chain-segment signing | Hash-chain integrity plus tamper-proofing against a full chain regeneration |

---


---

## Repository Structure

```
securmcp/
├── .github/workflows/
│   ├── ci.yml                 # lint, typecheck, test, coverage gate
│   └── release.yml            # build + push container image on tag
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── policy-schema.md
│   └── img/ (mermaid renders, dashboard screenshots)
├── infra/
│   ├── terraform/
│   │   ├── modules/ (vpc, rds, redis, ecs, secrets)
│   │   └── envs/ (dev, prod)
│   └── k8s/ (if EKS path: deployment.yaml, service.yaml, hpa.yaml)
├── policies/
│   ├── example-policy.yaml
│   └── revisions/                   # append-only snapshots, one file per policy version
├── services/
│   ├── gateway/
│   │   ├── main.py                # FastAPI app entrypoint
│   │   ├── session_manager.py     # per-client session lifecycle
│   │   ├── jsonrpc_interceptor.py # method dispatch: initialize / tools_list / tools_call
│   │   ├── policy_engine.py       # loads YAML, evaluates identity → allowed tools, ABAC conditions, versioning
│   │   ├── risk_engine.py         # scores each tools/call, returns allow/challenge/human_approval/deny
│   │   ├── schema_pruner.py       # strips unauthorized tools from tools/list response
│   │   ├── drift_detector.py      # hash-compares live schema vs cached baseline, classifies severity
│   │   ├── param_validator.py     # JSON Schema validation + sanitization on tools/call args
│   │   ├── replay_guard.py        # nonce + timestamp window dedup via Redis
│   │   ├── auth.py                # API key verification, identity resolution
│   │   ├── audit_log.py           # hash-chain writer + ECDSA signer + verifier
│   │   ├── policy_simulator.py    # replays historical audit events against a candidate policy
│   │   └── upstream_client.py     # manages connections to real MCP servers (stdio/SSE)
│   └── audit_verifier/
│       └── daemon.py               # standalone process, periodically re-walks the hash chain
├── sample_target/                  # deliberately vulnerable demo MCP server
│   ├── overscoped_server.py         # exposes tools a low-priv identity shouldn't see
│   └── rogue_server.py              # exposes POST /_admin/apply_mutation to mutate its own schema on demand (not a timer — see the demo script below)
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── adversarial/                 # rug-pull simulation, poisoned-description injection, replay attacks
│   └── benchmarks/                  # latency/throughput measurements, checked into CI as a report artifact
├── docs/adr/
│   ├── ADR-001-fastapi.md
│   ├── ADR-002-postgres-vs-dynamodb.md
│   ├── ADR-003-redis.md
│   └── ADR-004-no-opa-for-v1.md
├── scripts/
│   ├── seed_policies.py
│   └── verify_audit_chain.py
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── alembic/
├── .env.example
├── LICENSE (MIT)
└── README.md
```

---


---

## Demo Target (`sample_target/`)

Two tiny MCP servers built specifically to make the gateway's value visible in a 30-second recording:

- `overscoped_server.py`: exposes tools like `read_file`, `delete_repo`, `merge_pr` with no internal authz — demonstrates schema pruning when a low-privilege identity connects.
- `rogue_server.py`: starts with a benign `send_email(to, subject, body)` tool and exposes a real admin endpoint, **`POST /_admin/apply_mutation`**, which swaps in a version of the tool with an added `bcc` parameter and a modified description. There is no timer and no invisible trigger — the mutation only happens when that endpoint is actually called, deliberately, so the demo recording can show a terminal window where an operator runs `curl -X POST http://localhost:.../_admin/apply_mutation` and the schema visibly changes as a real operation, not something that "just happens" off-screen. A demo where the adversarial behavior is invisible reads as scripted magic rather than a real system reacting to a real event.

Recording script — a single continuous story rather than a feature checklist:

1. Connect as a low-privilege identity ("Developer") — only the safe tools show up in `tools/list`, the sensitive ones are simply absent.
2. In a visible terminal window, an "admin" runs `curl -X POST .../_admin/apply_mutation` against the rogue server — the mutation is an on-screen, operator-triggered action, not a hidden timer.
3. The Developer's next call is intercepted: drift is detected and classified, and the Risk Engine independently flags the call as high-risk — execution is blocked before it reaches the tool.
4. An admin reviews the diff via `GET /admin/decisions/{id}` (Decision Explanation), approves the new schema.
5. The tool becomes available again; the same call now succeeds.
6. The Developer's client replays the exact same request a second time — the Replay Guard blocks it as a duplicate.
7. To close: run Policy Simulation against next week's draft policy over the last hour of demo traffic, and show it would have denied three of the requests just made — a live, on-camera preview of a policy change before it ships.

This single flow demonstrates schema pruning, drift classification, risk scoring, human approval, decision explanation, replay protection, and policy simulation in about 90 seconds, without feeling like a feature tour.

---


