# ADR-003 — Redis for session/replay/rate-limit state, not Postgres

**Status:** Accepted

**Decision:** Use Redis for replay-nonce tracking, rate-limit counters, session idle-timeout TTLs, the cached `latest_audit_hash` chain pointer, and risk-decay calibration counters.

**Reasoning:** This state is high-churn and short-TTL, and non-durable-by-design in a way that's acceptable — a lost nonce cache just means a slightly wider replay window until it repopulates, not a security failure or data loss. This is a good fit for Redis's operational model, and keeps write pressure off the durability-critical audit log in Postgres, which has a stricter guarantee to uphold (see `THREAT_MODEL.md` and the Failure Modes section of `ARCHITECTURE.md`).

**Alternatives considered:** Keeping this state in Postgres alongside the audit log; in-process memory (rejected — breaks statelessness required for multi-replica deployment, see `ARCHITECTURE.md` §4.5).
