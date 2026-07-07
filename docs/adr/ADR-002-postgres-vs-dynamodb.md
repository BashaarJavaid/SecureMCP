# ADR-002 — PostgreSQL over DynamoDB

**Status:** Accepted

**Decision:** Use PostgreSQL for the audit log, policy store, and policy-version history.

**Reasoning:** The audit log's hash chain and policy-versioning queries need relational integrity and range queries (`WHERE timestamp BETWEEN ...`, `JOIN` across `policy_versions`) that are awkward in a key-value/document store. DynamoDB's core strength — massive horizontal write scale — isn't the actual bottleneck for this project; the hash-chain dependency between sequential writes is (see `ARCHITECTURE.md`, Audit Log section), and that's a concurrency/ordering problem, not a partitioning problem DynamoDB is well-suited to solve.

**Alternatives considered:** DynamoDB, MongoDB.
