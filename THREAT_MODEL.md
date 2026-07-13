# Threat Model

What SecurMCP protects against, what it explicitly does not, and the assumptions the whole model depends on. See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for how each protection is implemented, and [`docs/adr/`](./docs/adr/) for why certain alternative approaches weren't used.

---

An explicit scope boundary is worth more to a technical reviewer than an implied claim of total coverage.

| Threat | Protected? | Notes |
|---|---|---|
| Tool Poisoning (adversarial text in tool descriptions) | **No** | The gateway forwards descriptions to the client **verbatim** — `tests/adversarial/test_tool_poisoning.py` asserts exactly that. The attack targets the LLM, not the gateway, so "the gateway never executes descriptions" is not a mitigation. A server that is poisoned *at first contact* has that description recorded as its approved baseline (`drift_detector.py`, first sighting = trust anchor); a description changed *later* classifies as `DRIFT_LOW`, which is logged but **does not block**. Schema pruning reduces how many identities are exposed to a given description, but does not defend against the ones that still see it. Detecting adversarial instruction text requires content analysis the gateway does not perform — tracked as Phase 5 |
| Rogue / rug-pulling MCP server (schema/shape mutation) | Yes | Drift Detector classifies and blocks on schema mutation per severity tier; High/Critical blocks `tools/call` until admin re-approval. Note this covers a tool's *shape* changing, not its *description* text — see the poisoning row above |
| Unauthorized tool access by a known identity | Yes | RBAC + ABAC policy resolution |
| Overly broad or contextually risky calls by an authorized identity | Yes | Risk Engine — this was the gap in v1 |
| Replay of a captured request | **Yes for `signed` identities / Partial for `bearer`** | For a `signed` identity the captured request contains no credential: the policy holds a non-secret key id, the HMAC secret lives only in the gateway's environment, and the signature covers the canonical `{nonce, timestamp, method, tool, arguments}`. A byte-identical replay dies on nonce dedup (`DENY_REPLAY`); a fresh nonce cannot be signed (401 at the edge) — `tests/adversarial/test_signed_auth.py` proves both. For `bearer` identities this stays Partial: a volunteered nonce is fully enforced and catches accidental resubmission, but the API key travels in the same captured request, so a deliberate adversary can mint fresh nonces. Residual for `signed`: GET/DELETE carry no body to sign, so a captured session id can read that session's response stream (not initiate calls) until teardown |
| Prompt injection reaching the LLM through tool *results* (not descriptions) | Partial | Out of scope for a protocol-layer gateway — this needs to be handled by the client/agent framework itself; the gateway can log and rate-limit but cannot semantically evaluate result content |
| Stolen API key | Partial | Rate limiting and anomaly detection (via the Risk Engine's historical-behavior signal) reduce blast radius; the gateway cannot distinguish a stolen key from its legitimate holder by identity alone. `signed` identities materially improve this: no credential appears in any request, so the key cannot be stolen from traffic at all — stealing the secret requires compromising the client's or gateway's environment, which is the host-hardening threat class below |
| Compromised host OS running the gateway itself | No | If the host is compromised, the attacker has the signing key and Redis/Postgres access; this is a deployment/infra hardening problem (secrets management, host patching), not something the application layer can defend against |
| Malicious local user with shell access to the gateway container | Partial | Non-root container user and dropped capabilities limit damage but don't eliminate it |
| Insider admin abusing legitimate admin-API access (policy edits, drift approvals) | No | The audit log makes such actions attributable and tamper-evident after the fact, but does not *prevent* an admin with legitimate credentials from making a bad change — that requires a separate approval workflow (e.g. two-person policy activation), which is out of scope for this project. **Phase 4 includes a documented design for two-person policy activation** (an approval workflow required before a policy change takes effect), which closes this gap as an administrative overlay rather than a core gateway logic change — the gap is recognized and has a planned path to closing it, even though it isn't built in v1. |

**Assumptions** — every threat model implicitly relies on some things being true; stating them explicitly is what separates a scoped security document from an implied claim of total coverage:

- TLS terminates correctly at the load balancer/ingress; the gateway does not itself defend against a broken or misconfigured TLS termination point.
- The gateway host is not already compromised at deployment time (a compromised host invalidates the signing-key and credential guarantees entirely — see the threat table above).
- The upstream MCP server's *identity* (which server this is) is authenticated at the transport layer (e.g. mTLS or a pinned endpoint) — SecurMCP defends against a server's *behavior* changing (drift), not against connecting to an impersonated server in the first place.
- Redis is a trusted component within the deployment's network boundary — it is not itself hardened against a malicious actor with direct network access to it.
- Postgres is trusted to execute the queries it's given faithfully — SecurMCP defends against *external* tampering with stored rows (via the hash chain and signatures), not against a malicious database engine or a superuser with direct `UPDATE` access bypassing the application entirely (covered under "insider admin," above).
- The `mcp` SDK's own JSON-RPC framing is trusted to be spec-compliant; SecurMCP does not re-implement wire-level protocol conformance checking beyond what it needs for interception.
- **Multiple upstreams are registered per policy (`servers:` block, item 35).** Each entry is a `server_id → stdio command`; clients connect to `/mcp/<server_id>` and one session is bound to one upstream at connect time. RBAC grants, drift baselines, schema caches, risk frequency/decay counters, and approvals are all keyed on the real `server_id` — an identically-named tool on two servers is two different tools (`tests/integration/test_multi_server.py`). Registration is still the trust decision: every registered server gets the same pipeline and thresholds; per-server trust tiers remain a discussion (`ARCHITECTURE.md` §4.7), not a capability.

---


