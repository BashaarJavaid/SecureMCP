# ADR-006 — Why Not Envoy / NGINX / Kong / OPA / Sidecars / Client-SDK Middleware

**Status:** Accepted

**Decision:** Build a purpose-built application-layer gateway in Python rather than adopting an existing proxy platform, service mesh pattern, or client-side middleware approach.

**Reasoning per alternative:**

- **Why not Envoy or NGINX as the proxy layer?** Both are excellent generic L4/L7 proxies, but neither has any native understanding of JSON-RPC 2.0 method semantics — they'd need a custom filter/module written in C++/Lua/WASM to even parse `tools/list` vs `tools/call`, at which point the same application-layer logic has effectively been rebuilt anyway, just inside a heavier, less iterable host process. A purpose-built application-layer gateway in Python is faster to build and easier to reason about for this specific protocol.
- **Why not Kong (or another API gateway platform)?** Same root issue — Kong's plugin model is built around HTTP/REST semantics (paths, methods, headers), not stateful JSON-RPC sessions with a persistent upstream subprocess connection per client. Bending Kong's model to fit MCP's session lifecycle would fight the platform more than it would save effort.
- **Why not OPA/Rego or Cedar for policy?** See `ADR-004-no-opa-for-v1.md` — the primary reason is evaluation-path auditability, not scale.
- **Why not a sidecar pattern (one gateway instance per upstream server, à la service mesh)?** Sidecars make sense when per-service network policy needs to be enforced uniformly across a large, heterogeneous fleet. For this project's threat model — a single client-facing choke point auditing all MCP traffic for a given org — a centralized gateway is simpler to operate and gives a single place to enforce identity-scoped tool visibility across *all* upstream servers at once, which a sidecar-per-server topology would need to coordinate separately anyway.
- **Why not implement policy checks directly as middleware inside the MCP client SDK, instead of a separate proxy process?** This is the most natural objection to a gateway pattern existing at all. Client-SDK middleware means every client application re-implements (and can drift out of sync on) the same policy logic, there's no single place to update policy when it changes, and there's no single point to audit traffic across every client uniformly — a compromised or outdated client could simply skip its own middleware. Centralizing enforcement at a separate proxy layer means one place to update policy, one place to audit, and one place to observe, independent of how many different clients or client versions exist.

**Alternatives considered:** each of the above, individually, as the primary architecture instead of a purpose-built gateway.
