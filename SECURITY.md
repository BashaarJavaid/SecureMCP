# Security Policy

## Status

SecurMCP is pre-1.0 and maintained by a single author. It has not been through an
external security audit. Treat it as a reference implementation and a starting point,
not as a hardened product you drop in front of production traffic without reading it
first.

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

Use GitHub's [private vulnerability reporting](https://github.com/BashaarJavaid/SecureMCP/security/advisories/new),
or email **aarish@issm.ai**.

Please include the affected component, what an attacker gains, and a reproduction if
you have one. I'll acknowledge within 7 days and aim to have a fix or a documented
mitigation within 30 days for anything that breaks a guarantee this project actually
claims to make.

## What counts as a vulnerability here

Scope is defined by [`THREAT_MODEL.md`](./THREAT_MODEL.md), which is deliberately
explicit about what is *not* protected. A report that a documented non-guarantee is
not, in fact, guaranteed is not a vulnerability — but a report that the threat model
itself **overstates** what the code does absolutely is, and is exactly the kind of
report I want.

Things that *are* in scope:

- A policy decision that can be bypassed (RBAC, ABAC, drift block, risk band, replay).
- A way to write to, forge, or silently break the audit chain without detection by
  `scripts/verify_audit_chain.py`.
- Privilege escalation across identities, or an admin endpoint reachable without an
  admin-resolving key.
- A `Decision` the gateway reports that does not match what it actually enforced.

Things that are **out of scope**, per the threat model:

- Anything requiring a compromised gateway host (the signing key is then already lost).
- Prompt injection reaching the LLM through tool *results* — a client/agent-framework
  concern, not a protocol-layer one.
- Insider abuse by a legitimate admin credential (attributable after the fact by
  design, not prevented).
