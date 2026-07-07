# ADR-004 — No OPA/Rego/Cedar for v1

**Status:** Accepted (revisit if policy surface outgrows the embedded evaluator)

**Decision:** Use a small, hand-rolled, constrained boolean-expression evaluator for ABAC conditions instead of adopting OPA/Rego or Cedar.

**Reasoning, in order of weight:**

1. **Evaluation-path auditability (primary reason).** OPA's model is built around data queries over a unified input document. Making it work here means pushing request-scoped context (identity, tool, arguments, risk score) into that input document and writing Rego rules that reference it — achievable, but it's an extra layer of indirection between "a request came in" and "here's why it was allowed or denied." The evaluation happens inside a separate query language against a document tree, rather than as a Python function that can be stepped through directly in a debugger or read top-to-bottom in a code review. For a security tool where "what happens here, exactly" needs to be immediately greppable in the codebase, the embedded evaluator keeps that path transparent in a way OPA's model doesn't naturally give you.
2. **Scale (secondary reason).** A full policy-as-code engine is justified once policies are authored by non-engineers, shared across many independent services, or need formal verification. None of those are true yet.

The embedded evaluator gets real ABAC expressiveness (see `ARCHITECTURE.md`, Policy Engine section) at a fraction of the integration cost, with an explicit constraint: no loops, no recursion, no arbitrary code execution, no user-defined functions — fully deterministic, side-effect-free evaluation only.

**Revisit when:** the policy surface grows past what the embedded evaluator can express cleanly, or policies need to be authored/reviewed by people outside the engineering team.

**Alternatives considered:** OPA/Rego, Cedar, a general-purpose embedded scripting language (e.g. Lua) — rejected for the same reason OPA is not primary: it would trade determinism and auditability for expressiveness this project doesn't need yet.
