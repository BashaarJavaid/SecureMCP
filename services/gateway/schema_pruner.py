"""Strips unauthorized tools from tools/list responses (ARCHITECTURE.md §4.8).

Denied tools are removed entirely — not marked, actually absent — so the LLM client's
planning step never sees them as an option. This is a planning-surface control, not the
security boundary: tools/call is independently authorized per §4.1.
"""

from typing import Any

from services.gateway.policy_engine import PolicyEngine


def prune(
    tools: list[dict[str, Any]],
    identity_id: str | None,
    server_id: str,
    engine: PolicyEngine,
) -> list[dict[str, Any]]:
    return [
        tool for tool in tools if engine.is_allowed(identity_id, server_id, str(tool.get("name")))
    ]
