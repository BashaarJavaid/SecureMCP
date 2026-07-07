"""Drift Detector (ARCHITECTURE.md §4.8): severity-classified schema-change detection.

The first successful tools/list for a (server_id, tool_name) is the trust anchor —
hash AND full schema stored as the approved baseline. Every later sighting is diffed
field-by-field and classified rather than "block on any change"; High/Critical drift
blocks tools/call (pipeline stage 5, DENY_DRIFT) until an admin re-approves.

Canonicalization is canonicaljson (pinned) — see the key-reordering smoke test.
"""

import hashlib
import logging
from enum import IntEnum
from typing import Any

import canonicaljson
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway.audit_log import AuditWriter
from services.gateway.db import ToolBaseline
from services.gateway.decision import EventType

logger = logging.getLogger(__name__)

# Sentinel stored in observed_hash while a baselined tool is absent from the live list,
# so its removal (DRIFT_MEDIUM) is logged once, not on every poll.
REMOVED_SENTINEL = "-" * 64


class DriftSeverity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def event(self) -> EventType:
        return EventType[f"DRIFT_{self.name}"]

    @property
    def blocks(self) -> bool:
        return self >= DriftSeverity.HIGH


def tool_hash(tool: dict[str, Any]) -> str:
    return hashlib.sha256(canonicaljson.encode_canonical_json(tool)).hexdigest()


def shape_hash(tool: dict[str, Any]) -> str:
    """Hash of everything except the name and cosmetic `title` fields — SDK servers
    derive titles from the function name (e.g. 'send_emailArguments'), which would
    otherwise defeat the rename heuristic's 'same-shaped tool' comparison."""

    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k != "title"}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value

    return tool_hash({k: strip(v) for k, v in tool.items() if k != "name"})


def classify(old: dict[str, Any], new: dict[str, Any]) -> DriftSeverity | None:
    """Severity of the change between two tool definitions (§4.8 table); None if
    identical. Multiple changes report the maximum severity."""
    severities: list[DriftSeverity] = []
    if old.get("description") != new.get("description"):
        severities.append(DriftSeverity.LOW)

    old_schema = old.get("inputSchema") or {}
    new_schema = new.get("inputSchema") or {}
    old_props: dict[str, Any] = old_schema.get("properties") or {}
    new_props: dict[str, Any] = new_schema.get("properties") or {}
    old_required = set(old_schema.get("required") or [])
    new_required = set(new_schema.get("required") or [])

    for prop in new_props.keys() - old_props.keys():
        # A new *required* parameter changes what a valid call even looks like.
        severities.append(
            DriftSeverity.CRITICAL if prop in new_required else DriftSeverity.MEDIUM
        )
    if old_props.keys() - new_props.keys():
        severities.append(DriftSeverity.HIGH)
    for prop in old_props.keys() & new_props.keys():
        if old_props[prop].get("type") != new_props[prop].get("type"):
            severities.append(DriftSeverity.CRITICAL)
        elif old_props[prop] != new_props[prop]:
            severities.append(DriftSeverity.LOW)
    if (old_required ^ new_required) & (old_props.keys() & new_props.keys()):
        severities.append(DriftSeverity.CRITICAL)  # required status flipped

    if severities:
        return max(severities)
    if tool_hash(old) != tool_hash(new):
        # Changed in a way the table doesn't name — unclassifiable drift fails closed.
        return DriftSeverity.HIGH
    return None


class DriftDetector:
    def __init__(
        self, sessionmaker: async_sessionmaker[AsyncSession], writer: AuditWriter
    ) -> None:
        self._sessions = sessionmaker
        self._writer = writer

    async def check(
        self, server_id: str, tools: list[dict[str, Any]], identity_id: str
    ) -> None:
        """Run drift detection over a freshly observed tools list. Raises on storage
        failure — callers withhold the list (fail closed, §5)."""
        live = {str(tool.get("name")): tool for tool in tools}
        async with self._sessions() as session:
            result = await session.execute(
                select(ToolBaseline).where(ToolBaseline.server_id == server_id)
            )
            baselines = {row.tool_name: row for row in result.scalars()}
            renamed_sources: set[str] = set()

            for name, tool in live.items():
                row = baselines.get(name)
                if row is None:
                    await self._first_sighting(
                        session,
                        server_id,
                        name,
                        tool,
                        live,
                        baselines,
                        renamed_sources,
                        identity_id,
                    )
                    continue
                live_hash = tool_hash(tool)
                if live_hash == row.approved_hash:
                    if row.observed_hash is not None:  # reverted to the approved shape
                        row.observed_hash = None
                        row.observed_schema = None
                        row.blocked = False
                    continue
                if live_hash == row.observed_hash:
                    continue  # this exact drift is already logged
                severity = classify(row.approved_schema, tool) or DriftSeverity.HIGH
                await self._writer.write(
                    severity.event,
                    identity_id,
                    tool_name=name,
                    payload_extra={
                        "severity": severity.name.lower(),
                        "approved_hash": row.approved_hash,
                        "observed_hash": live_hash,
                        "blocked": severity.blocks,
                    },
                )
                row.observed_schema = tool
                row.observed_hash = live_hash
                if severity.blocks:
                    row.blocked = True

            for name, row in baselines.items():
                if name in live or name in renamed_sources:
                    continue
                if row.observed_hash != REMOVED_SENTINEL:
                    await self._writer.write(
                        EventType.DRIFT_MEDIUM,
                        identity_id,
                        tool_name=name,
                        payload_extra={"severity": "medium", "removed": True},
                    )
                    row.observed_hash = REMOVED_SENTINEL
                    row.observed_schema = None
            await session.commit()

    async def _first_sighting(
        self,
        session: AsyncSession,
        server_id: str,
        name: str,
        tool: dict[str, Any],
        live: dict[str, dict[str, Any]],
        baselines: dict[str, ToolBaseline],
        renamed_sources: set[str],
        identity_id: str,
    ) -> None:
        live_hash = tool_hash(tool)
        source = next(
            (
                row
                for row in baselines.values()
                if row.tool_name not in live
                and shape_hash(row.approved_schema) == shape_hash(tool)
            ),
            None,
        )
        if source is None:
            # First successful sighting is the trust anchor (§4.8).
            session.add(
                ToolBaseline(
                    server_id=server_id,
                    tool_name=name,
                    approved_schema=tool,
                    approved_hash=live_hash,
                )
            )
            return
        renamed_sources.add(source.tool_name)
        await self._writer.write(
            EventType.DRIFT_CRITICAL,
            identity_id,
            tool_name=name,
            payload_extra={
                "severity": "critical",
                "renamed_from": source.tool_name,
                "observed_hash": live_hash,
                "blocked": True,
            },
        )
        # Treated as a new, unapproved tool: baselined but blocked until approval.
        session.add(
            ToolBaseline(
                server_id=server_id,
                tool_name=name,
                approved_schema=tool,
                approved_hash=live_hash,
                blocked=True,
                observed_schema=tool,
                observed_hash=live_hash,
            )
        )

    async def is_blocked(self, server_id: str, tool_name: str) -> bool:
        async with self._sessions() as session:
            result = await session.execute(
                select(ToolBaseline.blocked).where(
                    ToolBaseline.server_id == server_id,
                    ToolBaseline.tool_name == tool_name,
                )
            )
            return bool(result.scalar_one_or_none())

    async def approve(self, server_id: str, tool_name: str, approved_by: str) -> int:
        """Promote the observed schema to the accepted baseline (admin action).
        Returns the APPROVED audit row's seq. Raises LookupError if there is no
        pending drift to approve."""
        async with self._sessions() as session:
            result = await session.execute(
                select(ToolBaseline).where(
                    ToolBaseline.server_id == server_id,
                    ToolBaseline.tool_name == tool_name,
                )
            )
            row = result.scalar_one_or_none()
            if row is None or row.observed_schema is None:
                raise LookupError("no pending drift for this tool")
            old_hash = row.approved_hash
            row.approved_schema = row.observed_schema
            row.approved_hash = row.observed_hash or tool_hash(row.observed_schema)
            row.observed_schema = None
            row.observed_hash = None
            row.blocked = False
            seq = await self._writer.write(
                EventType.APPROVED,
                approved_by,
                tool_name=tool_name,
                payload_extra={"old_hash": old_hash, "new_hash": row.approved_hash},
            )
            await session.commit()
            return seq
