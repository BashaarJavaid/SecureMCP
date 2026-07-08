"""Risk Engine v1 (ARCHITECTURE.md §4.8, item 16): rule-based factor-list scoring.

Each signal is a small pure function over a pre-gathered RiskContext, returning a
weighted contribution and a human-readable reason; the engine sums a fixed list of
them (a common-interface function list, deliberately not a plugin system) into a
0-100 score. Deterministic and rule-based by design — no ML, ever (§4.8).

Risk decay (§4.8): a per-(identity, tool) Redis counter, incremented on each admin
approval, discounts the *behavioral* subtotal (call frequency, drift-in-review) —
never the static tool-sensitivity tier — floored at 0, so rubber-stamp approvals
can't desensitize the engine to an inherently dangerous tool.

Scoring exceptions propagate to the caller, which must treat them as score 100 and
deny (§5 fail-closed).
"""

import fnmatch
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis

from services.gateway.config import settings
from services.gateway.decision import RiskFactor
from services.gateway.drift_detector import DriftDetector
from services.gateway.policy_engine import RiskPolicy

# Weighted contributions. Anchored to §4.3's worked example (protected repo 30,
# business hours 25); the tier ladder is chosen so the §11 canary scenario
# (high-sensitivity tool + protected repo + off-hours = 85) lands in 70-90.
TIER_CONTRIBUTION = {"low": 10, "medium": 20, "high": 30, "critical": 45}
PROTECTED_CONTRIBUTION = 30
OFF_HOURS_CONTRIBUTION = 25
FREQUENCY_CONTRIBUTION = 20
DRIFT_IN_REVIEW_CONTRIBUTION = 15

# Factors risk decay may discount (§4.8 boundary: behavioral only, never the tier).
BEHAVIORAL_FACTORS = frozenset({"call_frequency", "drift_in_review"})


@dataclass
class RiskContext:
    identity_id: str
    tool_name: str
    arguments: dict[str, Any]
    policy: RiskPolicy
    now: datetime  # timezone-aware UTC
    call_count: int  # calls for this identity+tool in the rolling window, incl. this one
    drift_in_review: bool


def _string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


def _tool_sensitivity(ctx: RiskContext) -> RiskFactor | None:
    tier = ctx.policy.tool_sensitivity.get(ctx.tool_name)
    if tier is None:
        return None
    return RiskFactor(
        factor="tool_sensitivity",
        contribution=TIER_CONTRIBUTION[tier],
        reason=f"{ctx.tool_name!r} is policy-tiered {tier}",
    )


def _blast_radius(ctx: RiskContext) -> RiskFactor | None:
    for value in _string_values(ctx.arguments):
        for pattern in ctx.policy.protected_repos:
            if fnmatch.fnmatch(value, pattern):
                return RiskFactor(
                    factor="protected_repository",
                    contribution=PROTECTED_CONTRIBUTION,
                    reason=f"argument {value!r} matches protected pattern {pattern!r}",
                )
    return None


def _business_hours(ctx: RiskContext) -> RiskFactor | None:
    # v1 window: Mon-Fri, settings-configured hours, UTC only (no per-identity
    # timezone yet — documented choice, see config.py).
    off_hours = (
        ctx.now.weekday() >= 5
        or not settings.business_hours_start_utc <= ctx.now.hour < settings.business_hours_end_utc
    )
    if not off_hours:
        return None
    return RiskFactor(
        factor="business_hours",
        contribution=OFF_HOURS_CONTRIBUTION,
        reason=f"call at {ctx.now:%a %H:%M} UTC is outside business hours",
    )


def _call_frequency(ctx: RiskContext) -> RiskFactor | None:
    if ctx.call_count <= settings.risk_freq_threshold:
        return None
    return RiskFactor(
        factor="call_frequency",
        contribution=FREQUENCY_CONTRIBUTION,
        reason=(
            f"{ctx.call_count} calls to {ctx.tool_name!r} in the last"
            f" {settings.risk_freq_window_seconds}s exceeds {settings.risk_freq_threshold}"
        ),
    )


def _drift_in_review(ctx: RiskContext) -> RiskFactor | None:
    if not ctx.drift_in_review:
        return None
    return RiskFactor(
        factor="drift_in_review",
        contribution=DRIFT_IN_REVIEW_CONTRIBUTION,
        reason=f"{ctx.tool_name!r} has unresolved schema drift pending review",
    )


FACTORS: list[Callable[[RiskContext], RiskFactor | None]] = [
    _tool_sensitivity,
    _blast_radius,
    _business_hours,
    _call_frequency,
    _drift_in_review,
]


def _freq_key(identity_id: str, tool_name: str) -> str:
    return f"risk:freq:{identity_id}:{tool_name}"


def _decay_key(identity_id: str, tool_name: str) -> str:
    return f"risk:decay:{identity_id}:{tool_name}"


def combine(factors: list[RiskFactor], decay_offset: int) -> int:
    """Weighted sum with the decay boundary: the offset discounts only the behavioral
    subtotal, floored at 0, and the total is clamped to 0-100."""
    behavioral = sum(f.contribution for f in factors if f.factor in BEHAVIORAL_FACTORS)
    static = sum(f.contribution for f in factors if f.factor not in BEHAVIORAL_FACTORS)
    return min(static + max(0, behavioral - decay_offset), 100)


class RiskEngine:
    def __init__(self, redis_client: aioredis.Redis, detector: DriftDetector) -> None:
        self._redis = redis_client
        self._detector = detector

    async def score(
        self,
        identity_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        risk_policy: RiskPolicy,
    ) -> tuple[int, list[RiskFactor]]:
        """Score one prospective call. Raises on Redis/Postgres failure — callers
        treat that as score 100 and deny (§5)."""
        ctx = RiskContext(
            identity_id=identity_id,
            tool_name=tool_name,
            arguments=arguments,
            policy=risk_policy,
            now=datetime.now(UTC),
            call_count=await self._bump_frequency(identity_id, tool_name),
            drift_in_review=await self._detector.has_pending_drift(
                settings.upstream_server_id, tool_name
            ),
        )
        factors = [factor for fn in FACTORS if (factor := fn(ctx)) is not None]
        decay_raw = await self._redis.get(_decay_key(identity_id, tool_name))
        return combine(factors, int(decay_raw or 0)), factors

    async def _bump_frequency(self, identity_id: str, tool_name: str) -> int:
        key = _freq_key(identity_id, tool_name)
        count: int = await self._redis.incr(key)
        if count == 1:
            await self._redis.expire(key, settings.risk_freq_window_seconds)
        return count

    async def apply_decay(self, identity_id: str, tool_name: str) -> None:
        """One admin approval = one calibration step (§4.8): grow this pair's offset.
        No TTL — calibration is meant to persist, unlike the rolling counters."""
        await self._redis.incrby(_decay_key(identity_id, tool_name), settings.risk_decay_step)
