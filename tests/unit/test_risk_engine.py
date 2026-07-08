"""Unit tests for the Risk Engine's pure parts (item 16): each factor in isolation
and the weighted sum with the decay boundary. Threshold routing lives with the
interceptor tests; Redis/Postgres-backed scoring is covered by the integration suite."""

from datetime import UTC, datetime
from typing import Any

from services.gateway.decision import RiskFactor
from services.gateway.policy_engine import RiskPolicy
from services.gateway.risk_engine import (
    DRIFT_IN_REVIEW_CONTRIBUTION,
    FREQUENCY_CONTRIBUTION,
    OFF_HOURS_CONTRIBUTION,
    PROTECTED_CONTRIBUTION,
    TIER_CONTRIBUTION,
    RiskContext,
    _blast_radius,
    _business_hours,
    _call_frequency,
    _drift_in_review,
    _tool_sensitivity,
    combine,
)

WEDNESDAY_NOON = datetime(2026, 7, 8, 12, 0, tzinfo=UTC)


def ctx(**overrides: Any) -> RiskContext:
    defaults: dict[str, Any] = {
        "identity_id": "agent-readonly",
        "tool_name": "echo",
        "arguments": {},
        "policy": RiskPolicy(),
        "now": WEDNESDAY_NOON,
        "call_count": 1,
        "drift_in_review": False,
    }
    return RiskContext(**{**defaults, **overrides})


def test_tool_sensitivity_tiers() -> None:
    policy = RiskPolicy(tool_sensitivity={"delete_repo": "high"})
    factor = _tool_sensitivity(ctx(tool_name="delete_repo", policy=policy))
    assert factor is not None
    assert factor.contribution == TIER_CONTRIBUTION["high"]
    assert _tool_sensitivity(ctx(tool_name="unlisted", policy=policy)) is None


def test_blast_radius_matches_nested_string_arguments() -> None:
    policy = RiskPolicy(protected_repos=["acme/prod-*"])
    factor = _blast_radius(
        ctx(arguments={"target": {"repos": ["acme/dev", "acme/prod-api"]}}, policy=policy)
    )
    assert factor is not None
    assert factor.contribution == PROTECTED_CONTRIBUTION
    assert "acme/prod-api" in (factor.reason or "")
    assert _blast_radius(ctx(arguments={"repo": "acme/dev"}, policy=policy)) is None
    assert _blast_radius(ctx(arguments={"repo": "acme/prod-api"})) is None  # empty list


def test_business_hours_window_and_weekend() -> None:
    assert _business_hours(ctx(now=WEDNESDAY_NOON)) is None
    late = _business_hours(ctx(now=WEDNESDAY_NOON.replace(hour=20)))
    assert late is not None and late.contribution == OFF_HOURS_CONTRIBUTION
    # Boundaries: start hour is inside, end hour is outside.
    assert _business_hours(ctx(now=WEDNESDAY_NOON.replace(hour=9))) is None
    assert _business_hours(ctx(now=WEDNESDAY_NOON.replace(hour=18))) is not None
    saturday = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    assert _business_hours(ctx(now=saturday)) is not None


def test_call_frequency_spike_threshold() -> None:
    assert _call_frequency(ctx(call_count=10)) is None  # at threshold: no spike
    factor = _call_frequency(ctx(call_count=11))
    assert factor is not None and factor.contribution == FREQUENCY_CONTRIBUTION


def test_drift_in_review_flag() -> None:
    assert _drift_in_review(ctx()) is None
    factor = _drift_in_review(ctx(drift_in_review=True))
    assert factor is not None and factor.contribution == DRIFT_IN_REVIEW_CONTRIBUTION


def _factors() -> list[RiskFactor]:
    return [
        RiskFactor(factor="tool_sensitivity", contribution=30),
        RiskFactor(factor="call_frequency", contribution=20),
        RiskFactor(factor="drift_in_review", contribution=15),
    ]


def test_decay_discounts_behavioral_factors_only() -> None:
    """§4.8 boundary: decay floors the behavioral subtotal at 0 and never touches
    the static sensitivity tier — rubber-stamp approvals can't erode it."""
    assert combine(_factors(), decay_offset=0) == 65
    assert combine(_factors(), decay_offset=10) == 55
    assert combine(_factors(), decay_offset=35) == 30  # behavioral floored at 0
    assert combine(_factors(), decay_offset=1000) == 30  # tier survives any decay


def test_combine_clamps_to_100() -> None:
    heavy = _factors() + [
        RiskFactor(factor="protected_repository", contribution=30),
        RiskFactor(factor="business_hours", contribution=25),
    ]
    assert combine(heavy, decay_offset=0) == 100
