"""Unit tests for Policy Simulation Mode (item 21): the replay-window parser and
the hand-computed Mode A / Mode B diff counters (§11's simulation-accuracy check
at the pure-function level; the end-to-end version runs in the integration suite)."""

from datetime import UTC, datetime

import pytest

from services.gateway.db import AuditLog
from services.gateway.decision import Decision, DecisionOutcome, EventType
from services.gateway.policy_simulator import (
    parse_window,
    summarize_compare,
    summarize_historical,
)


def test_parse_window_inclusive_range() -> None:
    start, end = parse_window("2026-06-01..2026-07-01")
    assert start == datetime(2026, 6, 1, tzinfo=UTC)
    # Inclusive end date -> exclusive end is the following midnight.
    assert end == datetime(2026, 7, 2, tzinfo=UTC)


def test_parse_window_single_day() -> None:
    start, end = parse_window("2026-06-15..2026-06-15")
    assert start == datetime(2026, 6, 15, tzinfo=UTC)
    assert end == datetime(2026, 6, 16, tzinfo=UTC)


@pytest.mark.parametrize(
    "window",
    ["2026-06-01", "2026-06-01..2026-07-01..2026-08-01", "june..july", ""],
)
def test_parse_window_malformed(window: str) -> None:
    with pytest.raises(ValueError, match="replay_window must be"):
        parse_window(window)


def test_parse_window_reversed() -> None:
    with pytest.raises(ValueError, match="after its end"):
        parse_window("2026-07-01..2026-06-01")


def _row(seq: int, event_type: EventType) -> AuditLog:
    return AuditLog(
        seq=seq,
        identity_id="agent",
        tool_name="delete_repo",
        policy_version=1,
        event_type=event_type.value,
        payload={"arguments": {"repo": "acme/prod-api"}},
    )


def _decision(
    outcome: DecisionOutcome,
    risk_score: int | None = None,
    reason: str = "simulated",
) -> Decision:
    events: dict[DecisionOutcome, EventType] = {
        DecisionOutcome.ALLOW: EventType.ALLOW,
        DecisionOutcome.DENY: EventType.DENY_RBAC,
        DecisionOutcome.CHALLENGE: EventType.CHALLENGE,
        DecisionOutcome.HUMAN_APPROVAL_REQUIRED: EventType.HUMAN_APPROVAL_REQUIRED,
    }
    return Decision(
        decision=outcome,
        event_type=events[outcome],
        reason=reason,
        matched_rules=["policy-v2:rbac"],
        risk_score=risk_score,
        policy_version=2,
    )


def test_summarize_historical_hand_computed() -> None:
    ALLOW, DENY = DecisionOutcome.ALLOW, DecisionOutcome.DENY
    HAR = DecisionOutcome.HUMAN_APPROVAL_REQUIRED
    pairs: list[tuple[AuditLog, Decision]] = [
        (_row(1, EventType.ALLOW), _decision(ALLOW)),  # unchanged
        (_row(2, EventType.ALLOW), _decision(DENY)),  # would_now_deny
        (_row(3, EventType.ALLOW), _decision(HAR)),  # would_now_require_approval
        (_row(4, EventType.DENY_RBAC), _decision(ALLOW)),  # newly_allowed
        (_row(5, EventType.CHALLENGE), _decision(ALLOW)),  # newly_allowed
        (_row(6, EventType.CHALLENGE), _decision(DENY)),  # changed, no named counter
        (_row(7, EventType.DENY_RISK), _decision(HAR)),  # would_now_require_approval
        (_row(8, EventType.HUMAN_APPROVAL_REQUIRED), _decision(HAR)),  # unchanged
        (_row(9, EventType.HUMAN_APPROVAL_REQUIRED), _decision(ALLOW)),  # changed, no counter
    ]
    result = summarize_historical(pairs)
    assert result.total_replayed == 9
    assert result.unchanged == 2
    assert result.would_now_deny == 1
    assert result.would_now_require_approval == 2
    assert result.newly_allowed == 2
    # Every changed pair gets a sample diff (7 changed, under the cap of 10).
    assert len(result.sample_diffs) == 7
    first = result.sample_diffs[0]
    assert (first.audit_seq, first.before, first.after) == (2, "allow", "deny")


def test_summarize_compare_hand_computed() -> None:
    def t(seq: int, old: Decision, new: Decision) -> tuple[AuditLog, Decision, Decision]:
        return (_row(seq, EventType.ALLOW), old, new)

    ALLOW, DENY = DecisionOutcome.ALLOW, DecisionOutcome.DENY
    CHALLENGE, HAR = DecisionOutcome.CHALLENGE, DecisionOutcome.HUMAN_APPROVAL_REQUIRED
    triples = [
        t(1, _decision(ALLOW, 10), _decision(ALLOW, 10)),  # identical
        t(2, _decision(ALLOW, 10), _decision(DENY, 95, "too risky")),  # new denial
        t(3, _decision(CHALLENGE, 50), _decision(DENY, 95, "too risky")),  # new denial
        t(4, _decision(ALLOW, 10), _decision(HAR, 75, "needs approval")),  # new approval
        t(5, _decision(HAR, 75), _decision(HAR, 75)),  # identical
        t(6, _decision(ALLOW, 10), _decision(ALLOW, 20)),  # score only
        t(7, _decision(ALLOW, 10, "reason a"), _decision(ALLOW, 10, "reason b")),  # reason only
        t(8, _decision(DENY, reason="rule x"), _decision(DENY, reason="rule y")),  # reason only
    ]
    result = summarize_compare(triples, [2, 5])
    assert result.total_replayed == 8
    assert result.compared_versions == [2, 5]
    assert result.new_denials == 2
    assert result.new_approvals == 1
    assert result.changed_risk_scores == 4  # seqs 2, 3, 4, 6
    assert result.changed_explanations == 5  # seqs 2, 3, 4 (bucket) + 7, 8 (reason)
    # Sample diffs cover explanation changes only; labels carry the risk scores.
    assert [d.audit_seq for d in result.sample_diffs] == [2, 3, 4, 7, 8]
    assert result.sample_diffs[0].before == "allow (risk 10)"
    assert result.sample_diffs[0].after == "deny (risk 95)"
    assert result.sample_diffs[0].reason == "too risky"


def test_summarize_empty_replay_set() -> None:
    a: list[tuple[AuditLog, Decision]] = []
    assert summarize_historical(a).total_replayed == 0
    b: list[tuple[AuditLog, Decision, Decision]] = []
    assert summarize_compare(b, [1, 2]).new_denials == 0
