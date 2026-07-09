"""ARCHITECTURE.md §11 unit criterion: ABAC condition evaluation (item 17) —
grammar whitelist, and/or/not truth tables, and the missing-attribute rule,
specifically the not(...) inversion case."""

import pytest

from services.gateway import abac
from services.gateway.abac import compile_condition, evaluate

ATTRS: dict[str, abac.AttrValue] = {
    "identity.id": "agent-01",
    "identity.team": "engineering",
    "tool.name": "delete_repo",
    "tool.server_id": "github",
    "context.hour": 14,
    "risk.score": 35,
}


def check(source: str, attrs: dict[str, abac.AttrValue] = ATTRS) -> tuple[bool, list[str]]:
    return evaluate(compile_condition(source), attrs)


# --- parsing: accepted grammar ---


@pytest.mark.parametrize(
    "source",
    [
        "identity.team == 'engineering'",
        "identity.team != 'sales'",
        "context.hour < 20",
        "context.hour > 8",
        "context.hour <= 20",
        "context.hour >= 9",
        "identity.team == 'engineering' and context.hour < 20",
        "identity.team == 'ops' or identity.team == 'engineering'",
        "not (context.hour < 9)",
        "(identity.team == 'engineering' or tool.name == 'get_pr') and risk.score < 60",
        "risk.score < 60.5",
        "identity.mfa == True",
        "9 <= context.hour < 18",  # chained comparison
    ],
)
def test_valid_expressions_parse(source: str) -> None:
    compile_condition(source)


def test_referenced_paths_and_risk_flag() -> None:
    condition = compile_condition("identity.team == 'x' and risk.score < 60")
    assert condition.paths == {"identity.team", "risk.score"}
    assert condition.references_risk
    assert not compile_condition("context.hour < 20").references_risk


# --- parsing: rejected grammar (no code execution surface) ---


@pytest.mark.parametrize(
    "source",
    [
        "__import__('os').system('id')",
        "open('/etc/passwd')",
        "identity.team.upper() == 'X'",  # calls
        "identity['team'] == 'x'",  # subscripts
        "context.a.b < 5",  # deeper than root.attr
        "foo.bar == 1",  # unknown root
        "team == 'engineering'",  # bare name
        "lambda: True",
        "[x for x in identity.team]",
        "context.hour + 1 < 20",  # arithmetic
        "identity.team is None",  # non-whitelisted comparator
        "identity.team in 'engineering'",
        "context.hour if True else 1",
        "(x := 5) > 1",
        "f'{identity.team}' == 'x'",
        "None == None",  # None literal
        "b'x' == b'x'",  # bytes literal
        "True",  # bare constant, not a comparison
        "identity.team",  # bare path, not a comparison
        "not identity.team",  # `not` over a non-boolean leaf
        "version: [broken",  # syntax error
    ],
)
def test_invalid_expressions_rejected(source: str) -> None:
    with pytest.raises(ValueError):
        compile_condition(source)


def test_oversized_condition_rejected() -> None:
    huge = "context.hour < 20 and " * 50 + "context.hour < 20"
    with pytest.raises(ValueError):
        compile_condition(huge)


# --- evaluation: comparisons and combinators ---


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("identity.team == 'engineering'", True),
        ("identity.team == 'sales'", False),
        ("identity.team != 'sales'", True),
        ("context.hour < 20", True),
        ("context.hour < 14", False),
        ("context.hour <= 14", True),
        ("context.hour > 20", False),
        ("context.hour >= 14", True),
        ("9 <= context.hour < 18", True),
        ("15 <= context.hour < 18", False),
        ("risk.score < 60.5", True),
    ],
)
def test_comparisons(source: str, expected: bool) -> None:
    assert check(source) == (expected, [])


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("context.hour < 20 and identity.team == 'engineering'", True),
        ("context.hour < 20 and identity.team == 'sales'", False),
        ("context.hour > 20 and identity.team == 'sales'", False),
        ("context.hour < 20 or identity.team == 'sales'", True),
        ("context.hour > 20 or identity.team == 'engineering'", True),
        ("context.hour > 20 or identity.team == 'sales'", False),
        ("not (context.hour > 20)", True),
        ("not (context.hour < 20)", False),
        ("not (context.hour > 20 and identity.team == 'sales')", True),
        ("context.hour < 20 and (identity.team == 'sales' or risk.score < 60)", True),
    ],
)
def test_combinator_truth_tables(source: str, expected: bool) -> None:
    assert check(source) == (expected, [])


# --- missing attributes: the §4.8 security-critical rule ---

NO_HOUR = {k: v for k, v in ATTRS.items() if k != "context.hour"}


def test_missing_attribute_makes_condition_not_satisfied() -> None:
    assert check("context.hour < 20", NO_HOUR) == (False, ["context.hour"])


def test_missing_attribute_inside_not_is_not_inverted() -> None:
    # The §11 inversion case: a False leaf under not(...) would flip to a grant.
    # The whole condition is decided as not-satisfied before `not` ever runs.
    assert check("not (context.hour < 20)", NO_HOUR) == (False, ["context.hour"])


def test_missing_attribute_is_not_rescued_by_short_circuit() -> None:
    # The satisfied `or` arm can't save a condition referencing a missing path.
    satisfied, missing = check("identity.team == 'engineering' or context.hour < 20", NO_HOUR)
    assert (satisfied, missing) == (False, ["context.hour"])


def test_all_missing_paths_are_reported() -> None:
    satisfied, missing = check("context.hour < 20 and identity.region == 'eu'", NO_HOUR)
    assert not satisfied
    assert missing == ["context.hour", "identity.region"]


def test_type_mismatch_comparison_raises_for_caller_to_fail_closed() -> None:
    with pytest.raises(TypeError):
        check("identity.team < 5")
