"""ABAC condition compiler + evaluator (ARCHITECTURE.md §4.8, ADR-004, item 17).

Conditions are boolean expressions over dotted attribute paths — comparisons
(==, !=, <, >, <=, >=), and/or/not, parentheses, string/number/bool literals —
parsed once at policy load and evaluated per tools/call. The grammar is a strict
subset of Python expressions, so parsing is `ast.parse(mode="eval")` followed by
a node whitelist; anything outside it (calls, subscripts, comprehensions,
lambdas, names without a dot, paths deeper than root.attr) fails at load. No
loops, no recursion, no user-defined functions, no eval/exec — evaluation is a
hand-written walk over the validated tree: deterministic and side-effect-free.

Missing-attribute rule (§4.8, security-critical): if ANY path a condition
references is absent from the supplied attributes, the ENTIRE condition is
not-satisfied — decided before any and/or/not combinator runs, so a missing
leaf can never be inverted into a grant by `not(...)` or rescued by
short-circuiting. Callers log POLICY_ERROR for visibility (policy authoring
bug) and deny as DENY_ABAC.
"""

import ast
from dataclasses import dataclass

ATTRIBUTE_ROOTS = frozenset({"identity", "tool", "context", "risk"})
MAX_CONDITION_LENGTH = 500  # cheap parse-bomb guard

_COMPARE_OPS: dict[type[ast.cmpop], str] = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.Gt: ">",
    ast.LtE: "<=",
    ast.GtE: ">=",
}

AttrValue = str | int | float | bool


@dataclass(frozen=True)
class Condition:
    source: str
    tree: ast.expr
    paths: frozenset[str]

    @property
    def references_risk(self) -> bool:
        return any(path.startswith("risk.") for path in self.paths)


def compile_condition(source: str) -> Condition:
    """Parse and validate one condition string. Raises ValueError on anything
    outside the whitelisted grammar — policy load fails closed on a bad rule."""
    if len(source) > MAX_CONDITION_LENGTH:
        raise ValueError(f"condition exceeds {MAX_CONDITION_LENGTH} characters")
    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"invalid condition syntax: {exc.msg}") from exc
    paths: set[str] = set()
    _validate(tree.body, paths)
    return Condition(source=source, tree=tree.body, paths=frozenset(paths))


def _validate(node: ast.expr, paths: set[str]) -> None:
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And | ast.Or):
        for value in node.values:
            _validate(value, paths)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        _validate(node.operand, paths)
    elif isinstance(node, ast.Compare):
        for op in node.ops:
            if type(op) not in _COMPARE_OPS:
                raise ValueError(f"comparison operator {type(op).__name__!r} is not allowed")
        for operand in (node.left, *node.comparators):
            _validate_operand(operand, paths)
    else:
        raise ValueError(
            f"{type(node).__name__} is not allowed: conditions are comparisons"
            " combined with and/or/not"
        )


def _validate_operand(node: ast.expr, paths: set[str]) -> None:
    if isinstance(node, ast.Attribute):
        if not isinstance(node.value, ast.Name):
            raise ValueError("attribute paths must be exactly root.attribute")
        if node.value.id not in ATTRIBUTE_ROOTS:
            allowed = ", ".join(sorted(ATTRIBUTE_ROOTS))
            raise ValueError(f"unknown attribute root {node.value.id!r} (allowed: {allowed})")
        paths.add(f"{node.value.id}.{node.attr}")
    elif isinstance(node, ast.Constant):
        # bool must precede int in the check only conceptually — bool is an int
        # subclass, so a plain isinstance covers both; None/bytes/etc. are out.
        if not isinstance(node.value, str | int | float):
            raise ValueError(f"literal {node.value!r} is not allowed")
    else:
        raise ValueError(
            f"{type(node).__name__} is not allowed: comparison operands are"
            " attribute paths or string/number/bool literals"
        )


def evaluate(condition: Condition, attrs: dict[str, AttrValue]) -> tuple[bool, list[str]]:
    """Return (satisfied, missing_paths). Every referenced path is resolved up
    front — a single unresolvable path makes the whole condition not-satisfied
    before any combinator logic runs (§4.8). With all paths bound, evaluation is
    a pure walk; a type-mismatch comparison raises TypeError, which the caller
    must treat as not-satisfied plus a POLICY_ERROR (authoring bug), fail-closed."""
    missing = sorted(path for path in condition.paths if path not in attrs)
    if missing:
        return False, missing
    return _eval(condition.tree, attrs), []


def _eval(node: ast.expr, attrs: dict[str, AttrValue]) -> bool:
    if isinstance(node, ast.BoolOp):
        results = (_eval(value, attrs) for value in node.values)
        return all(results) if isinstance(node.op, ast.And) else any(results)
    if isinstance(node, ast.UnaryOp):
        return not _eval(node.operand, attrs)
    assert isinstance(node, ast.Compare)  # _validate admits nothing else
    left = _operand(node.left, attrs)
    for op, comparator in zip(node.ops, node.comparators, strict=True):
        right = _operand(comparator, attrs)
        if not _compare(op, left, right):
            return False
        left = right
    return True


def _operand(node: ast.expr, attrs: dict[str, AttrValue]) -> AttrValue:
    if isinstance(node, ast.Attribute):
        assert isinstance(node.value, ast.Name)  # enforced by _validate_operand
        return attrs[f"{node.value.id}.{node.attr}"]
    assert isinstance(node, ast.Constant)
    value: AttrValue = node.value
    return value


def _compare(op: ast.cmpop, left: AttrValue, right: AttrValue) -> bool:
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.Lt):
        return left < right  # type: ignore[operator]  # TypeError -> not-satisfied
    if isinstance(op, ast.Gt):
        return left > right  # type: ignore[operator]
    if isinstance(op, ast.LtE):
        return left <= right  # type: ignore[operator]
    return left >= right  # type: ignore[operator]
