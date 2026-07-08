"""arguments_hash is the TOCTOU comparison's foundation (item 16): it must be
key-order-insensitive (canonical JSON) but sensitive to any value change. The full
redemption lifecycle runs against real Postgres in tests/integration."""

from services.gateway.approvals import arguments_hash


def test_arguments_hash_is_canonical_and_value_sensitive() -> None:
    assert arguments_hash({"a": 1, "b": [2, 3]}) == arguments_hash({"b": [2, 3], "a": 1})
    assert arguments_hash({"a": 1}) != arguments_hash({"a": 2})
    assert arguments_hash({}) == arguments_hash({})
