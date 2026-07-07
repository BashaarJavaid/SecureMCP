import hashlib

import canonicaljson

from services.gateway.audit_log import GENESIS_HASH, compute_hash


def test_matches_spec_formula() -> None:
    payload = {"event_type": "ALLOW", "identity_id": "a"}
    expected = hashlib.sha256(
        GENESIS_HASH.encode() + canonicaljson.encode_canonical_json(payload)
    ).hexdigest()
    assert compute_hash(GENESIS_HASH, payload) == expected


def test_stable_under_key_reordering() -> None:
    # The audit-chain twin of item 9's canonicalization smoke test.
    assert compute_hash("f" * 64, {"a": 1, "b": 2}) == compute_hash("f" * 64, {"b": 2, "a": 1})


def test_chaining_differs_by_prev_hash() -> None:
    payload = {"x": 1}
    assert compute_hash("0" * 64, payload) != compute_hash("1" * 64, payload)
