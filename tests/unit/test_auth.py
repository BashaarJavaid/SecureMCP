import hashlib

from services.gateway.auth import resolve_identity
from services.gateway.policy_engine import PolicyEngine, PolicyFile

KEY_A = "test-key-alpha"
KEY_B = "test-key-beta"


def hash_of(key: str) -> str:
    return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


ENGINE = PolicyEngine(
    PolicyFile.model_validate(
        {
            "version": 1,
            "identities": [
                {"id": "agent-a", "api_key_hash": hash_of(KEY_A), "allowed_servers": []},
                {"id": "agent-b", "api_key_hash": hash_of(KEY_B), "allowed_servers": []},
            ],
        }
    )
)


def test_correct_key_resolves_to_its_identity() -> None:
    assert resolve_identity(KEY_A, ENGINE) == "agent-a"
    assert resolve_identity(KEY_B, ENGINE) == "agent-b"


def test_wrong_key_resolves_to_none() -> None:
    assert resolve_identity("not-a-key", ENGINE) is None


def test_missing_key_resolves_to_none() -> None:
    assert resolve_identity(None, ENGINE) is None
    assert resolve_identity("", ENGINE) is None
