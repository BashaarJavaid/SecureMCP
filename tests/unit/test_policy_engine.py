"""ARCHITECTURE.md §11 unit criterion: policy resolution logic (RBAC + ABAC load)."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from services.gateway import policy_engine
from services.gateway.policy_engine import PolicyEngine, PolicyFile


def make_engine(identities: list[dict]) -> PolicyEngine:
    return PolicyEngine(PolicyFile.model_validate({"version": 3, "identities": identities}))


READONLY = {
    "id": "agent-readonly",
    "api_key_hash": "sha256:0",
    "allowed_servers": [{"server_id": "github", "allowed_tools": ["list_issues", "get_pr"]}],
}


def test_allowed_tool_on_matching_server() -> None:
    assert make_engine([READONLY]).is_allowed("agent-readonly", "github", "list_issues")


def test_unlisted_tool_is_denied() -> None:
    assert not make_engine([READONLY]).is_allowed("agent-readonly", "github", "merge_pr")


def test_other_server_is_denied() -> None:
    assert not make_engine([READONLY]).is_allowed("agent-readonly", "filesystem", "list_issues")


def test_unknown_identity_is_denied() -> None:
    assert not make_engine([READONLY]).is_allowed("nobody", "github", "list_issues")


def test_missing_identity_is_denied() -> None:
    assert not make_engine([READONLY]).is_allowed(None, "github", "list_issues")


def test_denied_tools_overrides_wildcard_allow() -> None:
    engine = make_engine(
        [
            {
                "id": "ops",
                "api_key_hash": "sha256:1",
                "allowed_servers": [
                    {
                        "server_id": "*",
                        "allowed_tools": ["*"],
                        "denied_tools": ["delete_repo"],
                    }
                ],
            }
        ]
    )
    assert engine.is_allowed("ops", "github", "merge_pr")
    assert not engine.is_allowed("ops", "github", "delete_repo")


def test_conditions_are_compiled_at_load(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
version: 1
identities:
  - id: "ops"
    api_key_hash: "sha256:1"
    attributes:
      team: "engineering"
    allowed_servers:
      - server_id: "*"
        allowed_tools: ["*"]
        conditions:
          - "identity.team == 'engineering' and context.hour < 20"
          - "risk.score < 60"
"""
    )
    engine = policy_engine.load(policy)
    grant = engine.matching_grant("ops", "github", "merge_pr")
    assert grant is not None
    compiled = grant.compiled_conditions
    assert [c.source for c in compiled] == [
        "identity.team == 'engineering' and context.hour < 20",
        "risk.score < 60",
    ]
    assert [c.references_risk for c in compiled] == [False, True]
    assert engine.identity("ops") is not None
    assert engine.identity("ops").attributes == {"team": "engineering"}  # type: ignore[union-attr]


def test_malformed_condition_fails_load(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
version: 1
identities:
  - id: "ops"
    api_key_hash: "sha256:1"
    allowed_servers:
      - server_id: "*"
        allowed_tools: ["*"]
        conditions:
          - "__import__('os').system('id')"
"""
    )
    with pytest.raises(ValidationError):
        policy_engine.load(policy)


def test_matching_grant_none_when_rbac_denies() -> None:
    engine = make_engine([READONLY])
    assert engine.matching_grant("agent-readonly", "github", "merge_pr") is None
    assert engine.matching_grant("nobody", "github", "list_issues") is None


def test_missing_policy_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        policy_engine.load(tmp_path / "nope.yaml")


def test_policy_store_reload_swaps_engine(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nidentities: []\n")
    store = policy_engine.PolicyStore(path)
    assert store.engine.version == 1

    path.write_text("version: 2\nidentities: []\n")
    assert store.reload() is True
    assert store.engine.version == 2
    assert store.engine.content_hash  # recorded for the POLICY_ACTIVATED payload


def test_policy_store_keeps_last_known_good_on_broken_reload(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nidentities: []\n")
    store = policy_engine.PolicyStore(path)

    path.write_text("version: [broken\n")
    assert store.reload() is False
    assert store.engine.version == 1  # old policy stays active


def test_policy_store_keeps_last_known_good_on_bad_condition(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nidentities: []\n")
    store = policy_engine.PolicyStore(path)

    path.write_text(
        """
version: 2
identities:
  - id: "ops"
    api_key_hash: "sha256:1"
    allowed_servers:
      - server_id: "*"
        allowed_tools: ["*"]
        conditions:
          - "open('/etc/passwd')"
"""
    )
    assert store.reload() is False
    assert store.engine.version == 1
