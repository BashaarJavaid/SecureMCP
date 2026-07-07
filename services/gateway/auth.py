"""API key verification, identity resolution (ARCHITECTURE.md §4.8 Auth Layer).

Hash-and-lookup, not HMAC or signing: the policy store holds only SHA256(key) as
"sha256:<hex>"; the presented key is hashed and looked up directly. Keys are 256-bit
random values (see scripts/generate_api_key.py), so no salting is needed — and
deterministic hashing is what makes direct lookup possible. Never log the key (§6).
"""

import hashlib

from services.gateway.policy_engine import PolicyEngine


def resolve_identity(api_key: str | None, engine: PolicyEngine) -> str | None:
    if not api_key:
        return None
    digest = hashlib.sha256(api_key.encode()).hexdigest()
    return engine.identity_for_key_hash(f"sha256:{digest}")
