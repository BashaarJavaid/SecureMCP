"""Mint an API key for a SecurMCP identity (ARCHITECTURE.md §4.8).

Prints the raw key exactly once — hand it to the operator, it is never stored.
Paste the api_key_hash line into the identity's entry in the policy YAML.
"""

import base64
import hashlib
import secrets

key = base64.b64encode(secrets.token_bytes(32)).decode()
digest = hashlib.sha256(key.encode()).hexdigest()

print(f"API key (shown once, store securely): {key}")
print(f'api_key_hash: "sha256:{digest}"')
