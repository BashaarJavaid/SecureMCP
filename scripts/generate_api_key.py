"""Mint credentials for a PortunusMCP identity (ARCHITECTURE.md §4.8).

Default (bearer): prints the raw key exactly once — hand it to the operator, it is
never stored. Paste the api_key_hash line into the identity's entry in the policy YAML.

--signed (item 34): prints a non-secret key id plus the HMAC signing secret exactly
once. The secret goes into an environment variable on the gateway host — never into
the policy YAML, which stores only the key id and the env var's *name*.

--totp (item 37): prints a base32 TOTP secret exactly once — load it into an
authenticator app and export it on the gateway host; the policy YAML stores only
the env var's name (totp_secret_env). Combinable with either auth mode.
"""

import base64
import hashlib
import secrets
import sys

if "--totp" in sys.argv[1:]:
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    env_name = f"PORTUNUSMCP_TOTP_SECRET_{secrets.token_hex(4).upper()}"
    print(f"TOTP secret (shown once; load into an authenticator app): {secret}")
    print("\nExport it on the gateway host (rename the var to taste):")
    print(f"  export {env_name}={secret}")
    print("\nPaste into the identity's entry in the policy YAML:")
    print(f'  totp_secret_env: "{env_name}"')
elif "--signed" in sys.argv[1:]:
    key_id = f"kid_{secrets.token_hex(8)}"
    secret = base64.b64encode(secrets.token_bytes(32)).decode()
    env_name = f"PORTUNUSMCP_SIGNING_SECRET_{secrets.token_hex(4).upper()}"
    print(f"Signing secret (shown once, store securely): {secret}")
    print("\nExport it on the gateway host (rename the var to taste):")
    print(f"  export {env_name}={secret}")
    print("\nPaste into the identity's entry in the policy YAML:")
    print('  auth_mode: "signed"')
    print(f'  key_id: "{key_id}"')
    print(f'  signing_secret_env: "{env_name}"')
else:
    key = base64.b64encode(secrets.token_bytes(32)).decode()
    digest = hashlib.sha256(key.encode()).hexdigest()
    print(f"API key (shown once, store securely): {key}")
    print(f'api_key_hash: "sha256:{digest}"')
