"""Step-up auth for the CHALLENGE band (ROADMAP item 37).

A fresh score in the 40-69 band issues a one-time challenge instead of a bare
terminal error — provided the identity has a TOTP factor configured
(`totp_secret_env` in the policy YAML; base32 secret resolved from the environment
at load, same indirection as item 34's signing secret). The client surfaces the
challenge to a human, who reads a code off their authenticator app; the retry
carries the challenge id and code in `params._meta`, structurally the same
one-time redeem-token pattern as `portunusmcp/approval_id`.

Pending challenges live in Redis with a short TTL, consumed atomically via GETDEL —
one-time use, no migration, and a gateway restart simply drops them (the client
triggers a fresh challenge). Redemption re-checks identity/server/tool and the
arguments hash (the TOCTOU case, mirroring approvals), verifies the TOTP code
(RFC 6238, 30s step, ±1 step skew), and dedups the code per identity so a captured
code can't be replayed onto a second challenge. A verified proof only ever clears
the CHALLENGE band: the retry is re-scored, and the approval (70-90) and deny (>90)
bands still stand — step-up can never bypass human approval or DENY_RISK.
"""

import base64
import binascii
import hashlib
import hmac
import json
import struct
import time
import uuid

import canonicaljson
import redis.asyncio as aioredis

from services.gateway.config import settings

CHALLENGE_ID_META_KEY = "portunusmcp/challenge_id"
CHALLENGE_PROOF_META_KEY = "portunusmcp/challenge_proof"

# RFC 6238 spec constants, not knobs (item-32 precedent): 30s step, 6 digits,
# SHA-1 (what authenticator apps implement), ±1 step of clock skew.
_TOTP_STEP_SECONDS = 30
_TOTP_DIGITS = 6
_TOTP_SKEW_STEPS = 1
# A code is valid for at most (skew+1) steps = 60s; the dedup key must outlive that.
_CODE_DEDUP_TTL_SECONDS = 90


def decode_totp_secret(secret_b32: str) -> bytes:
    """base32 → key bytes; raises on garbage. Called at policy load too, so a
    malformed secret fails startup rather than failing every redemption (§5)."""
    return base64.b32decode(secret_b32.strip().upper())


def totp_code(secret_b32: str, at: float | None = None) -> str:
    """The RFC 6238 code for the step containing `at` (default: now). Public so
    tests and signing clients can compute codes; verification is verify_totp()."""
    counter = int((time.time() if at is None else at) // _TOTP_STEP_SECONDS)
    return _hotp(decode_totp_secret(secret_b32), counter)


def verify_totp(secret_b32: str, code: str, at: float | None = None) -> bool:
    """Constant-time check against the current step ±1 for clock skew."""
    try:
        secret = decode_totp_secret(secret_b32)
    except (binascii.Error, ValueError):
        return False
    counter = int((time.time() if at is None else at) // _TOTP_STEP_SECONDS)
    return any(
        hmac.compare_digest(_hotp(secret, counter + skew), code)
        for skew in range(-_TOTP_SKEW_STEPS, _TOTP_SKEW_STEPS + 1)
    )


def _hotp(secret: bytes, counter: int) -> str:
    # RFC 4226 dynamic truncation.
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 10**_TOTP_DIGITS:0{_TOTP_DIGITS}d}"


def _challenge_key(challenge_id: str) -> str:
    return f"challenge:{challenge_id}"


def _code_dedup_key(identity_id: str, code: str) -> str:
    return f"challenge:code:{identity_id}:{code}"


class ChallengeStore:
    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client

    async def create(
        self, identity_id: str, server_id: str, tool_name: str, args_hash: str, audit_id: int
    ) -> str:
        """Store a pending challenge under a fresh one-time id. Raises on Redis
        failure — the caller fails closed, mirroring the approvals row (§5)."""
        challenge_id = uuid.uuid4().hex
        record = canonicaljson.encode_canonical_json(
            {
                "identity_id": identity_id,
                "server_id": server_id,
                "tool_name": tool_name,
                "arguments_hash": args_hash,
                "audit_id": audit_id,
            }
        )
        await self._redis.set(_challenge_key(challenge_id), record, ex=settings.step_up_ttl_seconds)
        return challenge_id

    async def redeem(
        self,
        challenge_id: str,
        identity_id: str,
        server_id: str,
        tool_name: str,
        args_hash: str,
        proof: object,
        secret_b32: str,
    ) -> str | None:
        """Validate a step-up retry, consuming the challenge first (one-time use
        holds whatever else fails). Returns None on success, or the reason for the
        denial. GETDEL can't distinguish unknown/expired/consumed — one reason says
        so. Raises on Redis failure; the caller denies (§5)."""
        raw = await self._redis.getdel(_challenge_key(challenge_id))
        if raw is None:
            return "challenge is unknown, expired, or already used"
        record = json.loads(raw)
        if (
            record["identity_id"] != identity_id
            or record["server_id"] != server_id
            or record["tool_name"] != tool_name
        ):
            return "challenge was issued to a different identity, server, or tool"
        if record["arguments_hash"] != args_hash:
            # TOCTOU, mirroring approvals: arguments changed between challenge and retry.
            return "arguments differ from the ones that were challenged"
        if not secret_b32:
            return "identity has no step-up factor configured"
        if not isinstance(proof, str) or not verify_totp(secret_b32, proof):
            return "TOTP proof is invalid"
        # One code, one redemption: a captured code can't answer a second challenge
        # within its validity window.
        fresh = await self._redis.set(
            _code_dedup_key(identity_id, proof), 1, nx=True, ex=_CODE_DEDUP_TTL_SECONDS
        )
        if not fresh:
            return "TOTP code has already been used"
        return None
