"""ECDSA (P-256) signing over audit-row hashes (ARCHITECTURE.md §4.8, item 11).

The hash chain alone only proves internal consistency — an attacker with Postgres
write access can regenerate a self-consistent chain from a tampered point forward.
Signing each row's curr_hash with a key held only by the gateway process closes that
gap: the verifier checks both the chain math AND the signature on every row.

Keypair is minted once via scripts/generate_signing_key.py; loaders raise on a
missing or invalid file so the gateway fails startup (§5, fail closed).
"""

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def load_private_key(path: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError(f"{path} is not an EC private key")
    return key


def load_public_key(path: str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError(f"{path} is not an EC public key")
    return key


def sign(private_key: ec.EllipticCurvePrivateKey, curr_hash: str) -> bytes:
    """DER-encoded ECDSA-SHA256 signature over the row's curr_hash."""
    return private_key.sign(curr_hash.encode(), ec.ECDSA(hashes.SHA256()))


def verify(
    public_key: ec.EllipticCurvePublicKey, signature: bytes, curr_hash: str
) -> bool:
    try:
        public_key.verify(signature, curr_hash.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True
