from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from services.gateway import signing

HASH = "ab" * 32


def test_sign_verify_round_trip() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    signature = signing.sign(key, HASH)
    assert signing.verify(key.public_key(), signature, HASH)


def test_verify_fails_for_tampered_hash() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    signature = signing.sign(key, HASH)
    assert not signing.verify(key.public_key(), signature, "cd" * 32)


def test_verify_fails_for_wrong_key() -> None:
    signature = signing.sign(ec.generate_private_key(ec.SECP256R1()), HASH)
    other = ec.generate_private_key(ec.SECP256R1())
    assert not signing.verify(other.public_key(), signature, HASH)


def test_loaders_raise_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        signing.load_private_key(str(tmp_path / "nope.pem"))
    with pytest.raises(FileNotFoundError):
        signing.load_public_key(str(tmp_path / "nope.pub.pem"))


def test_loaders_round_trip_pem(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    private_path = tmp_path / "key.pem"
    public_path = tmp_path / "key.pub.pem"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    loaded_private = signing.load_private_key(str(private_path))
    loaded_public = signing.load_public_key(str(public_path))
    assert signing.verify(loaded_public, signing.sign(loaded_private, HASH), HASH)
