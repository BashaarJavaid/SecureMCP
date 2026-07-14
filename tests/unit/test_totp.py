"""TOTP verification (item 37): RFC 6238 Appendix B test vectors and the ±1-step
skew window. The challenge lifecycle itself is exercised end to end in
tests/integration/test_step_up.py and tests/adversarial/test_step_up.py."""

import base64

import pytest

from services.gateway.step_up import totp_code, verify_totp

# RFC 6238's SHA-1 vectors use the ASCII seed "12345678901234567890" and 8-digit
# codes; a 6-digit code is the same dynamically truncated value mod 10^6, i.e. the
# vector's last six digits.
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()
RFC_VECTORS = [
    (59, "287082"),  # 94287082
    (1111111109, "081804"),  # 07081804
    (1111111111, "050471"),  # 14050471
    (1234567890, "005924"),  # 89005924
    (2000000000, "279037"),  # 69279037
    (20000000000, "353130"),  # 65353130
]


@pytest.mark.parametrize(("at", "expected"), RFC_VECTORS)
def test_rfc6238_vectors(at: int, expected: str) -> None:
    assert totp_code(RFC_SECRET, at) == expected
    assert verify_totp(RFC_SECRET, expected, at)


def test_skew_window_is_plus_minus_one_step() -> None:
    now = 1111111111  # mid-step; step = 30s
    for drift in (-30, 0, 30):
        assert verify_totp(RFC_SECRET, totp_code(RFC_SECRET, now + drift), now)
    for drift in (-60, 60):
        assert not verify_totp(RFC_SECRET, totp_code(RFC_SECRET, now + drift), now)


def test_wrong_code_and_garbage_secret_fail_closed() -> None:
    assert not verify_totp(RFC_SECRET, "000000", 59)
    assert not verify_totp("not!base32", "287082", 59)
