"""ECDSA signature verification over the NIST P-curves (FIPS 186-4)."""

from __future__ import annotations

import hashlib

from . import ec


def _decode_point(data: bytes) -> ec.Point:
    """Decode an uncompressed EC point (``0x04 || X || Y``)."""
    if len(data) < 3 or data[0] != 0x04 or len(data) % 2 == 0:
        return None
    half = (len(data) - 1) // 2
    return int.from_bytes(data[1 : 1 + half], "big"), int.from_bytes(data[1 + half :], "big")


def verify(
    curve: ec.Curve, public_key: bytes, r: int, s: int, message: bytes, hash_name: str
) -> bool:
    """Verify an ECDSA ``(r, s)`` over ``message`` for ``public_key`` on ``curve``."""
    n = curve.n
    if not (1 <= r < n and 1 <= s < n):
        return False
    point = _decode_point(public_key)
    if point is None or not ec.on_curve(curve, point):
        return False

    digest = hashlib.new(hash_name, message).digest()
    e = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - n.bit_length()
    if excess > 0:  # use the leftmost bits when the hash is wider than the order
        e >>= excess

    w = pow(s, -1, n)
    candidate = ec.add(
        curve,
        ec.scalar_mul(curve, e * w % n, curve.g),
        ec.scalar_mul(curve, r * w % n, point),
    )
    if candidate is None:
        return False
    return candidate[0] % n == r
