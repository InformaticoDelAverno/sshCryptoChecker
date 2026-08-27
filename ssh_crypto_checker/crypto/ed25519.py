"""Ed25519 signature verification (RFC 8032), for certificate chains.

PureEdDSA over edwards25519: the message (a tbsCertificate) is signed directly, not
pre-hashed. Only verification -- decompress the public key and the signature's R
point, then check ``[S]B == R + [k]A`` in extended coordinates. Public-key math, so
nothing here is secret. Follows the reference in RFC 8032 Appendix A.
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

p = 2**255 - 19  # the field prime
#: The group order of the base point.
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    """The multiplicative inverse modulo ``p`` (Fermat, since ``p`` is prime)."""
    return pow(x, p - 2, p)


d = -121665 * _inv(121666) % p  # the curve's non-square d
_SQRT_M1 = pow(2, (p - 1) // 4, p)  # a square root of -1, for the x recovery

_Point = Tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T), with x=X/Z etc.
_NEUTRAL: _Point = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> Optional[int]:
    """The x with the given low bit for a point with the given y, or None if there is none."""
    if y >= p:
        return None
    x2 = (y * y - 1) * _inv(d * y * y + 1) % p
    if x2 == 0:
        return None if sign else 0  # only (0, 1): the two points with x == 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _SQRT_M1 % p  # the other candidate root
    if (x * x - x2) % p != 0:
        return None  # x2 is not a square: y is not on the curve
    if (x & 1) != sign:
        x = p - x
    return x


def _point_add(point: _Point, other: _Point) -> _Point:
    """Add two edwards25519 points in extended coordinates (RFC 8032, a = -1)."""
    diff = (point[1] - point[0]) * (other[1] - other[0]) % p  # A
    summ = (point[1] + point[0]) * (other[1] + other[0]) % p  # B
    prod = 2 * point[3] * other[3] * d % p  # C
    zz = 2 * point[2] * other[2] % p  # D
    e, f, g, h = summ - diff, zz - prod, zz + prod, summ + diff  # E, F, G, H
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def _scalar_mul(scalar: int, point: _Point) -> _Point:
    """Multiply ``point`` by ``scalar`` by double-and-add."""
    result = _NEUTRAL
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


_g_y = 4 * _inv(5) % p
_g_x = _recover_x(_g_y, 0)
assert _g_x is not None  # the base point is on the curve by construction
_BASE: _Point = (_g_x, _g_y, 1, _g_x * _g_y % p)


def _decompress(data: bytes) -> Optional[_Point]:
    """Decode a 32-byte compressed point into extended coordinates, or None if invalid."""
    if len(data) != 32:
        return None
    encoded = int.from_bytes(data, "little")
    sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def _equal(point: _Point, other: _Point) -> bool:
    """Whether two points are equal, comparing the projective coordinates cross-multiplied."""
    if (point[0] * other[2] - other[0] * point[2]) % p != 0:
        return False
    return (point[1] * other[2] - other[1] * point[2]) % p == 0


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether ``signature`` is a valid Ed25519 signature of ``message`` under ``public_key``."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    point_a = _decompress(public_key)
    if point_a is None:
        return False
    r_bytes = signature[:32]
    point_r = _decompress(r_bytes)
    if point_r is None:
        return False
    scalar_s = int.from_bytes(signature[32:], "little")
    if scalar_s >= _L:
        return False
    digest = hashlib.sha512(r_bytes + public_key + message).digest()
    scalar_k = int.from_bytes(digest, "little") % _L
    checked = _scalar_mul(scalar_s, _BASE)
    expected = _point_add(point_r, _scalar_mul(scalar_k, point_a))
    return _equal(checked, expected)
