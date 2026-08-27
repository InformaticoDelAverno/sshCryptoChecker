"""Short Weierstrass curve arithmetic for the NIST P-256/384/521 curves.

Used to build a valid ephemeral public point for the ``ecdh-sha2-nistp*`` key
exchange methods. Not constant-time; see the package docstring.

The curve constants are validated by the test suite: the generator must lie on
the curve and ``n * G`` must be the point at infinity, which catches any typo.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

__all__ = ["CURVES", "Curve", "curve_for_kex", "encode_point", "generate_key_pair"]

#: Affine point; ``None`` represents the point at infinity.
Point = Optional[Tuple[int, int]]


@dataclass(frozen=True)
class Curve:
    """Domain parameters of a short Weierstrass curve ``y^2 = x^3 + ax + b``."""

    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int
    bits: int

    @property
    def byte_length(self) -> int:
        return (self.bits + 7) // 8

    @property
    def generator(self) -> Point:
        return (self.gx, self.gy)

    def is_on_curve(self, point: Point) -> bool:
        if point is None:
            return True
        x, y = point
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def add(self, first: Point, second: Point) -> Point:
        """Affine point addition."""
        if first is None:
            return second
        if second is None:
            return first
        x1, y1 = first
        x2, y2 = second
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None
        if first == second:
            numerator = (3 * x1 * x1 + self.a) % self.p
            denominator = (2 * y1) % self.p
        else:
            numerator = (y2 - y1) % self.p
            denominator = (x2 - x1) % self.p
        slope = numerator * pow(denominator, self.p - 2, self.p) % self.p
        x3 = (slope * slope - x1 - x2) % self.p
        y3 = (slope * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def multiply(self, scalar: int, point: Point) -> Point:
        """Double-and-add scalar multiplication."""
        if scalar % self.n == 0 or point is None:
            return None
        if scalar < 0:
            scalar = -scalar
            point = (point[0], (-point[1]) % self.p)
        result: Point = None
        addend: Point = point
        while scalar:
            if scalar & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            scalar >>= 1
        return result


# The NIST primes have exact closed forms (FIPS 186-5, D.1.2). Writing them as
# expressions rather than long hex literals removes any chance of a transcription
# error; `a` is -3 on all three curves.
_P256_PRIME = 2**256 - 2**224 + 2**192 + 2**96 - 1
_P384_PRIME = 2**384 - 2**128 - 2**96 + 2**32 - 1
_P521_PRIME = 2**521 - 1

P256 = Curve(
    name="nistp256",
    p=_P256_PRIME,
    a=_P256_PRIME - 3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    bits=256,
)

P384 = Curve(
    name="nistp384",
    p=_P384_PRIME,
    a=_P384_PRIME - 3,
    b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    bits=384,
)

P521 = Curve(
    name="nistp521",
    p=_P521_PRIME,
    a=_P521_PRIME - 3,
    b=0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
    gx=0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
    gy=0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
    n=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
    bits=521,
)

CURVES: Dict[str, Curve] = {curve.name: curve for curve in (P256, P384, P521)}

#: SSH key exchange method name -> curve.
_KEX_CURVES: Dict[str, Curve] = {
    "ecdh-sha2-nistp256": P256,
    "ecdh-sha2-nistp384": P384,
    "ecdh-sha2-nistp521": P521,
}


def curve_for_kex(kex_name: str) -> Optional[Curve]:
    """Return the curve used by an ``ecdh-sha2-nistp*`` key exchange method."""
    return _KEX_CURVES.get(kex_name)


def encode_point(curve: Curve, point: Point) -> bytes:
    """Encode a point in uncompressed SEC1 form (``0x04 || X || Y``)."""
    if point is None:
        return b"\x00"
    x, y = point
    size = curve.byte_length
    return b"\x04" + x.to_bytes(size, "big") + y.to_bytes(size, "big")


def generate_key_pair(curve: Curve) -> Tuple[int, bytes]:
    """Return ``(private_scalar, encoded_public_point)`` for ``curve``."""
    # Redrawn on a scalar of zero, which is a 2^-256 event; the loop is the
    # whole guard, so there is no separate branch nothing can take.
    candidate = 0
    while candidate < 1:
        candidate = int.from_bytes(os.urandom(curve.byte_length + 8), "big") % curve.n
    public = curve.multiply(candidate, curve.generator)
    return candidate, encode_point(curve, public)
