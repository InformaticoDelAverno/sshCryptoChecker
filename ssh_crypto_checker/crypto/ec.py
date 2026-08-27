"""Short-Weierstrass elliptic curves over a prime field, for ECDSA verification.

Just the NIST curves that ECDSA certificates use, and just the two operations a
signature check needs: point addition and scalar multiplication. Every NIST curve
has ``a = -3``, so it is written in rather than carried around. Nothing here is
constant-time: a scanner verifies public signatures and guards no secret.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

Point = Optional[Tuple[int, int]]  # None is the point at infinity


@dataclass(frozen=True)
class Curve:
    """A NIST prime curve ``y^2 = x^3 - 3x + b (mod p)`` with base point ``G``."""

    name: str
    p: int
    b: int
    gx: int
    gy: int
    n: int

    @property
    def g(self) -> Tuple[int, int]:
        return (self.gx, self.gy)


def add(curve: Curve, point_a: Point, point_b: Point) -> Point:
    """The elliptic-curve group addition of two points."""
    if point_a is None:
        return point_b
    if point_b is None:
        return point_a
    p = curve.p
    x1, y1 = point_a
    x2, y2 = point_b
    if x1 == x2 and (y1 + y2) % p == 0:
        return None  # P + (-P) is the point at infinity
    if point_a == point_b:
        slope = (3 * x1 * x1 - 3) * pow(2 * y1, -1, p) % p
    else:
        slope = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mul(curve: Curve, scalar: int, point: Point) -> Point:
    """Multiply ``point`` by ``scalar`` by double-and-add."""
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = add(curve, result, addend)
        addend = add(curve, addend, addend)
        scalar >>= 1
    return result


def on_curve(curve: Curve, point: Point) -> bool:
    """Whether ``point`` satisfies the curve equation (rejects invalid keys)."""
    if point is None:
        return False
    x, y = point
    return (y * y - (x * x * x - 3 * x + curve.b)) % curve.p == 0


P256 = Curve(
    name="P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)
P384 = Curve(
    name="P-384",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
)

#: The named curves, keyed by their SubjectPublicKeyInfo OID.
CURVES_BY_OID: Dict[str, Curve] = {
    "1.2.840.10045.3.1.7": P256,  # prime256v1 / secp256r1
    "1.3.132.0.34": P384,  # secp384r1
}
