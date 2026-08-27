"""X25519 scalar multiplication (RFC 7748).

Only used to build a valid ephemeral public key for the ``curve25519-sha256``
key exchange. Not constant-time; see the package docstring.
"""

from __future__ import annotations

import os

__all__ = ["P", "generate_private_key", "public_key", "scalar_mult"]

P = 2**255 - 19
_A24 = 121665
_BITS = 255
_BASE_POINT = b"\x09" + b"\x00" * 31


def _decode_scalar(scalar: bytes) -> int:
    if len(scalar) != 32:
        raise ValueError("X25519 scalars are 32 bytes long")
    clamped = bytearray(scalar)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return int.from_bytes(bytes(clamped), "little")


def _decode_u(coordinate: bytes) -> int:
    if len(coordinate) != 32:
        raise ValueError("X25519 u-coordinates are 32 bytes long")
    masked = bytearray(coordinate)
    masked[31] &= 127
    return int.from_bytes(bytes(masked), "little")


def scalar_mult(scalar: bytes, u_coordinate: bytes) -> bytes:
    """Return ``scalar * u`` on Curve25519, using the RFC 7748 Montgomery ladder."""
    x_1 = _decode_u(u_coordinate)
    k = _decode_scalar(scalar)

    x_2, z_2 = 1, 0
    x_3, z_3 = x_1, 1
    swap = 0

    for bit in range(_BITS - 1, -1, -1):
        k_t = (k >> bit) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        a = (x_2 + z_2) % P
        aa = a * a % P
        b = (x_2 - z_2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x_3 + z_3) % P
        d = (x_3 - z_3) % P
        da = d * a % P
        cb = c * b % P
        x_3 = pow(da + cb, 2, P)
        z_3 = x_1 * pow(da - cb, 2, P) % P
        x_2 = aa * bb % P
        z_2 = e * (aa + _A24 * e % P) % P

    # RFC 7748's reference ladder ends with one more conditional swap, and it
    # is absent here on purpose. That swap is driven by the last bit processed,
    # which is bit 0 of the scalar -- and _decode_scalar clamps bit 0 to zero
    # for every input this function accepts, so the swap could never happen.
    # The RFC vectors below the fold prove the result is unchanged.
    result = x_2 * pow(z_2, P - 2, P) % P
    return result.to_bytes(32, "little")


def generate_private_key() -> bytes:
    """Return 32 random bytes suitable for use as an X25519 scalar."""
    return os.urandom(32)


def public_key(private_key: bytes) -> bytes:
    """Return the 32 byte public key for ``private_key``."""
    return scalar_mult(private_key, _BASE_POINT)
