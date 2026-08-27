"""RSA signature verification, for DNSSEC RRSIG records (RFC 5702).

RSASSA-PKCS1-v1_5 with SHA-2, the only RSA scheme DNSSEC signs with. It is
public-key math -- a modular exponentiation and a comparison -- so nothing here
is secret. Only verification, never signing. SSH validates no PSS signature, so
this covers PKCS#1 only.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict

#: The DigestInfo DER header that precedes the raw hash in a PKCS#1 v1.5 block.
_DIGEST_INFO: Dict[str, bytes] = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def verify_pkcs1(
    modulus: int, exponent: int, signature: bytes, message: bytes, hash_name: str
) -> bool:
    """Verify an RSASSA-PKCS1-v1_5 signature over ``message``."""
    prefix = _DIGEST_INFO.get(hash_name)
    if prefix is None:
        return False
    key_length = (modulus.bit_length() + 7) // 8
    if len(signature) != key_length or modulus <= 0:
        return False
    opened = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(key_length, "big")
    digest = hashlib.new(hash_name, message).digest()
    padding_length = key_length - 3 - len(prefix) - len(digest)
    if padding_length < 8:  # PKCS#1 requires at least eight 0xFF padding bytes
        return False
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + prefix + digest
    return hmac.compare_digest(opened, expected)
