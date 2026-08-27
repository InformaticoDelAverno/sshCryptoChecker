"""AES in Galois/counter mode (AES-GCM), as SSH uses it (RFC 5647).

Split out of aes.py: AES and its block modes live there, AES-GCM here. GCH
multiply-accumulates in GF(2^128); it builds on the AES block transform next
door. Not constant-time; see the package docstring.
"""

from __future__ import annotations

from .aes import AES, BLOCK_SIZE

__all__ = ["GCM"]


def _ghash(key: int, data: bytes) -> int:
    """GHASH: multiply-accumulate in GF(2^128), the field GCM authenticates in."""
    result = 0
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE].ljust(BLOCK_SIZE, b"\x00")
        result ^= int.from_bytes(block, "big")
        # Multiplication with the GCM bit ordering: bit 127 is the most
        # significant, and the reduction polynomial is x^128 + x^7 + x^2 + x + 1.
        product = 0
        value = result
        for bit in range(128):
            if key >> (127 - bit) & 1:
                product ^= value
            if value & 1:
                value = (value >> 1) ^ (0xE1 << 120)
            else:
                value >>= 1
        result = product
    return result


class GCM:
    """AES in Galois/counter mode, as SSH uses it (RFC 5647).

    In SSH the packet length is authenticated but not encrypted, and the
    invocation counter advances once per packet rather than per call.
    """

    __slots__ = ("_cipher", "_fixed", "_hash_key", "_invocation")

    TAG_SIZE = 16

    def __init__(self, key: bytes, iv: bytes) -> None:
        if len(iv) != 12:
            raise ValueError("the GCM initialisation vector must be 12 bytes")
        self._cipher = AES(key)
        self._hash_key = int.from_bytes(self._cipher.encrypt_block(bytes(BLOCK_SIZE)), "big")
        self._fixed = iv[:4]
        self._invocation = int.from_bytes(iv[4:], "big")

    def _nonce(self) -> bytes:
        return self._fixed + self._invocation.to_bytes(8, "big")

    def advance(self) -> None:
        """Move to the next packet's invocation counter."""
        self._invocation = (self._invocation + 1) % (1 << 64)

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        stream = b""
        counter = 2  # counter 1 is reserved for the tag mask
        while len(stream) < length:
            stream += self._cipher.encrypt_block(nonce + counter.to_bytes(4, "big"))
            counter += 1
        return stream[:length]

    def _tag(self, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
        padded_aad = aad + b"\x00" * (-len(aad) % BLOCK_SIZE)
        padded_ct = ciphertext + b"\x00" * (-len(ciphertext) % BLOCK_SIZE)
        digest = _ghash(self._hash_key, padded_aad + padded_ct + lengths)
        mask = self._cipher.encrypt_block(nonce + (1).to_bytes(4, "big"))
        return bytes(a ^ b for a, b in zip(digest.to_bytes(BLOCK_SIZE, "big"), mask))

    def seal(self, aad: bytes, plaintext: bytes) -> bytes:
        """Encrypt and authenticate, returning ciphertext concatenated with the tag."""
        nonce = self._nonce()
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, self._keystream(nonce, len(plaintext))))
        return ciphertext + self._tag(nonce, aad, ciphertext)

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        """Decrypt, without verifying the tag.

        The scanner reads a name-list and hangs up; it never acts on the
        contents, so authenticating the server's packets would buy nothing.
        """
        nonce = self._nonce()
        return bytes(a ^ b for a, b in zip(ciphertext, self._keystream(nonce, len(ciphertext))))
