"""ChaCha20-Poly1305 in the shape OpenSSH uses it.

OpenSSH's ``chacha20-poly1305@openssh.com`` is not the RFC 8439 AEAD. It takes
512 bits of key material and runs two independent ChaCha20 instances: one keyed
with K_1 encrypts the four-byte packet length, so a receiver can learn how much
to read before it has authenticated anything, and one keyed with K_2 derives a
Poly1305 key from block counter 0 and encrypts the payload from block counter 1
onwards. The tag covers the encrypted length together with the encrypted
payload.

Not constant-time; see the package docstring. The Poly1305 here computes tags
for the packets this scanner sends, and does not verify the server's.
"""

from __future__ import annotations

import struct
from typing import List

__all__ = ["KEY_SIZE", "TAG_SIZE", "ChaCha20", "ChaCha20Poly1305", "poly1305"]

KEY_SIZE = 64
"""OpenSSH derives 64 bytes: K_2 first, then K_1."""

TAG_SIZE = 16

_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_MASK = 0xFFFFFFFF


def _rotate(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & _MASK


def _quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & _MASK
    state[d] = _rotate(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotate(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK
    state[d] = _rotate(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotate(state[b] ^ state[c], 7)


class ChaCha20:
    """The ChaCha20 stream cipher (RFC 8439 section 2.4)."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError(f"ChaCha20 keys are 32 bytes long, got {len(key)}")
        self._key = key

    def block(self, counter: int, nonce: bytes) -> bytes:
        """One 64-byte keystream block."""
        if len(nonce) != 8:
            raise ValueError("SSH uses an 8-byte ChaCha20 nonce")
        state = list(_CONSTANTS)
        state += list(struct.unpack("<8I", self._key))
        # SSH keeps the 64-bit block counter and the 64-bit nonce, which is the
        # original ChaCha layout rather than RFC 8439's 96-bit nonce.
        state += [counter & _MASK, (counter >> 32) & _MASK]
        state += list(struct.unpack("<2I", nonce))

        working = list(state)
        for _ in range(10):  # 20 rounds, as column and diagonal pairs
            _quarter_round(working, 0, 4, 8, 12)
            _quarter_round(working, 1, 5, 9, 13)
            _quarter_round(working, 2, 6, 10, 14)
            _quarter_round(working, 3, 7, 11, 15)
            _quarter_round(working, 0, 5, 10, 15)
            _quarter_round(working, 1, 6, 11, 12)
            _quarter_round(working, 2, 7, 8, 13)
            _quarter_round(working, 3, 4, 9, 14)
        return struct.pack("<16I", *[(a + b) & _MASK for a, b in zip(working, state)])

    def crypt(self, counter: int, nonce: bytes, data: bytes) -> bytes:
        """Encrypt or decrypt, starting at ``counter``."""
        out = bytearray()
        for offset in range(0, len(data), 64):
            chunk = data[offset : offset + 64]
            keystream = self.block(counter + offset // 64, nonce)
            out += bytes(a ^ b for a, b in zip(chunk, keystream))
        return bytes(out)


def poly1305(key: bytes, message: bytes) -> bytes:
    """The Poly1305 one-time authenticator (RFC 8439 section 2.5)."""
    if len(key) != 32:
        raise ValueError(f"Poly1305 keys are 32 bytes long, got {len(key)}")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    prime = (1 << 130) - 5

    accumulator = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset : offset + 16]
        # The high bit marks the end of the block, which is what stops a
        # shorter block from colliding with a longer one.
        accumulator = (accumulator + int.from_bytes(chunk + b"\x01", "little")) % prime
        accumulator = (accumulator * r) % prime
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


class ChaCha20Poly1305:
    """OpenSSH's chacha20-poly1305@openssh.com, one instance per direction."""

    __slots__ = ("_length_key", "_payload_key")

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_SIZE:
            raise ValueError(f"this cipher needs {KEY_SIZE} bytes of key material")
        self._payload_key = ChaCha20(key[:32])  # K_2
        self._length_key = ChaCha20(key[32:])  # K_1

    @staticmethod
    def _nonce(sequence_number: int) -> bytes:
        return struct.pack(">Q", sequence_number)

    def encrypt_length(self, sequence_number: int, length: bytes) -> bytes:
        return self._length_key.crypt(0, self._nonce(sequence_number), length)

    decrypt_length = encrypt_length  # the stream cipher is its own inverse

    def seal(self, sequence_number: int, length: bytes, payload: bytes) -> bytes:
        """Encrypt the length and payload and append the Poly1305 tag."""
        nonce = self._nonce(sequence_number)
        encrypted_length = self._length_key.crypt(0, nonce, length)
        encrypted_payload = self._payload_key.crypt(1, nonce, payload)
        poly_key = self._payload_key.block(0, nonce)[:32]
        packet = encrypted_length + encrypted_payload
        return packet + poly1305(poly_key, packet)

    def decrypt_payload(self, sequence_number: int, payload: bytes) -> bytes:
        return self._payload_key.crypt(1, self._nonce(sequence_number), payload)
