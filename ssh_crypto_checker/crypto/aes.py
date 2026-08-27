"""AES in the modes SSH uses: counter (CTR) and cipher block chaining (CBC).

Counter mode needs only the forward block transform, in both directions.
CBC decryption needs the inverse cipher. AES-GCM lives beside this, in
aesgcm.py, so a server offering neither CTR nor ChaCha20 can still be asked
which authentication methods it accepts.

Not constant-time; see the package docstring.
"""

from __future__ import annotations

from typing import List

__all__ = ["AES", "BLOCK_SIZE", "CBC", "CTR"]

BLOCK_SIZE = 16

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

#: Round constants for the key schedule.
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D)


def _build_inverse_sbox() -> bytes:
    table = bytearray(256)
    for index, value in enumerate(_SBOX):
        table[value] = index
    return bytes(table)


def _xtime(value: int) -> int:
    """Multiply by x in GF(2^8), reducing by the AES polynomial."""
    value <<= 1
    return (value ^ 0x1B) & 0xFF if value & 0x100 else value


_INV_SBOX = _build_inverse_sbox()


def _multiply(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8), the field AES's MixColumns works over."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        b >>= 1
        a = _xtime(a)
    return result


class AES:
    """AES-128, AES-192 or AES-256 block encryption."""

    __slots__ = ("_round_keys", "_rounds")

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError(f"AES keys are 16, 24 or 32 bytes long, got {len(key)}")
        self._rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        self._round_keys = self._expand_key(key)

    @staticmethod
    def _expand_key(key: bytes) -> List[List[int]]:
        """Rijndael key schedule, producing 4-byte words."""
        key_words = len(key) // 4
        total_words = 4 * ({16: 10, 24: 12, 32: 14}[len(key)] + 1)
        words = [list(key[i * 4 : i * 4 + 4]) for i in range(key_words)]

        for index in range(key_words, total_words):
            word = list(words[index - 1])
            if index % key_words == 0:
                word = word[1:] + word[:1]  # RotWord
                word = [_SBOX[b] for b in word]  # SubWord
                word[0] ^= _RCON[index // key_words - 1]
            elif key_words > 6 and index % key_words == 4:
                word = [_SBOX[b] for b in word]
            words.append([a ^ b for a, b in zip(words[index - key_words], word)])
        return words

    def _add_round_key(self, state: List[int], round_index: int) -> None:
        base = round_index * 4
        for column in range(4):
            word = self._round_keys[base + column]
            for row in range(4):
                state[column * 4 + row] ^= word[row]

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt exactly one 16-byte block."""
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"AES blocks are {BLOCK_SIZE} bytes long, got {len(block)}")
        state = list(block)
        self._add_round_key(state, 0)

        for round_index in range(1, self._rounds + 1):
            state = [_SBOX[b] for b in state]

            # ShiftRows: the state is column-major, so row r rotates left by r.
            shifted = list(state)
            for row in range(1, 4):
                for column in range(4):
                    shifted[column * 4 + row] = state[((column + row) % 4) * 4 + row]
            state = shifted

            if round_index != self._rounds:  # MixColumns, omitted in the last round
                for column in range(4):
                    offset = column * 4
                    a0, a1, a2, a3 = state[offset : offset + 4]
                    parity = a0 ^ a1 ^ a2 ^ a3
                    state[offset] = a0 ^ parity ^ _xtime(a0 ^ a1)
                    state[offset + 1] = a1 ^ parity ^ _xtime(a1 ^ a2)
                    state[offset + 2] = a2 ^ parity ^ _xtime(a2 ^ a3)
                    state[offset + 3] = a3 ^ parity ^ _xtime(a3 ^ a0)

            self._add_round_key(state, round_index)
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt exactly one 16-byte block, for CBC mode."""
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"AES blocks are {BLOCK_SIZE} bytes long, got {len(block)}")
        state = list(block)
        self._add_round_key(state, self._rounds)

        for round_index in range(self._rounds - 1, -1, -1):
            # InvShiftRows: row r rotates right by r.
            shifted = list(state)
            for row in range(1, 4):
                for column in range(4):
                    shifted[((column + row) % 4) * 4 + row] = state[column * 4 + row]
            state = [_INV_SBOX[b] for b in shifted]
            self._add_round_key(state, round_index)

            if round_index != 0:  # InvMixColumns, omitted after the last round
                for column in range(4):
                    offset = column * 4
                    a0, a1, a2, a3 = state[offset : offset + 4]
                    state[offset] = (
                        _multiply(a0, 14) ^ _multiply(a1, 11) ^ _multiply(a2, 13) ^ _multiply(a3, 9)
                    )
                    state[offset + 1] = (
                        _multiply(a0, 9) ^ _multiply(a1, 14) ^ _multiply(a2, 11) ^ _multiply(a3, 13)
                    )
                    state[offset + 2] = (
                        _multiply(a0, 13) ^ _multiply(a1, 9) ^ _multiply(a2, 14) ^ _multiply(a3, 11)
                    )
                    state[offset + 3] = (
                        _multiply(a0, 11) ^ _multiply(a1, 13) ^ _multiply(a2, 9) ^ _multiply(a3, 14)
                    )
        return bytes(state)


class CTR:
    """Counter mode over AES, as SSH uses it (RFC 4344).

    The same object encrypts or decrypts: counter mode is symmetric. One
    instance must be used per direction, because the counter is stateful.
    """

    __slots__ = ("_cipher", "_counter", "_keystream")

    def __init__(self, key: bytes, initial_counter: bytes) -> None:
        if len(initial_counter) != BLOCK_SIZE:
            raise ValueError("the initial counter block must be 16 bytes")
        self._cipher = AES(key)
        self._counter = int.from_bytes(initial_counter, "big")
        self._keystream = b""

    def _next_keystream_block(self) -> bytes:
        block = self._cipher.encrypt_block(self._counter.to_bytes(BLOCK_SIZE, "big"))
        self._counter = (self._counter + 1) % (1 << (BLOCK_SIZE * 8))
        return block

    def update(self, data: bytes) -> bytes:
        """Encrypt or decrypt ``data``, advancing the counter."""
        while len(self._keystream) < len(data):
            self._keystream += self._next_keystream_block()
        keystream, self._keystream = self._keystream[: len(data)], self._keystream[len(data) :]
        return bytes(a ^ b for a, b in zip(data, keystream))


class CBC:
    """Cipher block chaining, as SSH uses it (RFC 4253).

    The chaining state carries between packets, so one instance is needed per
    direction and it must see every block in order.
    """

    __slots__ = ("_cipher", "_decrypt_iv", "_encrypt_iv")

    def __init__(self, key: bytes, iv: bytes) -> None:
        if len(iv) != BLOCK_SIZE:
            raise ValueError("the CBC initialisation vector must be 16 bytes")
        self._cipher = AES(key)
        self._encrypt_iv = iv
        self._decrypt_iv = iv

    def encrypt(self, data: bytes) -> bytes:
        if len(data) % BLOCK_SIZE:
            raise ValueError("CBC input must be a whole number of blocks")
        out = bytearray()
        previous = self._encrypt_iv
        for offset in range(0, len(data), BLOCK_SIZE):
            block = data[offset : offset + BLOCK_SIZE]
            previous = self._cipher.encrypt_block(
                bytes(a ^ b for a, b in zip(block, previous))
            )
            out += previous
        self._encrypt_iv = previous
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) % BLOCK_SIZE:
            raise ValueError("CBC input must be a whole number of blocks")
        out = bytearray()
        previous = self._decrypt_iv
        for offset in range(0, len(data), BLOCK_SIZE):
            block = data[offset : offset + BLOCK_SIZE]
            out += bytes(a ^ b for a, b in zip(self._cipher.decrypt_block(block), previous))
            previous = block
        self._decrypt_iv = previous
        return bytes(out)
