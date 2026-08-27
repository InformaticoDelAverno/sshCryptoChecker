"""Errors and wire-format helpers for the SSH binary packet protocol.

The exception hierarchy every other module raises, the ``printable`` scrub that
every attacker-controlled string passes through before it reaches a terminal,
the ``pack_*`` encoders, the ``Reader`` cursor that eats bytes off a possibly
lying server, and the packet framing. Depends only on the constants.
"""

from __future__ import annotations

import os
import struct
from typing import List

from .constants import MAX_PACKET_SIZE

# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class SSHError(Exception):
    """Base class for every error raised by this module."""


class SSHConnectionError(SSHError):
    """The server could not be reached."""


class SSHProtocolError(SSHError):
    """The server spoke something that is not SSH, or violated the protocol."""


class SSHDisconnectError(SSHProtocolError):
    """The server sent SSH_MSG_DISCONNECT."""


#: The name this had before it gained the suffix every other exception here
#: carries. Kept because it is importable and somebody may be catching it.
SSHDisconnect = SSHDisconnectError


# --------------------------------------------------------------------------- #
# Wire format helpers
# --------------------------------------------------------------------------- #


#: What a terminal would act on rather than show. Escape is the one that
#: matters -- it starts a sequence that can clear the screen, recolour what is
#: already there or move the cursor back over it -- but a bell or a carriage
#: return in the middle of a report is nobody's idea of a name either.
_CONTROL = {c: f"\\x{c:02x}" for c in range(0x20)}
_CONTROL[0x7F] = "\\x7f"
_CONTROL.pop(0x09, None)  # tab is harmless and occasionally meant

#: The same, for text that is still line-structured when it arrives.
_CONTROL_KEEPING_NEWLINES = {c: e for c, e in _CONTROL.items() if c != 0x0A}


def printable(text: str, keep_newlines: bool = False) -> str:
    """Replace control characters in text that came from the peer.

    Everything a scan reports about a server is the server's own words, and
    they are printed to a terminal somebody is watching. A peer that can send
    an escape sequence can write over the report about itself: clear the
    screen, colour a critical finding green, or move the cursor up and replace
    a line that has already scrolled past.

    The characters are shown as their escapes rather than dropped, because a
    name with a bell in it is worth knowing about.

    ``keep_newlines`` is for text that is still going to be split into lines:
    a transcript read from a machine being audited is line-structured, and
    turning its newlines into escapes would leave one very long line that no
    parser downstream would recognise.
    """
    table = _CONTROL_KEEPING_NEWLINES if keep_newlines else _CONTROL
    return text.translate(table)


def pack_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def pack_name_list(names: List[str]) -> bytes:
    return pack_string(",".join(names).encode("ascii"))


def pack_mpint(value: int) -> bytes:
    """Encode an integer in SSH ``mpint`` form (RFC 4251 section 5)."""
    if value == 0:
        return struct.pack(">I", 0)
    if value < 0:
        raise ValueError("negative mpint values are not used by SSH key exchange")
    length = (value.bit_length() + 8) // 8  # leading zero byte when the MSB is set
    return pack_string(value.to_bytes(length, "big"))


class Reader:
    """Cursor over an SSH wire-format buffer."""

    __slots__ = ("_data", "_offset")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    def read_bytes(self, count: int) -> bytes:
        if count < 0 or count > self.remaining:
            raise SSHProtocolError(
                f"truncated packet: wanted {count} bytes, {self.remaining} available"
            )
        chunk = self._data[self._offset : self._offset + count]
        self._offset += count
        return chunk

    def read_byte(self) -> int:
        return self.read_bytes(1)[0]

    def read_bool(self) -> bool:
        return self.read_byte() != 0

    def read_uint32(self) -> int:
        return int(struct.unpack(">I", self.read_bytes(4))[0])

    def read_uint64(self) -> int:
        return int(struct.unpack(">Q", self.read_bytes(8))[0])

    def read_string(self) -> bytes:
        length = self.read_uint32()
        if length > MAX_PACKET_SIZE:
            raise SSHProtocolError(f"implausible string length in packet: {length}")
        return self.read_bytes(length)

    def read_text(self) -> str:
        return printable(self.read_string().decode("utf-8", errors="replace"))

    def read_name_list(self) -> List[str]:
        raw = printable(self.read_string().decode("ascii", errors="replace"))
        return [name for name in raw.split(",") if name]

    def read_mpint(self) -> int:
        raw = self.read_string()
        if not raw:
            return 0
        return int.from_bytes(raw, "big", signed=True)


def _build_body(payload: bytes, block_size: int) -> bytes:
    """Padding length, payload and padding, for encrypt-then-MAC framing.

    Only this part is encrypted there, so only this part is padded to the
    cipher's block size.
    """
    padding = block_size - ((1 + len(payload)) % block_size)
    if padding < 4:
        padding += block_size
    return bytes([padding]) + payload + os.urandom(padding)


def build_packet(payload: bytes, block_size: int = 8) -> bytes:
    """Frame a payload for the binary packet protocol.

    ``block_size`` is 8 before a cipher is in place and the cipher's block size
    afterwards, because the whole packet must be a multiple of it.
    """
    padding = block_size - ((5 + len(payload)) % block_size)
    if padding < 4:
        padding += block_size
    packet_length = 1 + len(payload) + padding
    return struct.pack(">IB", packet_length, padding) + payload + os.urandom(padding)
