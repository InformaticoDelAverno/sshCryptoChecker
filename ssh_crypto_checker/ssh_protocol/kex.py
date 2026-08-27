"""Key exchange, driven only as far as the server's host key.

One function per family -- Curve25519, the NIST curves, finite-field
Diffie-Hellman with and without group exchange, and the post-quantum methods --
each sending a well-formed client value and reading the reply. With an
:class:`._ExchangeContext` it also derives the shared secret and exchange hash,
so a caller can go on to open a session; without one it stops at the host key.
"""

from __future__ import annotations

import hashlib
import os
import struct
from typing import Any, Callable, List, Optional

from ..crypto import dh, ecc, x25519
from ..models import KexInit
from .constants import (
    _KEX_HASHES,
    _MLKEM_Q,
    _PQ_KEX_CLIENT_BYTES,
    _SUPPORTED_KEX,
    MSG_KEX_DH_GEX_GROUP,
    MSG_KEX_DH_GEX_INIT,
    MSG_KEX_DH_GEX_REPLY,
    MSG_KEX_DH_GEX_REQUEST,
    MSG_KEX_ECDH_INIT,
    MSG_KEX_ECDH_REPLY,
    MSG_KEXDH_INIT,
    MSG_KEXDH_REPLY,
)
from .transport import SSHTransport, _ExchangeContext, _KexReply
from .wire import Reader, SSHProtocolError, pack_mpint, pack_string


def _kex_hash(kex_name: str) -> Callable[..., Any]:
    """The hash function a key exchange method derives its keys with.

    Named in the method itself for all but the ECDH curves, whose names carry
    the curve rather than the hash. A method that says neither is refused: the
    old answer was "SHA-256 then", which is a guess about which hash a peer is
    using to derive session keys, and a guess that happens to work is
    indistinguishable from one that does not until a packet fails to
    authenticate.
    """
    if kex_name in _KEX_HASHES:
        return _KEX_HASHES[kex_name]
    for suffix, function in (
        ("sha512", hashlib.sha512),
        ("sha384", hashlib.sha384),
        ("sha256", hashlib.sha256),
        ("sha1", hashlib.sha1),
    ):
        if suffix in kex_name:
            return function
    raise SSHProtocolError(
        f"key exchange method '{kex_name}' does not say which hash it derives "
        "keys with, and this scanner will not guess"
    )


def _run_key_exchange(
    transport: SSHTransport,
    kex_name: str,
    context: Optional[_ExchangeContext] = None,
) -> _KexReply:
    """Drive one key exchange until the server reveals its host key.

    When ``context`` is given, the shared secret and exchange hash are computed
    as well, so the caller can derive session keys and continue. Without it the
    connection is only taken far enough to read the host key.
    """
    digest = _kex_hash(kex_name)
    curve = ecc.curve_for_kex(kex_name)

    def finish(
        blob: bytes, tail: bytes, secret: Optional[int], group_bits: Optional[int] = None
    ) -> _KexReply:
        if context is None or secret is None:
            return _KexReply(host_key_blob=blob, dh_group_bits=group_bits)
        exchange_hash = digest(context.prefix(blob) + tail + pack_mpint(secret)).digest()
        return _KexReply(
            host_key_blob=blob,
            dh_group_bits=group_bits,
            shared_secret=secret,
            exchange_hash=exchange_hash,
        )

    if kex_name.startswith("curve25519-sha256"):
        private = x25519.generate_private_key()
        public = x25519.public_key(private)
        transport.send_packet(bytes([MSG_KEX_ECDH_INIT]) + pack_string(public))
        _, payload = transport.read_message(MSG_KEX_ECDH_REPLY)
        reader = Reader(payload)
        reader.read_byte()
        blob = reader.read_string()
        server_public = reader.read_string()
        secret = None
        if context is not None and len(server_public) == 32:
            secret = int.from_bytes(x25519.scalar_mult(private, server_public), "big")
        return finish(blob, pack_string(public) + pack_string(server_public), secret)

    if curve is not None:
        curve_private, public_point = ecc.generate_key_pair(curve)
        transport.send_packet(bytes([MSG_KEX_ECDH_INIT]) + pack_string(public_point))
        _, payload = transport.read_message(MSG_KEX_ECDH_REPLY)
        reader = Reader(payload)
        reader.read_byte()
        blob = reader.read_string()
        server_point = reader.read_string()
        secret = None
        if context is not None:
            shared = curve.multiply(curve_private, _decode_point(curve, server_point))
            secret = shared[0] if shared is not None else None
        return finish(blob, pack_string(public_point) + pack_string(server_point), secret)

    if kex_name.startswith("diffie-hellman-group-exchange"):
        minimum, preferred, maximum = 2048, 3072, 8192
        transport.send_packet(
            bytes([MSG_KEX_DH_GEX_REQUEST]) + struct.pack(">III", minimum, preferred, maximum)
        )
        _, payload = transport.read_message(MSG_KEX_DH_GEX_GROUP)
        reader = Reader(payload)
        reader.read_byte()
        prime = reader.read_mpint()
        generator = reader.read_mpint()
        gex_private, gex_public = dh.generate_key_pair(prime, generator)
        transport.send_packet(bytes([MSG_KEX_DH_GEX_INIT]) + pack_mpint(gex_public))
        _, payload = transport.read_message(MSG_KEX_DH_GEX_REPLY)
        reader = Reader(payload)
        reader.read_byte()
        blob = reader.read_string()
        gex_server_public = reader.read_mpint()
        secret = (
            pow(gex_server_public, gex_private, prime) if context is not None else None
        )
        tail = (
            struct.pack(">III", minimum, preferred, maximum)
            + pack_mpint(prime)
            + pack_mpint(generator)
            + pack_mpint(gex_public)
            + pack_mpint(gex_server_public)
        )
        return finish(blob, tail, secret, prime.bit_length())

    group = dh.group_for_kex(kex_name)
    if group is not None:
        group_private, group_public = dh.generate_key_pair(group.prime, group.generator)
        transport.send_packet(bytes([MSG_KEXDH_INIT]) + pack_mpint(group_public))
        _, payload = transport.read_message(MSG_KEXDH_REPLY)
        reader = Reader(payload)
        reader.read_byte()
        blob = reader.read_string()
        group_server_public = reader.read_mpint()
        secret = (
            pow(group_server_public, group_private, group.prime)
            if context is not None else None
        )
        tail = pack_mpint(group_public) + pack_mpint(group_server_public)
        return finish(blob, tail, secret, group.bits)

    if kex_name in _PQ_KEX_CLIENT_BYTES:
        if context is not None:
            # Deriving a session key would need the KEM itself. Nothing that
            # follows a key exchange -- authentication methods, the config
            # audit -- can run over one of these yet, and pretending otherwise
            # would produce a session that decrypts to noise.
            raise SSHProtocolError(
                f"'{kex_name}' can be used to read a host key but not to open a session, so "
                "checks that need an authenticated connection cannot run against this server"
            )
        transport.send_packet(
            bytes([MSG_KEX_ECDH_INIT]) + pack_string(_pq_client_key(kex_name))
        )
        _, payload = transport.read_message(MSG_KEX_ECDH_REPLY)
        reader = Reader(payload)
        reader.read_byte()
        return finish(reader.read_string(), b"", None)

    raise SSHProtocolError(f"key exchange method '{kex_name}' is not implemented by this scanner")


def _mlkem_encapsulation_key(k: int) -> bytes:
    """A syntactically valid ML-KEM encapsulation key, for one purpose only.

    FIPS 203 has the recipient reject an encapsulation key whose 12-bit
    coefficients are not all below q, which random bytes fail with certainty.
    Choosing the coefficients rather than the bytes satisfies the check.

    Nobody holds the matching decapsulation key and none exists: this buys a
    reply, not a session. It is why the caller refuses to go any further.
    """
    coefficients = [
        int.from_bytes(os.urandom(2), "big") % _MLKEM_Q for _ in range(256 * k)
    ]
    packed = bytearray()
    for index in range(0, len(coefficients), 2):
        low, high = coefficients[index], coefficients[index + 1]
        packed += bytes(
            [low & 0xFF, ((low >> 8) & 0x0F) | ((high & 0x0F) << 4), high >> 4]
        )
    return bytes(packed) + os.urandom(32)


def _pq_client_key(kex_name: str) -> bytes:
    """The client half of a post-quantum key exchange, as bytes on the wire."""
    k, trailing = _PQ_KEX_CLIENT_BYTES[kex_name]
    key = _mlkem_encapsulation_key(k) if k else b""
    return key + os.urandom(trailing)


def _decode_point(curve: ecc.Curve, encoded: bytes) -> ecc.Point:
    """Decode an uncompressed SEC1 point, rejecting anything off the curve."""
    size = curve.byte_length
    if len(encoded) != 1 + 2 * size or encoded[0] != 0x04:
        raise SSHProtocolError("server sent a malformed elliptic curve point")
    point = (
        int.from_bytes(encoded[1 : 1 + size], "big"),
        int.from_bytes(encoded[1 + size :], "big"),
    )
    if not curve.is_on_curve(point):
        raise SSHProtocolError("server sent a point that is not on the negotiated curve")
    return point


def _discard_wrong_guess(
    transport: SSHTransport,
    server_kexinit: KexInit,
    kex_algorithm: str,
    host_key_algorithm: str,
) -> None:
    """Drop a speculative key exchange packet the server guessed wrongly.

    RFC 4253 section 7.1: a peer may set ``first_kex_packet_follows`` and send a
    guessed first key exchange packet. The guess only counts as correct when
    both sides list the same key exchange and host key algorithm first;
    otherwise the packet must be silently ignored. Leaving it in the buffer
    would make us read it as the key exchange reply.
    """
    if not server_kexinit.first_kex_packet_follows:
        return
    guessed_right = (
        server_kexinit.kex_algorithms[:1] == [kex_algorithm]
        and server_kexinit.host_key_algorithms[:1] == [host_key_algorithm]
    )
    if not guessed_right:
        transport.read_message()


def select_kex_for_probe(server_kex_algorithms: List[str]) -> Optional[str]:
    """Pick a key exchange method this scanner can drive against the server.

    Classical methods first: they give a real shared secret, so everything the
    scanner might go on to do still works. A post-quantum method is the last
    resort, and only reaches the host key -- but a server that offers nothing
    else would otherwise be left with no host key inspected at all, and a key
    nobody looked at is how a scan ends up silent about the thing it exists to
    check.
    """
    offered = set(server_kex_algorithms)
    classical = next((name for name in _SUPPORTED_KEX if name in offered), None)
    if classical is not None:
        return classical
    return next((name for name in _PQ_KEX_CLIENT_BYTES if name in offered), None)
