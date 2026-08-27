"""The short-lived, unencrypted SSH transport connection and how to open one.

:class:`SSHTransport` frames, encrypts and reads the binary packets of RFC
4253, far enough to exchange banners, read a KEXINIT and -- once keys are set --
carry a handful of packets. Below it sit the DNS cache and the connect helper
that hand one back, and :class:`_ExchangeContext`, the identification strings
and KEXINIT payloads the exchange hash is bound to.
"""

from __future__ import annotations

import hmac
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, cast

from .. import CLIENT_BANNER
from ..crypto.aes import BLOCK_SIZE as AES_BLOCK_SIZE
from ..crypto.aes import CBC, CTR
from ..crypto.aesgcm import GCM
from ..crypto.chacha import ChaCha20Poly1305
from ..models import BannerInfo, KexInit
from .constants import (
    _CIPHER_IV_SIZES,
    _CIPHER_KEY_SIZES,
    _MAC_SIZES,
    MAX_BANNER_LINE,
    MAX_BANNER_LINES,
    MAX_PACKET_SIZE,
    MSG_DEBUG,
    MSG_DISCONNECT,
    MSG_EXT_INFO,
    MSG_IGNORE,
    MSG_KEXINIT,
    MSG_UNIMPLEMENTED,
)
from .messages import parse_banner, parse_ext_info, parse_kexinit_payload
from .wire import (
    Reader,
    SSHConnectionError,
    SSHDisconnectError,
    SSHProtocolError,
    _build_body,
    build_packet,
    pack_mpint,
    pack_string,
)

# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #


@dataclass
class _KexReply:
    host_key_blob: bytes
    dh_group_bits: Optional[int] = None
    shared_secret: Optional[int] = None
    exchange_hash: Optional[bytes] = None
    """Only computed when the caller needs to continue past the key exchange."""


class SSHTransport:
    """A short-lived, unencrypted SSH transport connection."""

    def __init__(self, sock: socket.socket, peer_address: str) -> None:
        self._sock = sock
        self.peer_address = peer_address
        self._buffer = b""
        self._send_seq = 0
        self._recv_seq = 0
        self._cipher_mode: Optional[str] = None
        self._out_ctr: Optional[CTR] = None
        self._in_ctr: Optional[CTR] = None
        self._out_cbc: Optional[CBC] = None
        self._in_cbc: Optional[CBC] = None
        self._out_gcm: Optional[GCM] = None
        self._in_gcm: Optional[GCM] = None
        self._out_chacha: Optional[ChaCha20Poly1305] = None
        self._in_chacha: Optional[ChaCha20Poly1305] = None
        self._out_mac: Optional[Tuple[bytes, object]] = None
        self._in_mac_length = 0
        self._block_size = 8
        self._encrypt_then_mac = False
        self.extensions: Dict[str, str] = {}
        """RFC 8308 extensions the server announced, such as server-sig-algs."""

    # -- lifecycle -------------------------------------------------------- #

    def close(self) -> None:
        # socket.close() is idempotent and does not raise, so there is nothing
        # to guard against here.
        self._sock.close()

    def __enter__(self) -> SSHTransport:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- raw IO ----------------------------------------------------------- #

    def _recv_into_buffer(self) -> None:
        try:
            chunk = self._sock.recv(16384)
        except socket.timeout as exc:
            raise SSHConnectionError("timed out waiting for data from the server") from exc
        except OSError as exc:
            raise SSHConnectionError(f"connection error: {exc}") from exc
        if not chunk:
            raise SSHConnectionError("server closed the connection unexpectedly")
        self._buffer += chunk

    def _read_exactly(self, count: int) -> bytes:
        while len(self._buffer) < count:
            self._recv_into_buffer()
        data, self._buffer = self._buffer[:count], self._buffer[count:]
        return data

    def _read_line(self) -> str:
        while b"\n" not in self._buffer:
            if len(self._buffer) > MAX_BANNER_LINE:
                raise SSHProtocolError("server sent an over-long line before its banner")
            self._recv_into_buffer()
        line, _, self._buffer = self._buffer.partition(b"\n")
        return line.rstrip(b"\r").decode("utf-8", errors="replace")

    def _send(self, data: bytes) -> None:
        try:
            self._sock.sendall(data)
        except OSError as exc:
            raise SSHConnectionError(f"could not send data: {exc}") from exc

    # -- protocol --------------------------------------------------------- #

    def exchange_banners(self) -> BannerInfo:
        """Send our identification string and read the server's."""
        self._send((CLIENT_BANNER + "\r\n").encode("ascii"))
        pre_banner: List[str] = []
        for _ in range(MAX_BANNER_LINES):
            line = self._read_line()
            if line.startswith("SSH-"):
                banner = parse_banner(line, pre_banner)
                if not banner.protocol_version.startswith(("2.0", "1.99")):
                    raise SSHProtocolError(
                        f"server only speaks SSH protocol {banner.protocol_version!r};"
                        " SSHv1 is obsolete and cannot be audited by this tool"
                    )
                return banner
            pre_banner.append(line)
        raise SSHProtocolError("server never sent an SSH identification string")

    def send_packet(self, payload: bytes) -> None:
        """Frame, encrypt and authenticate one packet in the negotiated mode."""
        if self._cipher_mode is None:
            self._send(build_packet(payload, self._block_size))
        elif self._cipher_mode == "chacha20":
            body = _build_body(payload, 8)
            chacha = cast(ChaCha20Poly1305, self._out_chacha)
            self._send(chacha.seal(self._send_seq, struct.pack(">I", len(body)), body))
        elif self._cipher_mode == "gcm":
            # The length is authenticated but not encrypted, and only the body
            # is padded to the block size.
            body = _build_body(payload, AES_BLOCK_SIZE)
            header = struct.pack(">I", len(body))
            out_gcm = cast(GCM, self._out_gcm)
            self._send(header + out_gcm.seal(header, body))
            out_gcm.advance()
        elif self._encrypt_then_mac:
            body = _build_body(payload, self._block_size)
            wire = struct.pack(">I", len(body)) + self._encrypt(body)
            self._send(wire + self._mac(wire))
        else:
            packet = build_packet(payload, self._block_size)
            self._send(self._encrypt(packet) + self._mac(packet))
        self._send_seq = (self._send_seq + 1) & 0xFFFFFFFF

    def _encrypt(self, data: bytes) -> bytes:
        if self._cipher_mode == "cbc":
            return cast(CBC, self._out_cbc).encrypt(data)
        return cast(CTR, self._out_ctr).update(data)

    def _decrypt(self, data: bytes) -> bytes:
        if self._cipher_mode == "cbc":
            return cast(CBC, self._in_cbc).decrypt(data)
        return cast(CTR, self._in_ctr).update(data)

    def _mac(self, data: bytes) -> bytes:
        if self._out_mac is None:
            return b""
        key, digest = self._out_mac
        return bytes(hmac.new(
            key, struct.pack(">I", self._send_seq) + data, cast(Any, digest)
        ).digest())

    def read_packet(self) -> bytes:
        """Read one binary packet and return its payload."""
        if self._cipher_mode is None:
            (packet_length,) = struct.unpack(">I", self._read_exactly(4))
            self._check_length(packet_length)
            body = self._read_exactly(packet_length)
        elif self._cipher_mode == "chacha20":
            encrypted_length = self._read_exactly(4)
            (packet_length,) = struct.unpack(
                ">I",
                cast(ChaCha20Poly1305, self._in_chacha).decrypt_length(
                    self._recv_seq, encrypted_length
                ),
            )
            self._check_length(packet_length)
            body = cast(ChaCha20Poly1305, self._in_chacha).decrypt_payload(
                self._recv_seq, self._read_exactly(packet_length)
            )
            self._read_exactly(16)  # Poly1305 tag
        elif self._cipher_mode == "gcm":
            (packet_length,) = struct.unpack(">I", self._read_exactly(4))
            self._check_length(packet_length)
            in_gcm = cast(GCM, self._in_gcm)
            body = in_gcm.open(b"", self._read_exactly(packet_length))
            self._read_exactly(GCM.TAG_SIZE)
            in_gcm.advance()
        elif self._encrypt_then_mac:
            (packet_length,) = struct.unpack(">I", self._read_exactly(4))
            self._check_length(packet_length)
            body = self._decrypt(self._read_exactly(packet_length))
            self._read_exactly(self._in_mac_length)
        else:
            # The length field is encrypted too, so one cipher block has to be
            # decrypted before the length is known.
            first = self._decrypt(self._read_exactly(self._block_size))
            (packet_length,) = struct.unpack(">I", first[:4])
            self._check_length(packet_length)
            remaining = packet_length + 4 - self._block_size
            body = first[4:] + self._decrypt(self._read_exactly(remaining))
            self._read_exactly(self._in_mac_length)

        self._recv_seq = (self._recv_seq + 1) & 0xFFFFFFFF
        padding_length = body[0]
        if padding_length + 1 > len(body):
            raise SSHProtocolError("packet padding is longer than the packet itself")
        return body[1 : len(body) - padding_length]

    @staticmethod
    def _check_length(packet_length: int) -> None:
        if not 8 <= packet_length <= MAX_PACKET_SIZE:
            raise SSHProtocolError(
                f"implausible packet length {packet_length}; this does not look like an SSH server"
            )

    def enable_encryption(
        self,
        cipher_name: str,
        mac_name: Optional[str],
        shared_secret: int,
        exchange_hash: bytes,
        hash_function: Callable[..., Any],
    ) -> None:
        """Switch both directions to the negotiated cipher (RFC 4253 section 7.2).

        The scanner does not verify the server's MACs or tags: it reads a
        name-list and hangs up, and never acts on the contents.
        """
        key_size = _CIPHER_KEY_SIZES[cipher_name]
        iv_size = _CIPHER_IV_SIZES.get(cipher_name, AES_BLOCK_SIZE)
        secret = pack_mpint(shared_secret)

        def derive(letter: bytes, size: int) -> bytes:
            material = bytes(
                hash_function(secret + exchange_hash + letter + exchange_hash).digest()
            )
            while len(material) < size:
                material += hash_function(secret + exchange_hash + material).digest()
            return material[:size]

        if cipher_name == "chacha20-poly1305@openssh.com":
            self._cipher_mode = "chacha20"
            self._out_chacha = ChaCha20Poly1305(derive(b"C", key_size))
            self._in_chacha = ChaCha20Poly1305(derive(b"D", key_size))
            self._block_size = 8
            return
        if cipher_name in {"aes256-gcm@openssh.com", "aes128-gcm@openssh.com"}:
            self._cipher_mode = "gcm"
            self._out_gcm = GCM(derive(b"C", key_size), derive(b"A", iv_size))
            self._in_gcm = GCM(derive(b"D", key_size), derive(b"B", iv_size))
            self._block_size = AES_BLOCK_SIZE
            return

        if cipher_name.endswith("-cbc"):
            self._cipher_mode = "cbc"
            self._out_cbc = CBC(derive(b"C", key_size), derive(b"A", iv_size))
            self._in_cbc = CBC(derive(b"D", key_size), derive(b"B", iv_size))
        else:
            self._cipher_mode = "ctr"
            self._out_ctr = CTR(derive(b"C", key_size), derive(b"A", iv_size))
            self._in_ctr = CTR(derive(b"D", key_size), derive(b"B", iv_size))

        assert mac_name is not None, "a non-AEAD cipher needs a MAC"
        mac_size, mac_digest = _MAC_SIZES[mac_name]
        self._out_mac = (derive(b"E", mac_size), mac_digest)
        self._in_mac_length = mac_size
        self._block_size = AES_BLOCK_SIZE
        self._encrypt_then_mac = mac_name.endswith("-etm@openssh.com")

    def read_message(self, expected: Optional[int] = None) -> Tuple[int, bytes]:
        """Read packets until an interesting one arrives.

        ``SSH_MSG_IGNORE``, ``SSH_MSG_DEBUG`` and ``SSH_MSG_UNIMPLEMENTED`` are
        transparently skipped; ``SSH_MSG_DISCONNECT`` raises.
        """
        for _ in range(32):
            payload = self.read_packet()
            if not payload:
                continue
            message_type = payload[0]
            if message_type in {MSG_IGNORE, MSG_DEBUG, MSG_UNIMPLEMENTED}:
                continue
            if message_type == MSG_EXT_INFO and expected != MSG_EXT_INFO:
                # RFC 8308 extension negotiation, sent right after NEWKEYS.
                # Record it and keep looking for what the caller wanted.
                self.extensions.update(parse_ext_info(payload))
                continue
            if message_type == MSG_DISCONNECT:
                raise SSHDisconnectError(_describe_disconnect(payload))
            if expected is not None and message_type != expected:
                raise SSHProtocolError(
                    f"expected message type {expected}, got {message_type}"
                )
            return message_type, payload
        raise SSHProtocolError("server kept sending filler messages")

    def read_kexinit(self) -> KexInit:
        return self.read_kexinit_raw()[0]

    def read_kexinit_raw(self) -> Tuple[KexInit, bytes]:
        """Read the server's KEXINIT and keep the raw payload.

        The exchange hash is computed over the payload exactly as it arrived,
        so it cannot be reconstructed from the parsed form.
        """
        _, payload = self.read_message(MSG_KEXINIT)
        return parse_kexinit_payload(payload), payload


def _describe_disconnect(payload: bytes) -> str:
    reasons = {
        1: "host not allowed to connect",
        2: "protocol error",
        3: "key exchange failed",
        4: "reserved",
        5: "MAC error",
        6: "compression error",
        7: "service not available",
        8: "protocol version not supported",
        9: "host key not verifiable",
        10: "connection lost",
        11: "disconnected by application",
        12: "too many connections",
        13: "authentication cancelled by user",
        14: "no more authentication methods available",
        15: "illegal user name",
    }
    try:
        reader = Reader(payload)
        reader.read_byte()
        code = reader.read_uint32()
        description = reader.read_text()
    except SSHProtocolError:
        return "server disconnected without a reason code"
    reason = reasons.get(code, f"reason {code}")
    detail = f": {description}" if description else ""
    return f"server disconnected ({reason}){detail}"


# --------------------------------------------------------------------------- #
# Connection helpers
# --------------------------------------------------------------------------- #


#: Resolutions are cached for this long. A scan of a large inventory hits the
#: same names repeatedly -- several checks per target, and often many targets in
#: one domain -- and a resolver outage part-way through a run would otherwise
#: turn a clean report into a wall of unrelated failures. It is short enough
#: that a deliberate DNS change during a scan still takes effect on the next
#: run rather than being pinned for the session.
DNS_CACHE_TTL = 300.0

_dns_cache: Dict[Tuple[str, int, int], Tuple[float, Any]] = {}
_dns_lock = threading.Lock()


def clear_dns_cache() -> None:
    """Forget every cached resolution."""
    with _dns_lock:
        _dns_cache.clear()


def _resolve(host: str, port: int, family: int) -> List[Any]:
    """``socket.getaddrinfo`` with a short-lived cache.

    Failures are cached too, and for the same reason: a name that does not
    resolve will not resolve on the next check either, and re-asking a dead
    resolver once per check is how a scan turns into a timeout.
    """
    key = (host, port, family)
    now = time.monotonic()
    with _dns_lock:
        entry = _dns_cache.get(key)
        if entry is not None and entry[0] > now:
            cached = entry[1]
            if isinstance(cached, Exception):
                raise cached
            return cast(List[Any], cached)

    try:
        candidates = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except UnicodeError as exc:
        # A name getaddrinfo will not even encode: an empty label from a
        # doubled dot, or one over 63 characters. It raises UnicodeEncodeError
        # rather than gaierror, so it used to escape as "internal error
        # scanning this target" -- which reads as a fault in this tool rather
        # than a bad line in somebody's inventory.
        failure = socket.gaierror(f"not a usable host name: {exc}")
        with _dns_lock:
            _dns_cache[key] = (now + DNS_CACHE_TTL, failure)
        raise failure from exc
    except socket.gaierror as exc:
        with _dns_lock:
            _dns_cache[key] = (now + DNS_CACHE_TTL, exc)
        raise

    with _dns_lock:
        _dns_cache[key] = (now + DNS_CACHE_TTL, candidates)
    return candidates


def _connect(
    host: str,
    port: int,
    timeout: float,
    family: int = socket.AF_UNSPEC,
    source_address: Optional[str] = None,
) -> SSHTransport:
    # ``_resolve`` is reached through the package so a test that patches
    # ``ssh_protocol._resolve`` still governs the address list a connection is
    # built from, exactly as it did when this lived in one module.
    from . import _resolve

    try:
        candidates = _resolve(host, port, family)
    except socket.gaierror as exc:
        raise SSHConnectionError(f"cannot resolve '{host}': {exc.strerror or exc}") from exc
    if not candidates:
        raise SSHConnectionError(f"cannot resolve '{host}': no addresses returned")

    last_error: Optional[Exception] = None
    for af, socktype, proto, _canonname, sockaddr in candidates:
        sock = socket.socket(af, socktype, proto)
        try:
            sock.settimeout(timeout)
            if source_address:
                sock.bind((source_address, 0))
            sock.connect(sockaddr)
        except OSError as exc:
            sock.close()
            last_error = exc
            continue
        return SSHTransport(sock, str(sockaddr[0]))

    detail = getattr(last_error, "strerror", None) or str(last_error)
    raise SSHConnectionError(f"cannot connect to {host}:{port}: {detail}")


# --------------------------------------------------------------------------- #
# Key exchange context
# --------------------------------------------------------------------------- #


@dataclass
class _ExchangeContext:
    """The identification strings and KEXINIT payloads the hash is bound to."""

    client_banner: str
    server_banner: str
    client_kexinit: bytes
    server_kexinit: bytes

    def prefix(self, host_key_blob: bytes) -> bytes:
        return (
            pack_string(self.client_banner.encode())
            + pack_string(self.server_banner.encode())
            + pack_string(self.client_kexinit)
            + pack_string(self.server_kexinit)
            + pack_string(host_key_blob)
        )
