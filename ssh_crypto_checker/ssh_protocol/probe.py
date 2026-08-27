"""The public probes: what a scan actually calls against a server.

The banner-and-KEXINIT probe, host key retrieval, the opt-in authentication
method enumeration that opens a real encrypted session, and the two timing
measurements (login grace and MaxStartups). ``_connect`` and
``_run_key_exchange`` are reached through the package so a test that patches
``ssh_protocol._connect`` or ``ssh_protocol._run_key_exchange`` still governs
these, exactly as it did when the whole client lived in one module.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import List, Optional, Tuple

from .. import CLIENT_BANNER
from ..models import AuthMethods, BannerInfo, HostKeyInfo, KexInit
from .constants import (
    _AEAD_CIPHERS,
    _SESSION_CIPHERS,
    _SESSION_MACS,
    MSG_NEWKEYS,
    MSG_SERVICE_ACCEPT,
    MSG_SERVICE_REQUEST,
    MSG_USERAUTH_BANNER,
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_REQUEST,
    MSG_USERAUTH_SUCCESS,
    STRICT_KEX_CLIENT,
)
from .kex import _discard_wrong_guess, _kex_hash
from .messages import _build_client_kexinit, parse_host_key_blob
from .transport import SSHTransport, _ExchangeContext
from .wire import Reader, SSHError, SSHProtocolError, pack_string

# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def probe_server(
    host: str,
    port: int,
    timeout: float = 5.0,
    family: int = socket.AF_UNSPEC,
    source_address: Optional[str] = None,
) -> Tuple[BannerInfo, KexInit, str]:
    """Connect and return the server's banner, its KEXINIT and its address."""
    from . import _connect

    with _connect(host, port, timeout, family, source_address) as transport:
        banner = transport.exchange_banners()
        kexinit = transport.read_kexinit()
        return banner, kexinit, transport.peer_address


def fetch_host_key(
    host: str,
    port: int,
    host_key_algorithm: str,
    kex_algorithm: str,
    timeout: float = 5.0,
    family: int = socket.AF_UNSPEC,
    source_address: Optional[str] = None,
) -> HostKeyInfo:
    """Run a key exchange and return the host key the server presents.

    A dedicated connection is used for each host key algorithm, because the
    algorithm is fixed by the client's proposal at the start of the exchange.
    """
    from . import _connect, _run_key_exchange

    try:
        with _connect(host, port, timeout, family, source_address) as transport:
            transport.exchange_banners()
            transport.send_packet(
                _build_client_kexinit(
                    [kex_algorithm, STRICT_KEX_CLIENT, "ext-info-c"], [host_key_algorithm]
                )
            )
            server_kexinit = transport.read_kexinit()
            if host_key_algorithm not in server_kexinit.host_key_algorithms:
                raise SSHProtocolError(
                    f"server no longer offers host key algorithm '{host_key_algorithm}'"
                )
            _discard_wrong_guess(transport, server_kexinit, kex_algorithm, host_key_algorithm)
            reply = _run_key_exchange(transport, kex_algorithm)
    except SSHError as exc:
        return HostKeyInfo(algorithm=host_key_algorithm, kex_used=kex_algorithm, error=str(exc))
    except (ValueError, struct.error, OSError) as exc:
        # A hostile or broken server can feed values the primitives reject (for
        # example an unusable group-exchange modulus). That must cost us this
        # one host key, not the whole audit of an otherwise reachable server.
        return HostKeyInfo(
            algorithm=host_key_algorithm,
            kex_used=kex_algorithm,
            error=f"key exchange failed: {exc}",
        )

    info = parse_host_key_blob(reply.host_key_blob, host_key_algorithm)
    info.kex_used = kex_algorithm
    info.dh_group_bits = reply.dh_group_bits
    return info


# --------------------------------------------------------------------------- #
# Authentication method enumeration
# --------------------------------------------------------------------------- #


def probe_auth_methods(
    host: str,
    port: int,
    kex_algorithm: str,
    host_key_algorithm: str,
    username: str = "sshcryptochecker",
    timeout: float = 5.0,
    family: int = socket.AF_UNSPEC,
    source_address: Optional[str] = None,
) -> AuthMethods:
    """Ask the server which authentication methods it accepts.

    This is the only check that requires a fully established encrypted session:
    the method list travels in ``SSH_MSG_USERAUTH_FAILURE``, which the server
    only sends after ``SSH_MSG_NEWKEYS``. The scanner authenticates with the
    ``none`` method, which is designed to be rejected and to return the list of
    methods that could continue.

    Unlike the rest of the scan this leaves a failed-authentication record in
    the server's log, so it is opt-in.
    """
    from . import _connect, _run_key_exchange

    result = AuthMethods(username=username)
    try:
        with _connect(host, port, timeout, family, source_address) as transport:
            banner = transport.exchange_banners()
            # Strict key exchange is deliberately not requested: it would reset
            # the packet sequence numbers after NEWKEYS, and the scanner has no
            # reason to exercise that path.
            # ext-info-c asks the server for its RFC 8308 extensions, which
            # is the only way to see which signature algorithms it will accept
            # for client authentication.
            client_kexinit = _build_client_kexinit(
                [kex_algorithm, "ext-info-c"],
                [host_key_algorithm],
                _SESSION_CIPHERS,
                _SESSION_MACS,
            )
            transport.send_packet(client_kexinit)
            server_kexinit, server_kexinit_raw = transport.read_kexinit_raw()

            cipher = _negotiate(_SESSION_CIPHERS, server_kexinit.encryption_s2c)
            if cipher is None:
                raise SSHProtocolError(
                    "server offers no cipher this scanner can drive, so its authentication "
                    "methods cannot be read"
                )
            # An AEAD cipher authenticates on its own; only the others need a MAC.
            mac = None
            if cipher not in _AEAD_CIPHERS:
                mac = _negotiate(_SESSION_MACS, server_kexinit.mac_s2c)
                if mac is None:
                    raise SSHProtocolError(
                        f"server offers no MAC this scanner can pair with {cipher}, so its "
                        "authentication methods cannot be read"
                    )

            reply = _run_key_exchange(
                transport,
                kex_algorithm,
                _ExchangeContext(
                    client_banner=CLIENT_BANNER,
                    server_banner=banner.exact,
                    client_kexinit=client_kexinit,
                    server_kexinit=server_kexinit_raw,
                ),
            )
            if reply.shared_secret is None or reply.exchange_hash is None:
                raise SSHProtocolError("could not complete the key exchange")

            transport.send_packet(bytes([MSG_NEWKEYS]))
            transport.read_message(MSG_NEWKEYS)
            transport.enable_encryption(
                cipher, mac, reply.shared_secret, reply.exchange_hash, _kex_hash(kex_algorithm)
            )

            transport.send_packet(
                bytes([MSG_SERVICE_REQUEST]) + pack_string(b"ssh-userauth")
            )
            transport.read_message(MSG_SERVICE_ACCEPT)

            transport.send_packet(
                bytes([MSG_USERAUTH_REQUEST])
                + pack_string(username.encode())
                + pack_string(b"ssh-connection")
                + pack_string(b"none")
            )
            result.methods, result.accepted_without_credentials = _read_auth_response(transport)
            signature_algorithms = transport.extensions.get("server-sig-algs", "")
            result.server_sig_algs = [a for a in signature_algorithms.split(",") if a]
            result.extensions = dict(transport.extensions)
    except SSHError as exc:
        result.error = str(exc)
    except (ValueError, struct.error, OSError) as exc:
        result.error = f"authentication probe failed: {exc}"
    return result


def _negotiate(client_preference: List[str], server_offer: List[str]) -> Optional[str]:
    """The first client algorithm the server also supports (RFC 4253 section 7.1)."""
    offered = set(server_offer)
    return next((name for name in client_preference if name in offered), None)


def _read_auth_response(transport: SSHTransport) -> Tuple[List[str], bool]:
    """Read the reply to the ``none`` authentication attempt."""
    for _ in range(8):
        message_type, payload = transport.read_message()
        if message_type == MSG_USERAUTH_BANNER:
            continue  # a legal banner, shown before authentication
        if message_type == MSG_USERAUTH_FAILURE:
            reader = Reader(payload)
            reader.read_byte()
            return reader.read_name_list(), False
        if message_type == MSG_USERAUTH_SUCCESS:
            # The server accepted the "none" method: it grants access with no
            # credentials whatsoever.
            return [], True
        raise SSHProtocolError(
            f"unexpected message type {message_type} in reply to the authentication request"
        )
    raise SSHProtocolError("server kept sending banners instead of an authentication reply")


def measure_login_grace(
    host: str,
    port: int,
    maximum_wait: float = 130.0,
    connect_timeout: float = 5.0,
    family: int = socket.AF_UNSPEC,
    source_address: Optional[str] = None,
) -> Optional[float]:
    """Time how long the server tolerates an unauthenticated connection.

    This is ``LoginGraceTime`` observed from outside. It is worth knowing
    because the documented stop-gap for regreSSHion (CVE-2024-6387) is to set
    it to 0, which disables the timeout entirely and trades the vulnerability
    for a denial-of-service exposure.

    Returns the measured seconds, or ``None`` if the server was still holding
    the connection open after ``maximum_wait``. The wait is mostly idle, so
    running it across many hosts concurrently costs little more than one host.
    """
    from . import _connect

    started = time.monotonic()
    try:
        with _connect(host, port, connect_timeout, family, source_address) as transport:
            transport.exchange_banners()
            transport._sock.settimeout(maximum_wait)
            while True:
                elapsed = time.monotonic() - started
                if elapsed >= maximum_wait:
                    return None
                try:
                    if not transport._sock.recv(4096):
                        return round(time.monotonic() - started, 1)
                except socket.timeout:
                    return None
    except SSHError:
        return None
    except OSError:
        # A reset counts as the server hanging up on us.
        return round(time.monotonic() - started, 1)


def measure_max_startups(
    host: str,
    port: int,
    limit: int = 20,
    timeout: float = 5.0,
    family: int = socket.AF_UNSPEC,
) -> Optional[int]:
    """How many unauthenticated connections the server holds open at once.

    This is ``MaxStartups`` seen from outside. It matters because those slots
    are what an attacker exhausts to lock real users out, and because a long
    LoginGraceTime makes each slot cheaper to hold.

    The probe opens connections until the server stops answering or ``limit``
    is reached, then closes them all. That is a small, deliberate denial of
    service against the target, which is why it is opt-in and capped.

    Returns the number accepted, or ``None`` if the limit was reached without
    the server refusing, meaning its threshold is higher than we probed for.
    """
    from . import _connect

    transports: List[SSHTransport] = []
    try:
        for _ in range(limit):
            try:
                transport = _connect(host, port, timeout, family)
            except SSHError:
                return len(transports)
            # Recorded before the banner exchange rather than after it. A
            # server at its limit accepts the TCP connection and then goes
            # quiet, so the failure lands here with a socket already open;
            # tracking it first is what gets it closed instead of left to the
            # garbage collector. It is not counted as an accepted slot.
            transports.append(transport)
            try:
                transport.exchange_banners()
            except SSHError:
                return len(transports) - 1
        return None
    finally:
        for transport in transports:
            transport.close()
