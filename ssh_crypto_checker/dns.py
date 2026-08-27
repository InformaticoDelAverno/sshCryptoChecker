"""A minimal DNS client, just enough to look up SSHFP records.

SSHFP (RFC 4255) publishes host key fingerprints in DNS so a client can verify
a server it has never seen before, instead of accepting the key blindly on
first connection. Checking that the records exist and match the keys the server
actually presents is a genuine remote security check.

Only what that needs is implemented: one question, type SSHFP, over UDP. There
is no dependency on a DNS library because the package has no dependencies at
all.
"""

from __future__ import annotations

import os
import random
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from . import dnssec, resolver

__all__ = ["SSHFP_ALGORITHMS", "SshfpRecord", "lookup_sshfp", "resolver_addresses"]

TYPE_SSHFP = 44
CLASS_IN = 1

#: SSHFP algorithm numbers (RFC 4255 and its updates).
SSHFP_ALGORITHMS = {1: "rsa", 2: "dsa", 3: "ecdsa", 4: "ed25519", 6: "ed448"}

#: SSHFP fingerprint types. Only SHA-256 is worth trusting.
SSHFP_FINGERPRINT_TYPES = {1: "sha1", 2: "sha256"}

#: Key family -> the SSHFP algorithm number that should describe it.
FAMILY_TO_SSHFP = {"rsa": 1, "dsa": 2, "ecdsa": 3, "ed25519": 4, "ed448": 6}


class DNSError(Exception):
    """The lookup could not be completed."""


@dataclass(frozen=True)
class SshfpRecord:
    """One SSHFP resource record."""

    algorithm: int
    fingerprint_type: int
    fingerprint: str
    """Lower-case hexadecimal, as the record stores it."""

    @property
    def algorithm_name(self) -> str:
        return SSHFP_ALGORITHMS.get(self.algorithm, f"algorithm-{self.algorithm}")

    @property
    def fingerprint_type_name(self) -> str:
        return SSHFP_FINGERPRINT_TYPES.get(self.fingerprint_type, f"type-{self.fingerprint_type}")

    def __str__(self) -> str:
        return f"{self.algorithm_name}/{self.fingerprint_type_name} {self.fingerprint}"


def resolver_addresses() -> List[str]:
    """Name server addresses from ``/etc/resolv.conf``."""
    servers: List[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.split("#")[0].split(";")[0].strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except OSError:
        pass
    return servers


def _encode_name(name: str) -> bytes:
    """Encode a domain name in DNS label form."""
    encoded = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if not 1 <= len(raw) <= 63:
            raise DNSError(f"invalid label in '{name}'")
        encoded += bytes([len(raw)]) + raw
    return encoded + b"\x00"


def _skip_name(message: bytes, offset: int) -> int:
    """Advance past a (possibly compressed) name and return the new offset."""
    while offset < len(message):
        length = message[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # compression pointer, always the last part
            return offset + 2
        offset += length + 1
    raise DNSError("truncated name in the DNS response")


def _parse_response(message: bytes, query_id: int) -> Tuple[List[SshfpRecord], bool]:
    if len(message) < 12:
        raise DNSError("DNS response is too short")
    response_id, flags, questions, answers = struct.unpack(">HHHH", message[:8])
    if response_id != query_id:
        raise DNSError("DNS response does not match the query")
    rcode = flags & 0x000F
    if rcode == 3:
        return [], bool(flags & 0x0020)  # NXDOMAIN: no records, not an error here
    if rcode != 0:
        raise DNSError(f"the name server returned response code {rcode}")
    authenticated = bool(flags & 0x0020)  # AD bit: the resolver validated with DNSSEC

    offset = 12
    for _ in range(questions):
        offset = _skip_name(message, offset) + 4

    records: List[SshfpRecord] = []
    for _ in range(answers):
        offset = _skip_name(message, offset)
        if offset + 10 > len(message):
            raise DNSError("truncated answer in the DNS response")
        record_type, _cls, _ttl, length = struct.unpack(">HHIH", message[offset : offset + 10])
        offset += 10
        data = message[offset : offset + length]
        offset += length
        if record_type == TYPE_SSHFP and len(data) >= 3:
            records.append(
                SshfpRecord(
                    algorithm=data[0],
                    fingerprint_type=data[1],
                    fingerprint=data[2:].hex(),
                )
            )
    return records, authenticated


def split_server(server: str) -> Tuple[str, int]:
    """Split a name server given as ``address``, ``address:port`` or ``[v6]:port``.

    A bare IPv6 address contains colons of its own, so only the bracketed form
    can carry a port; anything else with more than one colon is the address.
    """
    if server.startswith("["):
        closing = server.find("]")
        if closing != -1:
            address = server[1:closing]
            remainder = server[closing + 1 :]
            if remainder.startswith(":") and remainder[1:].isdigit():
                return address, int(remainder[1:])
            return address, 53
    if server.count(":") == 1:
        address, _, port = server.partition(":")
        if port.isdigit():
            return address, int(port)
    return server, 53


def _authenticated_fetch(
    timeout: float, system_resolver: Optional[str]
) -> Callable[[str, int], Optional[bytes]]:
    """A record fetcher that trusts no third party's opinion: resolve iteratively
    from the authoritative servers, falling back to ``system_resolver`` only as a
    transport. Every signature is verified in ``dnssec`` against the IANA root
    key, so it is the transport, not the AD bit, that the validation rests on."""
    return resolver.fetch_with_fallback(
        resolver.iterative_fetch(timeout),
        dnssec.live_fetch(timeout, system_resolver, include_public=False),
    )


def lookup_sshfp(
    name: str, timeout: float = 3.0, servers: Optional[List[str]] = None
) -> Tuple[List[SshfpRecord], bool]:
    """Look up the SSHFP records for ``name``.

    Returns the records and whether the SSHFP RRset is **DNSSEC-validated to the
    IANA root** -- verified here by re-fetching the chain from the authoritative
    servers and checking every RRSIG, not by trusting the resolver's AD bit. An
    empty list means the name resolved but published no records.
    """
    nameservers = servers if servers is not None else resolver_addresses()
    if not nameservers:
        raise DNSError("no name server found in /etc/resolv.conf")

    query_id = int.from_bytes(os.urandom(2), "big") or random.randrange(1, 65535)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)  # RD set
    query = header + _encode_name(name) + struct.pack(">HH", TYPE_SSHFP, CLASS_IN)

    last_error: Optional[Exception] = None
    for server in nameservers[:3]:
        try:
            address, port = split_server(server)
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query, (address, port))
                message, _ = sock.recvfrom(4096)
            records, _ad_bit = _parse_response(message, query_id)
            validated = dnssec.validate_records(
                name, TYPE_SSHFP, int(time.time()),
                _authenticated_fetch(timeout, nameservers[0]),
            )
            return records, validated
        except (OSError, DNSError) as exc:
            last_error = exc
            continue
    raise DNSError(f"no name server answered: {last_error}")
