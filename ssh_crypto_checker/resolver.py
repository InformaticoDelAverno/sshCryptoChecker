"""A minimal iterative DNS resolver: answers from the authoritative servers directly.

For DNSSEC validation the recursive resolver is only a transport -- every signature is
checked in code against the root key, so a lying resolver just fails the chain. But an
auditor may not want to route reconnaissance queries through a public recursive resolver
at all. This walks the delegation itself, from the IANA root hints down through referrals
(honouring glue, and resolving a nameserver's address when glue is absent), so the DANE
DNSSEC lookups depend on no third-party resolver.

Queries carry the Checking Disabled bit and no recursion-desired bit: authoritative
servers return their own raw records, which the DNSSEC layer then judges.
"""

from __future__ import annotations

import socket
import struct
from typing import Callable, Dict, List, Optional, Tuple

# A record fetcher: given an owner name and RR type, the raw DNS response, or None.
Fetch = Callable[[str, int], Optional[bytes]]

# The IANA root servers (IPv4). A resolution starts here and follows referrals down.
ROOT_HINTS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10",
    "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
    "193.0.14.129", "199.7.83.42", "202.12.27.33",
]
_TYPE_A = 1
_TYPE_NS = 2
_TYPE_OPT = 41
_MAX_REFERRALS = 16
_MAX_GLUELESS_DEPTH = 4

Query = Callable[[str, str, int, float], Optional[bytes]]


def _encode_name(name: str) -> bytes:
    return b"".join(
        bytes([len(part)]) + part.encode("ascii") for part in name.split(".") if part
    ) + b"\x00"


def _read_name(message: bytes, offset: int) -> Tuple[List[bytes], int]:
    """Read a name, following compression pointers into the whole message."""
    labels: List[bytes] = []
    jumped = False
    start = offset
    for _ in range(128):
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if not jumped:
                start = offset + 2
            offset = struct.unpack(">H", message[offset : offset + 2])[0] & 0x3FFF
            jumped = True
            continue
        if length == 0:
            return labels, (start if jumped else offset + 1)
        labels.append(message[offset + 1 : offset + 1 + length])
        offset += 1 + length
    raise ValueError("name too long")


class _Rec:
    __slots__ = ("owner", "rdata", "rdata_offset", "rtype", "section")

    def __init__(
        self, section: str, owner: List[bytes], rtype: int, rdata: bytes, rdata_offset: int
    ) -> None:
        self.section = section
        self.owner = owner
        self.rtype = rtype
        self.rdata = rdata
        self.rdata_offset = rdata_offset


def _parse(message: bytes) -> List[_Rec]:
    """Every record (answer, authority, additional) with its owner and rdata offset."""
    questions, answers, authority, additional = struct.unpack(">HHHH", message[4:12])
    offset = 12
    for _ in range(questions):
        _, offset = _read_name(message, offset)
        offset += 4
    records: List[_Rec] = []
    for section, count in (("an", answers), ("ns", authority), ("ar", additional)):
        for _ in range(count):
            owner, offset = _read_name(message, offset)
            rtype, _cls, _ttl, rdlength = struct.unpack(">HHIH", message[offset : offset + 10])
            offset += 10
            records.append(_Rec(section, owner, rtype, message[offset : offset + rdlength], offset))
            offset += rdlength
    return records


def _has_answer(records: List[_Rec], rtype: int) -> bool:
    return any(r.section == "an" and r.rtype == rtype for r in records)


def _referral(message: bytes, records: List[_Rec]) -> Tuple[List[str], List[str]]:
    """A referral's next hops: ``(glue_ips, nameserver_names_without_glue)``."""
    glue: Dict[str, str] = {}
    for record in records:
        if record.section == "ar" and record.rtype == _TYPE_A and len(record.rdata) == 4:
            glue[b".".join(record.owner).lower().decode("latin1")] = socket.inet_ntoa(record.rdata)
    ns_names = [
        ".".join(part.decode("latin1") for part in _read_name(message, record.rdata_offset)[0])
        for record in records
        if record.section == "ns" and record.rtype == _TYPE_NS
    ]
    glue_ips = [glue[name.lower()] for name in ns_names if name.lower() in glue]
    return glue_ips, ns_names


def _query(server: str, name: str, rtype: int, timeout: float) -> Optional[bytes]:
    """One non-recursive, DNSSEC-OK, checking-disabled query to ``server``."""
    header = b"\x2b\x2b" + struct.pack(">H", 0x0010) + struct.pack(">HHHH", 1, 0, 0, 1)
    question = _encode_name(name) + struct.pack(">HH", rtype, 1)
    opt = b"\x00" + struct.pack(">HHIH", _TYPE_OPT, 4096, 0x00008000, 0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(header + question + opt, (server, 53))
        response = sock.recv(4096)
    except OSError:
        return None
    finally:
        sock.close()
    return response if len(response) >= 12 and not response[2] & 0x02 else None  # not truncated


def _first_response(servers: List[str], name: str, rtype: int, timeout: float,
                    query: Query) -> Optional[bytes]:
    for server in servers:
        response = query(server, name, rtype, timeout)
        if response is not None:
            return response
    return None


def resolve(
    name: str, rtype: int, timeout: float, query: Query = _query, _depth: int = 0
) -> Optional[bytes]:
    """Resolve ``name``/``rtype`` iteratively from the root, returning the authoritative
    response (whatever it is -- an answer or an authenticated negative), or ``None`` if the
    delegation cannot be followed."""
    servers = ROOT_HINTS
    for _ in range(_MAX_REFERRALS):
        response = _first_response(servers, name, rtype, timeout, query)
        if response is None:
            return None
        try:
            records = _parse(response)
        except (IndexError, struct.error, ValueError):
            return None
        if _has_answer(records, rtype):
            return response
        try:
            glue_ips, ns_names = _referral(response, records)
        except (IndexError, struct.error, ValueError):
            return None
        if glue_ips:
            servers = glue_ips
            continue
        if ns_names and _depth < _MAX_GLUELESS_DEPTH:
            address = _resolve_nameserver(ns_names[0], timeout, query, _depth)
            if address is None:
                return response  # cannot find the nameserver's address: give up here
            servers = [address]
            continue
        return response  # a final negative (NODATA / NXDOMAIN), or nothing to follow
    return None


def _resolve_nameserver(
    name: str, timeout: float, query: Query, depth: int
) -> Optional[str]:
    """The IPv4 address of a nameserver that a referral named without glue."""
    response = resolve(name, _TYPE_A, timeout, query, depth + 1)
    if response is None:
        return None
    for record in _parse(response):
        if record.section == "an" and record.rtype == _TYPE_A and len(record.rdata) == 4:
            return socket.inet_ntoa(record.rdata)
    return None


def iterative_fetch(timeout: float) -> Callable[[str, int], Optional[bytes]]:
    """A record fetcher that resolves iteratively from the root -- no recursive resolver."""
    def fetch(name: str, rtype: int) -> Optional[bytes]:
        return resolve(name, rtype, timeout)

    return fetch


def fetch_with_fallback(
    primary: Callable[[str, int], Optional[bytes]],
    fallback: Callable[[str, int], Optional[bytes]],
) -> Callable[[str, int], Optional[bytes]]:
    """A fetcher that tries ``primary`` and, only if it returns nothing, ``fallback``."""
    def fetch(name: str, rtype: int) -> Optional[bytes]:
        return primary(name, rtype) or fallback(name, rtype)

    return fetch
