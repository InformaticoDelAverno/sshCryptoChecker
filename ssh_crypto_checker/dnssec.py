"""DNSSEC validation of a DANE TLSA record, done independently (RFC 4033-4035, 4034).

DANE is only worth trusting when the TLSA record is authenticated by DNSSEC; otherwise
an on-path attacker can forge the pin. This validates the whole signature chain from the
TLSA record up to the IANA root key -- itself, in code, verifying every RRSIG and DS --
rather than trusting a resolver's "authenticated data" bit. Queries carry the Checking
Disabled bit so a validating resolver hands back the raw records for us to judge, and any
doubt fails closed: an unverifiable chain reports *not validated*, never *validated*.
"""

from __future__ import annotations

import hashlib
import socket
import struct
from typing import Callable, Dict, List, Optional, Tuple

from .crypto import ec, ecdsa, ed25519, rsa

TYPE_DS = 43
TYPE_RRSIG = 46
TYPE_NSEC = 47
TYPE_DNSKEY = 48
TYPE_NSEC3 = 50
TYPE_TLSA = 52
_TYPE_OPT = 41
_TYPE_CNAME = 5
# base32hex (RFC 4648) -- the alphabet NSEC3 owner names are encoded in (order-preserving).
_B32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

# IANA root key-signing keys, as (key tag -> SHA-256 DS digest). KSK-2017 (20326) is the
# long-standing anchor; KSK-2024 (38696) is its published successor. A root DNSKEY set is
# trusted only if one of its keys hashes to a digest here.
ROOT_ANCHORS: Dict[int, str] = {
    20326: "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
    38696: "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
}

# RRSIG/DNSKEY algorithm -> (hash name, family); DS digest type -> hash name.
_RSA_HASHES = {8: "sha256", 10: "sha512"}
_ECDSA = {13: (ec.P256, "sha256"), 14: (ec.P384, "sha384")}
_ED25519 = 15
_DS_DIGESTS = {2: hashlib.sha256, 4: hashlib.sha384}
_MAX_ZONES = 12  # a sanity bound on the delegation depth walked


class _ChainError(Exception):
    """Anything that stops the chain being proven; caught and reported as not validated."""


def _read_name(message: bytes, offset: int) -> Tuple[List[bytes], int]:
    """Read a (possibly compressed) DNS name; return its labels and the offset after it."""
    labels: List[bytes] = []
    jumped = False
    cursor = offset
    for _ in range(128):  # bounded: a name has at most 127 labels
        length = message[cursor]
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack(">H", message[cursor : cursor + 2])[0] & 0x3FFF
            if not jumped:
                offset = cursor + 2
            cursor = pointer
            jumped = True
            continue
        if length == 0:
            return labels, (offset if jumped else cursor + 1)
        labels.append(message[cursor + 1 : cursor + 1 + length])
        cursor += 1 + length
    raise _ChainError("name too long")


def _canonical_name(labels: List[bytes]) -> bytes:
    """The wire form of a name, lower-cased and uncompressed (RFC 4034 6.2)."""
    return b"".join(bytes([len(label)]) + label.lower() for label in labels) + b"\x00"


class _Record:
    __slots__ = ("name", "rdata", "rtype")

    def __init__(self, name: List[bytes], rtype: int, rdata: bytes) -> None:
        self.name = name
        self.rtype = rtype
        self.rdata = rdata


def _parse_answers(message: bytes) -> List[_Record]:
    """The answer-section records of a DNS response."""
    if len(message) < 12:
        raise _ChainError("short DNS message")
    questions = struct.unpack(">H", message[4:6])[0]
    answers = struct.unpack(">H", message[6:8])[0]
    offset = 12
    for _ in range(questions):
        _, offset = _read_name(message, offset)
        offset += 4  # qtype + qclass
    records: List[_Record] = []
    for _ in range(answers):
        name, offset = _read_name(message, offset)
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", message[offset : offset + 10])
        offset += 10
        records.append(_Record(name, rtype, message[offset : offset + rdlength]))
        offset += rdlength
    return records


class _Rrsig:
    __slots__ = (
        "algorithm",
        "expiration",
        "inception",
        "key_tag",
        "original_ttl",
        "signature",
        "signed_rdata",
        "signer",
        "type_covered",
    )

    def __init__(self, rdata: bytes) -> None:
        (self.type_covered, self.algorithm, _labels, self.original_ttl,
         self.expiration, self.inception, self.key_tag) = struct.unpack(">HBBIIIH", rdata[:18])
        self.signer, end = _read_name(rdata, 18)
        self.signed_rdata = rdata[:end]  # the RRSIG RDATA up to and including the signer name
        self.signature = rdata[end:]


def _key_tag(dnskey_rdata: bytes) -> int:
    """The key tag of a DNSKEY (RFC 4034 appendix B)."""
    total = sum(
        (byte << 8) if index % 2 == 0 else byte for index, byte in enumerate(dnskey_rdata)
    )
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


def _dnskeys(records: List[_Record]) -> Dict[int, bytes]:
    return {
        _key_tag(record.rdata): record.rdata
        for record in records
        if record.rtype == TYPE_DNSKEY
    }


def _rrset(records: List[_Record], rtype: int) -> Tuple[List[bytes], List[bytes]]:
    """The owner name and the RDATAs of the RRset of ``rtype`` (raises if absent)."""
    matching = [record for record in records if record.rtype == rtype]
    if not matching:
        raise _ChainError(f"no RRset of type {rtype}")
    return matching[0].name, [record.rdata for record in matching]


def _rrsig_for(records: List[_Record], rtype: int) -> _Rrsig:
    for record in records:
        if record.rtype == TYPE_RRSIG:
            signature = _Rrsig(record.rdata)
            if signature.type_covered == rtype:
                return signature
    raise _ChainError(f"no RRSIG covering type {rtype}")


def _signed_data(owner: List[bytes], rdatas: List[bytes], signature: _Rrsig) -> bytes:
    """The bytes an RRSIG signs: its RDATA, then each RR canonical and RDATA-sorted."""
    name = _canonical_name(owner)
    records = [
        name + struct.pack(">HHIH", signature.type_covered, 1, signature.original_ttl, len(rdata))
        + rdata
        for rdata in sorted(rdatas)  # RRs ordered by their RDATA (RFC 4034 6.3)
    ]
    return signature.signed_rdata + b"".join(records)


def _verify_signature(dnskey_rdata: bytes, signature: _Rrsig, message: bytes) -> bool:
    """Verify one RRSIG signature under a DNSKEY, dispatched on the algorithm."""
    public = dnskey_rdata[4:]  # after flags(2) + protocol(1) + algorithm(1)
    algorithm = signature.algorithm
    if algorithm in _RSA_HASHES:
        if public[0] == 0:  # a 3-byte exponent length (RFC 3110)
            exponent_length = struct.unpack(">H", public[1:3])[0]
            exponent = int.from_bytes(public[3 : 3 + exponent_length], "big")
            modulus = int.from_bytes(public[3 + exponent_length :], "big")
        else:
            exponent_length = public[0]
            exponent = int.from_bytes(public[1 : 1 + exponent_length], "big")
            modulus = int.from_bytes(public[1 + exponent_length :], "big")
        return rsa.verify_pkcs1(modulus, exponent, signature.signature, message,
                                _RSA_HASHES[algorithm])
    if algorithm in _ECDSA:
        curve, hash_name = _ECDSA[algorithm]
        half = len(signature.signature) // 2
        r = int.from_bytes(signature.signature[:half], "big")
        s = int.from_bytes(signature.signature[half:], "big")
        return ecdsa.verify(curve, b"\x04" + public, r, s, message, hash_name)
    if algorithm == _ED25519:
        return ed25519.verify(public, message, signature.signature)
    return False


def _verify_rrset(
    records: List[_Record], rtype: int, keys: Dict[int, bytes], now: int
) -> None:
    """Verify the ``rtype`` RRset in ``records`` under one of ``keys``; raise on any failure."""
    owner, rdatas = _rrset(records, rtype)
    signature = _rrsig_for(records, rtype)
    if not signature.inception <= now <= signature.expiration:
        raise _ChainError("RRSIG outside its validity period")
    key = keys.get(signature.key_tag)
    if key is None:
        raise _ChainError("no DNSKEY matches the RRSIG key tag")
    if not _verify_signature(key, signature, _signed_data(owner, rdatas, signature)):
        raise _ChainError("RRSIG signature did not verify")


def _ds_matches(owner: List[bytes], dnskey_rdata: bytes, ds_rdata: bytes) -> bool:
    """Whether a DNSKEY hashes to a DS record (RFC 4034 5.1.4)."""
    key_tag, _algorithm, digest_type = struct.unpack(">HBB", ds_rdata[:4])
    hasher = _DS_DIGESTS.get(digest_type)
    if hasher is None or key_tag != _key_tag(dnskey_rdata):
        return False
    return hasher(_canonical_name(owner) + dnskey_rdata).hexdigest() == ds_rdata[4:].hex()


def _authenticated_keys(
    dnskey_records: List[_Record], owner: List[bytes], now: int,
    anchor: Callable[[bytes], bool],
) -> Dict[int, bytes]:
    """The zone's DNSKEYs, once its set self-verifies and a key is vouched for by ``anchor``
    (a root trust anchor, or a DS from the parent)."""
    keys = _dnskeys(dnskey_records)
    if not any(anchor(rdata) for rdata in keys.values()):
        raise _ChainError("no DNSKEY is anchored")
    _verify_rrset(dnskey_records, TYPE_DNSKEY, keys, now)
    return keys


def _root_anchor(dnskey_rdata: bytes) -> bool:
    digest = hashlib.sha256(b"\x00" + dnskey_rdata).hexdigest()
    return ROOT_ANCHORS.get(_key_tag(dnskey_rdata)) == digest


def _ds_anchor(owner: List[bytes], ds_rdatas: List[bytes]) -> Callable[[bytes], bool]:
    """An anchor that accepts a DNSKEY vouched for by one of the parent's DS records."""
    def anchor(dnskey_rdata: bytes) -> bool:
        return any(_ds_matches(owner, dnskey_rdata, ds) for ds in ds_rdatas)
    return anchor


def validate_tlsa(
    host: str, port: int, now: int, fetch: Callable[[str, int], Optional[bytes]]
) -> bool:
    """Whether the TLSA record for ``_<port>._tcp.<host>`` is authenticated by DNSSEC to the
    IANA root key. Fails closed: any gap in the chain returns ``False``."""
    return validate_records(f"_{port}._tcp.{host}", TYPE_TLSA, now, fetch)


def validate_records(
    owner: str, rtype: int, now: int, fetch: Callable[[str, int], Optional[bytes]]
) -> bool:
    """Whether the RRset of ``rtype`` at ``owner`` is authenticated by DNSSEC to the IANA
    root key -- the RRSIG verifies under DNSKEYs whose chain of DS records walks up to a
    hardcoded root anchor. Fails closed: any gap returns ``False``, so a caller may treat
    ``True`` as "these records are genuine" and anything else as "not proven"."""
    try:
        return _validate_rrset(owner, rtype, now, fetch)
    except (_ChainError, struct.error, IndexError, ValueError):
        return False


def _fetch_records(
    fetch: Callable[[str, int], Optional[bytes]], name: str, rtype: int
) -> List[_Record]:
    response = fetch(name, rtype)
    if response is None:
        raise _ChainError(f"no response for {name}/{rtype}")
    return _parse_answers(response)


def _dotted(labels: List[bytes]) -> str:
    return ".".join(label.decode("ascii", "replace") for label in labels)


def _authenticated_zone_keys(
    zone: List[bytes], now: int, fetch: Callable[[str, int], Optional[bytes]]
) -> Dict[int, bytes]:
    """The DNSKEYs of ``zone``, authenticated by walking the DS chain to the root anchor.

    Walks up from ``zone`` to the root, discovering each parent from its DS RRSIG's signer,
    then validates top-down: the root DNSKEY anchored to IANA, and each child's DNSKEY
    vouched for by its parent's DS."""
    chain: List[Tuple[List[bytes], List[_Record]]] = []
    current = zone
    for _ in range(_MAX_ZONES):
        if not current:  # reached the root
            break
        ds_records = _fetch_records(fetch, _dotted(current), TYPE_DS)
        chain.append((current, ds_records))
        current = _rrsig_for(ds_records, TYPE_DS).signer
    else:
        raise _ChainError("delegation too deep")

    keys = _authenticated_keys(_fetch_records(fetch, ".", TYPE_DNSKEY), [], now, _root_anchor)
    for zone_labels, ds_records in reversed(chain):
        _verify_rrset(ds_records, TYPE_DS, keys, now)  # the DS set is signed by the parent
        _, ds_rdatas = _rrset(ds_records, TYPE_DS)
        dnskey_records = _fetch_records(fetch, _dotted(zone_labels), TYPE_DNSKEY)
        keys = _authenticated_keys(dnskey_records, zone_labels, now,
                                   _ds_anchor(zone_labels, ds_rdatas))
    return keys


def _validate_rrset(
    owner: str, rtype: int, now: int, fetch: Callable[[str, int], Optional[bytes]]
) -> bool:
    records = _fetch_records(fetch, owner, rtype)
    zone = _rrsig_for(records, rtype).signer  # the zone that signed this RRset
    keys = _authenticated_zone_keys(zone, now, fetch)
    _verify_rrset(records, rtype, keys, now)
    return True


# --------------------------------------------------------------------------- #
# Authenticated denial of existence (NSEC3 and NSEC): the TLSA is genuinely absent
# --------------------------------------------------------------------------- #


def _parse_answer_and_authority(message: bytes) -> Tuple[List[_Record], List[_Record]]:
    """The answer and authority sections of a DNS response (owner names kept)."""
    if len(message) < 12:
        raise _ChainError("short DNS message")
    _questions, answers, authority, _additional = struct.unpack(">HHHH", message[4:12])
    offset = 12
    for _ in range(_questions):
        _, offset = _read_name(message, offset)
        offset += 4
    sections: List[List[_Record]] = [[], []]
    for index, count in enumerate((answers, authority)):
        for _ in range(count):
            name, offset = _read_name(message, offset)
            rtype, _cls, _ttl, rdlength = struct.unpack(">HHIH", message[offset : offset + 10])
            offset += 10
            sections[index].append(_Record(name, rtype, message[offset : offset + rdlength]))
            offset += rdlength
    return sections[0], sections[1]


def _b32hex_decode(label: str) -> bytes:
    """Decode a base32hex (RFC 4648) NSEC3 owner label into the raw hash bytes."""
    bits = value = 0
    out = bytearray()
    for character in label:
        value = (value << 5) | _B32HEX.index(character)
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((value >> bits) & 0xFF)
    return bytes(out)


def _nsec3_hash(labels: List[bytes], salt: bytes, iterations: int) -> bytes:
    """The NSEC3 hash of a name: SHA-1 of its wire form, iterated with the salt (RFC 5155)."""
    digest = hashlib.sha1(_canonical_name(labels) + salt).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()
    return digest


class _Nsec3:
    __slots__ = ("bitmap", "iterations", "next_hash", "opt_out", "owner_hash", "salt")

    def __init__(self, record: _Record) -> None:
        rdata = record.rdata
        salt_length = rdata[4]
        self.salt = rdata[5 : 5 + salt_length]
        cursor = 5 + salt_length
        hash_length = rdata[cursor]
        self.next_hash = rdata[cursor + 1 : cursor + 1 + hash_length]
        self.bitmap = rdata[cursor + 1 + hash_length :]
        self.iterations = int.from_bytes(rdata[2:4], "big")
        self.opt_out = bool(rdata[1] & 1)
        self.owner_hash = _b32hex_decode(record.name[0].decode("ascii"))


def _type_in_bitmap(bitmap: bytes, rtype: int) -> bool:
    """Whether ``rtype`` is set in an NSEC/NSEC3 type bitmap (RFC 4034 4.1.2)."""
    window, bit = rtype >> 8, rtype & 0xFF
    cursor = 0
    while cursor + 2 <= len(bitmap):
        block, length = bitmap[cursor], bitmap[cursor + 1]
        data = bitmap[cursor + 2 : cursor + 2 + length]
        if block == window:
            index = bit >> 3
            return index < len(data) and bool(data[index] & (0x80 >> (bit & 7)))
        cursor += 2 + length
    return False


def _covers(owner: bytes, target: bytes, next_owner: bytes) -> bool:
    """Whether an NSEC3's [owner, next) hash range covers ``target`` (with wrap-around)."""
    if owner < next_owner:
        return owner < target < next_owner
    return target > owner or target < next_owner  # the last NSEC3 wraps past the apex


def _denies_tlsa(qname: List[bytes], records: List[_Nsec3]) -> bool:
    """Whether the NSEC3 set proves no TLSA exists at ``qname`` (RFC 5155 8)."""
    salt, iterations = records[0].salt, records[0].iterations
    owners = {record.owner_hash for record in records}
    query_hash = _nsec3_hash(qname, salt, iterations)
    for record in records:  # NODATA: the name exists but carries no TLSA (nor a CNAME)
        if record.owner_hash == query_hash:
            return not _type_in_bitmap(record.bitmap, TYPE_TLSA) \
                and not _type_in_bitmap(record.bitmap, _TYPE_CNAME)
    # NXDOMAIN: the closest-encloser proof -- the closest existing ancestor, plus NSEC3s
    # covering the next-closer name and the wildcard, proving neither exists.
    closest_encloser = None
    for index in range(1, len(qname) + 1):
        if _nsec3_hash(qname[index:], salt, iterations) in owners:
            closest_encloser = qname[index:]
            break
    if closest_encloser is None:
        return False
    next_closer = qname[len(qname) - len(closest_encloser) - 1 :]
    wildcard = [b"*", *closest_encloser]

    def covered(name: List[bytes]) -> bool:
        target = _nsec3_hash(name, salt, iterations)
        return any(_covers(r.owner_hash, target, r.next_hash) for r in records)

    return covered(next_closer) and covered(wildcard)


def _verify_each(
    authority: List[_Record], rtype: int, keys: Dict[int, bytes], now: int
) -> None:
    """Verify every ``rtype`` record's RRSIG (each has its own owner, so its own RRset)."""
    owners = {tuple(record.name) for record in authority if record.rtype == rtype}
    for owner in owners:
        subset = [record for record in authority if tuple(record.name) == owner]
        _verify_rrset(subset, rtype, keys, now)


# --- NSEC (non-hashed) denial: the same proof over plain, canonically-ordered names ------ #


def _name_key(labels: List[bytes]) -> List[bytes]:
    """A name as its labels in canonical DNS order (RFC 4034 6.1): lower-cased and compared
    from the rightmost label, so Python's list/bytes ordering matches the wire ordering."""
    return [label.lower() for label in reversed(labels)]


def _covers_name(owner: List[bytes], target: List[bytes], next_name: List[bytes]) -> bool:
    """Whether an NSEC's [owner, next) name range covers ``target`` (with wrap-around)."""
    owner_key, target_key, next_key = _name_key(owner), _name_key(target), _name_key(next_name)
    if owner_key < next_key:
        return owner_key < target_key < next_key
    return target_key > owner_key or target_key < next_key  # the last NSEC wraps past the apex


def _common_suffix(first: List[bytes], second: List[bytes]) -> List[bytes]:
    """The longest run of trailing labels two names share (case-insensitively)."""
    shared: List[bytes] = []
    for left, right in zip(reversed(first), reversed(second)):
        if left.lower() != right.lower():
            break
        shared.append(left)
    return list(reversed(shared))


def _parse_nsec(record: _Record) -> Tuple[List[bytes], List[bytes], bytes]:
    """An NSEC record as (owner, next-owner name, type bitmap). The next name is uncompressed
    in NSEC RDATA (RFC 4034 4.1.1), so it is read straight from the RDATA."""
    next_name, offset = _read_name(record.rdata, 0)
    return record.name, next_name, record.rdata[offset:]


def _denies_tlsa_nsec(
    qname: List[bytes], records: List[Tuple[List[bytes], List[bytes], bytes]]
) -> bool:
    """Whether the NSEC set proves no TLSA exists at ``qname`` (RFC 4035 5.4)."""
    query_key = _name_key(qname)
    for owner, _next, bitmap in records:  # NODATA: the name exists but carries no TLSA/CNAME
        if _name_key(owner) == query_key:
            return not _type_in_bitmap(bitmap, TYPE_TLSA) \
                and not _type_in_bitmap(bitmap, _TYPE_CNAME)
    # NXDOMAIN: an NSEC covers the name, and one covers the wildcard at its closest encloser
    # (the deepest ancestor of qname that an in-range endpoint shows to exist).
    covering = [rec for rec in records if _covers_name(rec[0], qname, rec[1])]
    if not covering:
        return False
    owner, next_name, _bitmap = covering[0]
    closest_encloser = max(
        _common_suffix(qname, owner), _common_suffix(qname, next_name), key=len
    )
    wildcard = [b"*", *closest_encloser]
    return any(_covers_name(rec[0], wildcard, rec[1]) for rec in records)


def validate_denial(
    host: str, port: int, now: int, fetch: Callable[[str, int], Optional[bytes]]
) -> bool:
    """Whether DNSSEC authentically proves that ``_<port>._tcp.<host>`` has no TLSA record
    (an NSEC3 or NSEC denial validated to the root). ``True`` means DANE is genuinely not
    configured, not merely unseen. Fails closed: any gap returns ``False``."""
    try:
        return _validate_denial(host, port, now, fetch)
    except (_ChainError, struct.error, IndexError, ValueError):
        return False


def _validate_denial(
    host: str, port: int, now: int, fetch: Callable[[str, int], Optional[bytes]]
) -> bool:
    response = fetch(f"_{port}._tcp.{host}", TYPE_TLSA)
    if response is None:
        raise _ChainError("no response")
    answers, authority = _parse_answer_and_authority(response)
    if any(record.rtype == TYPE_TLSA for record in answers):
        return False  # a TLSA is present -- this is not a denial
    qname = [part.encode("ascii") for part in f"_{port}._tcp.{host}".split(".") if part]
    nsec3_records = [record for record in authority if record.rtype == TYPE_NSEC3]
    if nsec3_records:
        keys = _denial_zone_keys(authority, TYPE_NSEC3, now, fetch)
        _verify_each(authority, TYPE_NSEC3, keys, now)
        return _denies_tlsa(qname, [_Nsec3(record) for record in nsec3_records])
    nsec_records = [record for record in authority if record.rtype == TYPE_NSEC]
    if nsec_records:
        keys = _denial_zone_keys(authority, TYPE_NSEC, now, fetch)
        _verify_each(authority, TYPE_NSEC, keys, now)
        return _denies_tlsa_nsec(qname, [_parse_nsec(record) for record in nsec_records])
    raise _ChainError("no NSEC/NSEC3 records to prove absence")


def _denial_zone_keys(
    authority: List[_Record], rtype: int, now: int, fetch: Callable[[str, int], Optional[bytes]]
) -> Dict[int, bytes]:
    """The authenticated DNSKEYs of the zone that signed the ``rtype`` denial records."""
    zone = _rrsig_for(
        [record for record in authority if record.rtype == TYPE_RRSIG], rtype
    ).signer
    return _authenticated_zone_keys(zone, now, fetch)


# --------------------------------------------------------------------------- #
# Transport: raw DNS over UDP, asking a resolver not to validate (we do)
# --------------------------------------------------------------------------- #

_PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]


def _build_query(name: str, rtype: int) -> bytes:
    labels = _canonical_name([part.encode() for part in name.split(".") if part])
    header = b"\x2b\x2b" + struct.pack(">H", 0x0110) + struct.pack(">HHHH", 1, 0, 0, 1)
    question = labels + struct.pack(">HH", rtype, 1)
    opt = b"\x00" + struct.pack(">HHIH", _TYPE_OPT, 4096, 0x00008000, 0)  # EDNS0, DO bit
    return header + question + opt


def _query(name: str, rtype: int, resolvers: List[str], timeout: float) -> Optional[bytes]:
    packet = _build_query(name, rtype)
    for resolver in resolvers:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(packet, (resolver, 53))
            response = sock.recv(4096)
        except OSError:
            continue
        finally:
            sock.close()
        # Take the first usable answer: not truncated, and no error rcode (a resolver that
        # cannot serve DNSSEC -- e.g. a stub returning SERVFAIL -- is skipped for the next).
        if len(response) >= 12 and not response[2] & 0x02 and not response[3] & 0x0F:
            return response
    return None


def live_fetch(
    timeout: float, system_resolver: Optional[str], include_public: bool = True
) -> Callable[[str, int], Optional[bytes]]:
    """A record fetcher over UDP, trying the system resolver first then, unless
    ``include_public`` is False, public ones. The resolver is transport only -- every
    signature is verified here against the root key."""
    resolvers = [system_resolver] if system_resolver else []
    if include_public:
        resolvers = resolvers + _PUBLIC_RESOLVERS

    def fetch(name: str, rtype: int) -> Optional[bytes]:
        return _query(name, rtype, resolvers, timeout)

    return fetch
