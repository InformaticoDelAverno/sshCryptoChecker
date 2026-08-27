"""Parsers for the SSH messages a scan reads and the payloads it builds.

The identification banner and the product it names, ``SSH_MSG_EXT_INFO``, the
server's ``SSH_MSG_KEXINIT`` and the client one this scanner proposes, and the
host key and certificate blobs -- every field of which is the peer's claim,
read through the ``Reader`` from :mod:`.wire`.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from typing import Dict, List, Optional, Tuple

from ..models import BannerInfo, CertificateInfo, HostKeyInfo, KexInit
from .constants import (
    _CLIENT_CIPHERS,
    _CLIENT_MACS,
    _ECDSA_CURVE_BITS,
    MSG_EXT_INFO,
    MSG_KEXINIT,
)
from .wire import Reader, SSHProtocolError, pack_name_list, printable

# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #


def parse_banner(raw: str, pre_banner_lines: Optional[List[str]] = None) -> BannerInfo:
    """Split an SSH identification string into its parts.

    The format is ``SSH-protoversion-softwareversion SP comments``.

    ``raw`` is kept exactly as it arrived: it goes into the exchange hash, and
    changing one byte of it would make every signature fail to verify. Every
    field derived from it is for reading, and is stripped of the characters a
    terminal would act on -- the banner is the most attacker-controlled string
    in a scan, and it is printed to somebody's screen.
    """
    info = BannerInfo(raw=printable(raw), exact=raw, pre_banner_lines=[
        printable(line) for line in (pre_banner_lines or [])
    ])
    body = raw[4:] if raw.startswith("SSH-") else raw
    protocol, _, remainder = body.partition("-")
    info.protocol_version = printable(protocol)
    software, _, comments = remainder.partition(" ")
    info.software = printable(software)
    info.comments = printable(comments)
    info.product, info.product_version = _identify_product(info.software)
    return info


#: Software strings that identify a product exactly, with no version attached.
_EXACT_PRODUCTS = {
    "Go": ("Go x/crypto/ssh", None),
}

#: Prefixes to strip to leave a bare version string. Longest first, so that
#: ``OpenSSH_for_Windows_8.1`` yields version ``8.1`` rather than
#: ``for_Windows_8.1``, which no version parser could read.
_PRODUCT_PREFIXES = (
    ("OpenSSH_for_Windows_", "OpenSSH"),
    ("OpenSSH_", "OpenSSH"),
    ("dropbear_", "Dropbear"),
    ("libssh_", "libssh"),
    ("libssh-", "libssh"),
    ("paramiko_", "Paramiko"),
    ("Erlang/", "Erlang/OTP ssh"),
    ("ROSSSH", "RouterOS"),
    ("mod_sftp/", "ProFTPD mod_sftp"),
    ("CoreFTP-", "CoreFTP"),
    ("Cisco-", "Cisco"),
    ("SSHD-CORE-", "Apache MINA SSHD"),
)


def _identify_product(software: str) -> Tuple[Optional[str], Optional[str]]:
    """Map a software string such as ``OpenSSH_9.6p1`` to (product, version)."""
    if software in _EXACT_PRODUCTS:
        return _EXACT_PRODUCTS[software]
    for prefix, product in _PRODUCT_PREFIXES:
        if software.startswith(prefix):
            version = software[len(prefix) :].strip()
            return product, version or None
    return None, None


# --------------------------------------------------------------------------- #
# KEXINIT
# --------------------------------------------------------------------------- #


def parse_ext_info(payload: bytes) -> Dict[str, str]:
    """Parse SSH_MSG_EXT_INFO (RFC 8308 section 2.3).

    ``server-sig-algs`` is the interesting one: it lists the signature
    algorithms the server will accept for client public key authentication,
    which is not visible in the KEXINIT at all.
    """
    reader = Reader(payload)
    if reader.read_byte() != MSG_EXT_INFO:
        raise SSHProtocolError("not an SSH_MSG_EXT_INFO packet")
    extensions: Dict[str, str] = {}
    count = reader.read_uint32()
    for _ in range(min(count, 64)):
        name = reader.read_text()
        extensions[name] = reader.read_text()
    return extensions


def parse_kexinit_payload(payload: bytes) -> KexInit:
    """Parse the payload of an ``SSH_MSG_KEXINIT`` packet."""
    reader = Reader(payload)
    message_type = reader.read_byte()
    if message_type != MSG_KEXINIT:
        raise SSHProtocolError(f"expected SSH_MSG_KEXINIT, got message type {message_type}")
    cookie = reader.read_bytes(16)
    kexinit = KexInit(
        cookie=cookie.hex(),
        kex_algorithms=reader.read_name_list(),
        host_key_algorithms=reader.read_name_list(),
        encryption_c2s=reader.read_name_list(),
        encryption_s2c=reader.read_name_list(),
        mac_c2s=reader.read_name_list(),
        mac_s2c=reader.read_name_list(),
        compression_c2s=reader.read_name_list(),
        compression_s2c=reader.read_name_list(),
        languages_c2s=reader.read_name_list(),
        languages_s2c=reader.read_name_list(),
    )
    kexinit.first_kex_packet_follows = reader.read_bool()
    return kexinit


def _build_client_kexinit(
    kex_algorithms: List[str],
    host_key_algorithms: List[str],
    ciphers: Optional[List[str]] = None,
    macs: Optional[List[str]] = None,
) -> bytes:
    """Build our own KEXINIT payload proposing exactly what we want to test."""
    ciphers = _CLIENT_CIPHERS if ciphers is None else ciphers
    macs = _CLIENT_MACS if macs is None else macs
    payload = bytes([MSG_KEXINIT]) + os.urandom(16)
    payload += pack_name_list(kex_algorithms)
    payload += pack_name_list(host_key_algorithms)
    payload += pack_name_list(ciphers)
    payload += pack_name_list(ciphers)
    payload += pack_name_list(macs)
    payload += pack_name_list(macs)
    payload += pack_name_list(["none"])
    payload += pack_name_list(["none"])
    payload += pack_name_list([])
    payload += pack_name_list([])
    payload += b"\x00"  # first_kex_packet_follows
    payload += struct.pack(">I", 0)  # reserved
    return payload


# --------------------------------------------------------------------------- #
# Host key blobs
# --------------------------------------------------------------------------- #


def _fingerprint(blob: bytes) -> str:
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _read_public_key_fields(
    reader: Reader, key_type: str, info: HostKeyInfo
) -> Tuple[Optional[int], str]:
    """Read the type-specific part of a public key and return (bits, family).

    RSA parameters are kept on ``info`` when one is given. A key's size says
    nothing about whether its arithmetic is sound, and a check that wants to
    divide the modulus cannot re-derive it from the bit count.
    """
    if key_type in {"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}:
        # Kept on the info rather than derived from the bit count: a check
        # that wants to divide the modulus cannot get it back from a number of
        # bits, and every caller has an info to put it on.
        info.public_exponent = reader.read_mpint()
        info.modulus = reader.read_mpint()
        return info.modulus.bit_length(), "rsa"
    if key_type == "ssh-dss":
        prime = reader.read_mpint()
        reader.read_mpint()  # q
        reader.read_mpint()  # g
        reader.read_mpint()  # y
        return prime.bit_length(), "dsa"
    if key_type.startswith("ecdsa-sha2-") or key_type.startswith("sk-ecdsa-sha2-"):
        curve = reader.read_text()
        reader.read_string()  # encoded point
        if key_type.startswith("sk-"):
            reader.read_string()  # FIDO application
        return _ECDSA_CURVE_BITS.get(curve), "ecdsa"
    # ``sk-ssh-ed25519`` is the base type left after stripping the certificate
    # suffix from sk-ssh-ed25519-cert-v01@openssh.com.
    if key_type in {"ssh-ed25519", "sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519"}:
        key = reader.read_string()
        if key_type.startswith("sk-"):
            reader.read_string()  # FIDO application
        return len(key) * 8, "ed25519"
    if key_type == "ssh-ed448":
        key = reader.read_string()
        return 448 if len(key) == 57 else len(key) * 8, "ed448"
    if key_type == "ssh-xmss@openssh.com":
        reader.read_text()  # parameter set name
        reader.read_string()  # public key
        return None, "xmss"
    return None, key_type


def parse_host_key_blob(blob: bytes, algorithm: str = "") -> HostKeyInfo:
    """Extract type, size and fingerprint from a raw host key blob."""
    info = HostKeyInfo(algorithm=algorithm or "", fingerprint_sha256=_fingerprint(blob))
    reader = Reader(blob)
    try:
        key_type = reader.read_text()
    except SSHProtocolError as exc:
        info.error = str(exc)
        return info

    info.key_type = key_type
    info.is_certificate = "-cert-v0" in key_type
    if not info.algorithm:
        info.algorithm = key_type

    try:
        if key_type.endswith("-cert-v01@openssh.com"):
            base_type = key_type.split("-cert-v01@", 1)[0]
            reader.read_string()  # nonce
            info.bits, info.key_family = _read_public_key_fields(reader, base_type, info)
            info.certificate = _read_certificate_fields(reader)
        elif info.is_certificate:
            # The withdrawn v00 format has a different layout (no leading
            # nonce, different tail). It is obsolete and the policy already
            # rates it insecure, so report it rather than misparse it.
            info.error = (
                "obsolete v00 certificate format; its fields are not parsed. "
                "Reissue the certificate in the v01 format."
            )
        else:
            info.bits, info.key_family = _read_public_key_fields(reader, key_type, info)
    except (SSHProtocolError, ValueError, struct.error) as exc:
        # A key blob comes off the wire, so every length in it is the peer's
        # claim. One clause covers the three ways that can go wrong; keeping
        # them apart left a branch no blob could reach.
        info.error = f"could not fully parse the key blob: {exc}"
    return info


def _read_certificate_fields(reader: Reader) -> CertificateInfo:
    """Read the certificate-specific tail of an OpenSSH certificate blob."""
    cert = CertificateInfo()
    cert.serial = reader.read_uint64()
    cert_type = reader.read_uint32()
    cert.cert_type = {1: "user", 2: "host"}.get(cert_type, f"unknown({cert_type})")
    cert.key_id = reader.read_text()
    principals_blob = reader.read_string()
    principal_reader = Reader(principals_blob)
    while principal_reader.remaining > 0:
        cert.principals.append(principal_reader.read_text())
    cert.valid_after = reader.read_uint64()
    cert.valid_before = reader.read_uint64()
    reader.read_string()  # critical options
    reader.read_string()  # extensions
    reader.read_string()  # reserved
    ca_blob = reader.read_string()
    if ca_blob:
        cert.ca_fingerprint = _fingerprint(ca_blob)
        try:
            cert.ca_key_type = Reader(ca_blob).read_text()
        except SSHProtocolError:
            # The CA blob is as much the peer's word as the rest of the
            # certificate: it can be truncated like anything else.
            cert.ca_key_type = None
    return cert
