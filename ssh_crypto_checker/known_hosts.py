"""Comparison against a local ``known_hosts`` file.

A host key that differs from the one recorded on a client is either a rotation
nobody wrote down or an interception. Either way it is worth reporting, and it
is the only check here that uses local state rather than the network.

Hashed entries (``HashKnownHosts yes``, the default on many systems) store
HMAC-SHA1 of the hostname under a per-entry salt rather than the name itself,
so a plain string comparison finds nothing. Both forms are handled.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

__all__ = ["KnownHostsEntry", "default_known_hosts_paths", "load_known_hosts", "lookup"]


@dataclass(frozen=True)
class KnownHostsEntry:
    """One record from a known_hosts file."""

    patterns: Tuple[str, ...]
    """Host patterns, empty when the entry is hashed."""
    hashed: Optional[Tuple[bytes, bytes]] = None
    """``(salt, digest)`` for a hashed entry."""
    key_type: str = ""
    key_blob: bytes = b""
    marker: str = ""
    """``@cert-authority`` or ``@revoked``, when present."""
    source: str = ""

    def matches(self, host: str, port: int) -> bool:
        """Whether this entry describes the given host.

        A non-default port is written ``[host]:port``, which is also the form
        that gets hashed.
        """
        name = host if port == 22 else f"[{host}]:{port}"
        if self.hashed is not None:
            salt, digest = self.hashed
            return hmac.compare_digest(
                hmac.new(salt, name.encode(), hashlib.sha1).digest(), digest
            )
        return any(_pattern_matches(pattern, host, port) for pattern in self.patterns)

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.key_blob).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _split_pattern(pattern: str) -> Tuple[str, int]:
    """Split ``[host]:port`` into its parts, defaulting to port 22.

    The brackets cannot be left in place for matching: fnmatch reads ``[...]``
    as a character class, so ``[host.example.com]:2222`` would match a single
    character rather than that host.
    """
    if pattern.startswith("[") and "]" in pattern:
        closing = pattern.index("]")
        host = pattern[1:closing]
        remainder = pattern[closing + 1 :]
        if remainder.startswith(":") and remainder[1:].isdigit():
            return host, int(remainder[1:])
        return host, 22
    return pattern, 22


def _pattern_matches(pattern: str, host: str, port: int) -> bool:
    """known_hosts patterns use ``*`` and ``?``, and may be negated with ``!``."""
    import fnmatch

    if pattern.startswith("!"):
        return False  # a negation only excludes; it never matches on its own
    pattern_host, pattern_port = _split_pattern(pattern)
    return pattern_port == port and fnmatch.fnmatchcase(host.lower(), pattern_host.lower())


def default_known_hosts_paths() -> List[Path]:
    """The files OpenSSH reads by default."""
    home = Path(os.path.expanduser("~"))
    return [
        home / ".ssh" / "known_hosts",
        home / ".ssh" / "known_hosts2",
        Path("/etc/ssh/ssh_known_hosts"),
    ]


def load_known_hosts(paths: Optional[Sequence[Path]] = None) -> List[KnownHostsEntry]:
    """Read every readable known_hosts file, skipping lines that do not parse."""
    entries: List[KnownHostsEntry] = []
    for path in paths if paths is not None else default_known_hosts_paths():
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, raw_line in enumerate(text.splitlines(), start=1):
            entry = _parse_line(raw_line, f"{path}:{number}")
            if entry is not None:
                entries.append(entry)
    return entries


def _parse_line(line: str, source: str) -> Optional[KnownHostsEntry]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    fields = line.split()
    marker = ""
    if fields and fields[0].startswith("@"):
        marker = fields[0]
        fields = fields[1:]
    if len(fields) < 3:
        return None

    hosts, key_type, encoded = fields[0], fields[1], fields[2]
    try:
        key_blob = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None

    hashed = None
    patterns: Tuple[str, ...] = ()
    if hosts.startswith("|1|"):
        parts = hosts.split("|")
        if len(parts) != 4:
            return None
        try:
            hashed = (base64.b64decode(parts[2]), base64.b64decode(parts[3]))
        except (ValueError, binascii.Error):
            return None
    else:
        patterns = tuple(hosts.split(","))

    return KnownHostsEntry(
        patterns=patterns,
        hashed=hashed,
        key_type=key_type,
        key_blob=key_blob,
        marker=marker,
        source=source,
    )


def lookup(
    entries: Sequence[KnownHostsEntry], host: str, port: int
) -> List[KnownHostsEntry]:
    """Entries describing one host, excluding certificate authority lines."""
    return [
        entry
        for entry in entries
        if entry.marker != "@cert-authority" and entry.matches(host, port)
    ]
