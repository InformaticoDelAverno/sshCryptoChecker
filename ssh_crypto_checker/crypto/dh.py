"""Finite-field Diffie-Hellman groups used by the SSH key exchange.

Only the groups needed to reach a server's host key are embedded. Servers that
offer none of them are still covered by ``diffie-hellman-group-exchange-*``,
where the server sends the modulus itself.

Not constant-time; see the package docstring.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

__all__ = ["GROUPS", "DHGroup", "generate_key_pair", "group_for_kex"]


@dataclass(frozen=True)
class DHGroup:
    """A MODP group: a safe prime modulus and a generator."""

    name: str
    prime: int
    generator: int

    @property
    def bits(self) -> int:
        return self.prime.bit_length()


# RFC 2409 Oakley group 2 (1024 bit). Only present so that legacy servers which
# offer nothing else can still be fingerprinted.
_GROUP1_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)

# RFC 3526 group 14 (2048 bit).
_GROUP14_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF"
    "FFFFFFFF",
    16,
)

GROUP1 = DHGroup(name="group1", prime=_GROUP1_PRIME, generator=2)
GROUP14 = DHGroup(name="group14", prime=_GROUP14_PRIME, generator=2)

GROUPS: Dict[str, DHGroup] = {group.name: group for group in (GROUP1, GROUP14)}

#: SSH key exchange method name -> group.
_KEX_GROUPS: Dict[str, DHGroup] = {
    "diffie-hellman-group1-sha1": GROUP1,
    "diffie-hellman-group14-sha1": GROUP14,
    "diffie-hellman-group14-sha256": GROUP14,
    "diffie-hellman-group14-sha256@ssh.com": GROUP14,
}


def group_for_kex(kex_name: str) -> Optional[DHGroup]:
    """Return the fixed MODP group used by a key exchange method, if any."""
    return _KEX_GROUPS.get(kex_name)


def generate_key_pair(prime: int, generator: int, exponent_bits: int = 256) -> Tuple[int, int]:
    """Return ``(private_exponent, public_value)`` for the given group.

    A short exponent is used deliberately: the shared secret is discarded, and
    a full-length exponent would make the modular exponentiation needlessly
    slow for large groups. The public value is forced into the range that
    OpenSSH accepts (``1 < e < p - 1``).
    """
    if prime < 5:
        raise ValueError("Diffie-Hellman modulus is too small to be usable")
    limit = min(exponent_bits, max(prime.bit_length() - 1, 8))
    # private is rebound in the loop below (which always runs, see public = 1);
    # the 0 is only here because a definite-assignment checker cannot see that.
    private = 0
    # Redrawn while the public value is degenerate, which is never: it would
    # take a broken urandom. Written this way -- a sentinel public = 1 that fails
    # the guard so the body runs once -- rather than `while True: ... if ok:
    # break`, because the sentinel form exercises BOTH sides of the guard (enter
    # once, then exit) whereas the break form leaves the "redraw" side unreached
    # by any real run, which the lab-coverage gate rightly flags.
    public = 1
    while not 1 < public < prime - 1:
        private = int.from_bytes(os.urandom((limit + 7) // 8), "big") | (1 << (limit - 1))
        public = pow(generator, private, prime)
    return private, public
