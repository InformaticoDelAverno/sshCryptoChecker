"""Protocol constants and algorithm tables for the SSH transport client.

Message numbers from RFC 4253 and its extensions, the size limits a scan
enforces against a hostile server, and the algorithm name-lists and lookup
tables the rest of the package proposes, drives and measures against. Nothing
here depends on any other module in the package.
"""

from __future__ import annotations

import hashlib

MSG_DISCONNECT = 1
MSG_IGNORE = 2
MSG_UNIMPLEMENTED = 3
MSG_DEBUG = 4
MSG_EXT_INFO = 7
MSG_SERVICE_REQUEST = 5
MSG_SERVICE_ACCEPT = 6
MSG_KEXINIT = 20
MSG_NEWKEYS = 21

MSG_USERAUTH_REQUEST = 50
MSG_USERAUTH_FAILURE = 51
MSG_USERAUTH_SUCCESS = 52
MSG_USERAUTH_BANNER = 53

# Numbers 30-34 are context dependent: their meaning depends on the negotiated
# key exchange method.
MSG_KEXDH_INIT = 30
MSG_KEXDH_REPLY = 31
MSG_KEX_ECDH_INIT = 30
MSG_KEX_ECDH_REPLY = 31
MSG_KEX_DH_GEX_GROUP = 31
MSG_KEX_DH_GEX_INIT = 32
MSG_KEX_DH_GEX_REPLY = 33
MSG_KEX_DH_GEX_REQUEST = 34

MAX_PACKET_SIZE = 256 * 1024
MAX_BANNER_LINES = 128
MAX_BANNER_LINE = 8192

STRICT_KEX_SERVER = "kex-strict-s-v00@openssh.com"
STRICT_KEX_CLIENT = "kex-strict-c-v00@openssh.com"

#: Offered by the scanner when it needs the negotiation to succeed. Deliberately
#: broad, including weak algorithms, so that even badly configured servers can
#: be fingerprinted. Nothing here is a recommendation.
_CLIENT_CIPHERS = [
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
    "aes256-cbc",
    "aes128-cbc",
    "3des-cbc",
]
_CLIENT_MACS = [
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
    "hmac-md5",
]
_CLIENT_COMPRESSION = ["none", "zlib@openssh.com", "zlib"]

#: Key exchange methods this scanner can drive, best first. Only used to pick a
#: method for host key retrieval.
_SUPPORTED_KEX = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha256@ssh.com",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
]

#: Hybrid and standalone post-quantum methods, and the size of the client key
#: each one expects. They are listed last on purpose: the scanner cannot derive
#: a session key from any of them, so they are only ever used to reach a host
#: key on a server that offers nothing else.
#:
#: Reaching it does not need the KEM. The server puts its host key first in the
#: reply, before the ciphertext and the signature, so a well-formed client key
#: is enough to make it answer -- and the answer is checked against a classical
#: exchange in the test suite, on a server that offers both.
_PQ_KEX_CLIENT_BYTES = {
    "mlkem768x25519-sha256": (3, 32),
    "mlkem1024nistp384-sha384": (4, 97),
    "mlkem1024-sha384": (4, 0),
    "mlkem768-sha256": (3, 0),
    "sntrup761x25519-sha512@openssh.com": (0, 1158 + 32),
    "sntrup761x25519-sha512": (0, 1158 + 32),
}

#: The modulus of ML-KEM's polynomial ring, from FIPS 203.
_MLKEM_Q = 3329

_ECDSA_CURVE_BITS = {"nistp256": 256, "nistp384": 384, "nistp521": 521}

_KEX_HASHES = {
    "ecdh-sha2-nistp256": hashlib.sha256,
    "ecdh-sha2-nistp384": hashlib.sha384,
    "ecdh-sha2-nistp521": hashlib.sha512,
}

#: Cipher and MAC the scanner proposes when it needs a working encrypted
#: session. AES-CTR with HMAC-SHA-2 is the most widely implemented pair, and
#: counter mode needs only the forward block transform.
_SESSION_CIPHERS = [
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-cbc",
    "aes192-cbc",
    "aes128-cbc",
]
#: Encrypt-then-MAC first: a hardened server often offers nothing else.
_SESSION_MACS = [
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    # Last resorts. Using a broken MAC for one throwaway packet is not a
    # security decision; it is the difference between auditing a legacy server
    # and being unable to tell anyone what it accepts.
    "hmac-sha1-etm@openssh.com",
    "hmac-sha1",
    "hmac-md5",
]
_CIPHER_KEY_SIZES = {
    "aes256-ctr": 32, "aes192-ctr": 24, "aes128-ctr": 16,
    "aes256-cbc": 32, "aes192-cbc": 24, "aes128-cbc": 16,
    "aes256-gcm@openssh.com": 32, "aes128-gcm@openssh.com": 16,
    "chacha20-poly1305@openssh.com": 64,
}
#: Ciphers that authenticate on their own, so no separate MAC is negotiated.
_AEAD_CIPHERS = {
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
}
#: Initialisation vector length per cipher; GCM takes 12 bytes, the rest a block.
_CIPHER_IV_SIZES = {"aes256-gcm@openssh.com": 12, "aes128-gcm@openssh.com": 12}
_MAC_SIZES = {
    "hmac-sha2-256-etm@openssh.com": (32, hashlib.sha256),
    "hmac-sha2-512-etm@openssh.com": (64, hashlib.sha512),
    "hmac-sha2-256": (32, hashlib.sha256),
    "hmac-sha2-512": (64, hashlib.sha512),
    "hmac-sha1-etm@openssh.com": (20, hashlib.sha1),
    "hmac-sha1": (20, hashlib.sha1),
    "hmac-md5": (16, hashlib.md5),
}
