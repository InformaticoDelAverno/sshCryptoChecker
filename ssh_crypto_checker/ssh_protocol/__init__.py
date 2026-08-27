"""Client side of the SSH transport layer, limited to what an audit needs.

The package speaks just enough of RFC 4253 to:

* exchange identification strings and record the server's banner,
* read the server's ``SSH_MSG_KEXINIT`` and therefore every algorithm it is
  willing to negotiate,
* optionally run a key exchange far enough for the server to send its host key,
  which reveals the key type, size and fingerprint.

No user data is ever exchanged and no authentication is attempted: the socket
is closed as soon as the host key arrives. Scans do show up in the server's
auth log as a connection closed before authentication.

It was one module until it grew past readability; it is now a package whose
submodules stack in one direction -- :mod:`.constants`, :mod:`.wire`,
:mod:`.messages`, :mod:`.transport`, :mod:`.kex`, :mod:`.probe` -- and this
``__init__`` re-exports (with redundant aliases, so the linter reads them as the
deliberate re-exports they are) every name they defined, so ``from
ssh_crypto_checker.ssh_protocol import X`` still finds it.
"""

from __future__ import annotations

# ``socket`` and ``time`` are re-exported so a test that patches
# ``ssh_protocol.socket.getaddrinfo`` or ``ssh_protocol.time.monotonic`` reaches
# the same module objects the submodules use; ``x25519`` likewise, for the test
# that wraps its ``scalar_mult``.
import socket as socket
import time as time

from ..crypto import x25519 as x25519
from ..models import AuthMethods as AuthMethods
from ..models import BannerInfo as BannerInfo
from ..models import CertificateInfo as CertificateInfo
from ..models import HostKeyInfo as HostKeyInfo
from ..models import KexInit as KexInit
from .constants import (
    _AEAD_CIPHERS as _AEAD_CIPHERS,
)
from .constants import (
    _CIPHER_IV_SIZES as _CIPHER_IV_SIZES,
)
from .constants import (
    _CIPHER_KEY_SIZES as _CIPHER_KEY_SIZES,
)
from .constants import (
    _CLIENT_CIPHERS as _CLIENT_CIPHERS,
)
from .constants import (
    _CLIENT_COMPRESSION as _CLIENT_COMPRESSION,
)
from .constants import (
    _CLIENT_MACS as _CLIENT_MACS,
)
from .constants import (
    _ECDSA_CURVE_BITS as _ECDSA_CURVE_BITS,
)
from .constants import (
    _KEX_HASHES as _KEX_HASHES,
)
from .constants import (
    _MAC_SIZES as _MAC_SIZES,
)
from .constants import (
    _MLKEM_Q as _MLKEM_Q,
)
from .constants import (
    _PQ_KEX_CLIENT_BYTES as _PQ_KEX_CLIENT_BYTES,
)
from .constants import (
    _SESSION_CIPHERS as _SESSION_CIPHERS,
)
from .constants import (
    _SESSION_MACS as _SESSION_MACS,
)
from .constants import (
    _SUPPORTED_KEX as _SUPPORTED_KEX,
)
from .constants import (
    MAX_BANNER_LINE as MAX_BANNER_LINE,
)
from .constants import (
    MAX_BANNER_LINES as MAX_BANNER_LINES,
)
from .constants import (
    MAX_PACKET_SIZE as MAX_PACKET_SIZE,
)
from .constants import (
    MSG_DEBUG as MSG_DEBUG,
)
from .constants import (
    MSG_DISCONNECT as MSG_DISCONNECT,
)
from .constants import (
    MSG_EXT_INFO as MSG_EXT_INFO,
)
from .constants import (
    MSG_IGNORE as MSG_IGNORE,
)
from .constants import (
    MSG_KEX_DH_GEX_GROUP as MSG_KEX_DH_GEX_GROUP,
)
from .constants import (
    MSG_KEX_DH_GEX_INIT as MSG_KEX_DH_GEX_INIT,
)
from .constants import (
    MSG_KEX_DH_GEX_REPLY as MSG_KEX_DH_GEX_REPLY,
)
from .constants import (
    MSG_KEX_DH_GEX_REQUEST as MSG_KEX_DH_GEX_REQUEST,
)
from .constants import (
    MSG_KEX_ECDH_INIT as MSG_KEX_ECDH_INIT,
)
from .constants import (
    MSG_KEX_ECDH_REPLY as MSG_KEX_ECDH_REPLY,
)
from .constants import (
    MSG_KEXDH_INIT as MSG_KEXDH_INIT,
)
from .constants import (
    MSG_KEXDH_REPLY as MSG_KEXDH_REPLY,
)
from .constants import (
    MSG_KEXINIT as MSG_KEXINIT,
)
from .constants import (
    MSG_NEWKEYS as MSG_NEWKEYS,
)
from .constants import (
    MSG_SERVICE_ACCEPT as MSG_SERVICE_ACCEPT,
)
from .constants import (
    MSG_SERVICE_REQUEST as MSG_SERVICE_REQUEST,
)
from .constants import (
    MSG_UNIMPLEMENTED as MSG_UNIMPLEMENTED,
)
from .constants import (
    MSG_USERAUTH_BANNER as MSG_USERAUTH_BANNER,
)
from .constants import (
    MSG_USERAUTH_FAILURE as MSG_USERAUTH_FAILURE,
)
from .constants import (
    MSG_USERAUTH_REQUEST as MSG_USERAUTH_REQUEST,
)
from .constants import (
    MSG_USERAUTH_SUCCESS as MSG_USERAUTH_SUCCESS,
)
from .constants import (
    STRICT_KEX_CLIENT as STRICT_KEX_CLIENT,
)
from .constants import (
    STRICT_KEX_SERVER as STRICT_KEX_SERVER,
)
from .kex import (
    _decode_point as _decode_point,
)
from .kex import (
    _discard_wrong_guess as _discard_wrong_guess,
)
from .kex import (
    _kex_hash as _kex_hash,
)
from .kex import (
    _mlkem_encapsulation_key as _mlkem_encapsulation_key,
)
from .kex import (
    _pq_client_key as _pq_client_key,
)
from .kex import (
    _run_key_exchange as _run_key_exchange,
)
from .kex import (
    select_kex_for_probe as select_kex_for_probe,
)
from .messages import (
    _EXACT_PRODUCTS as _EXACT_PRODUCTS,
)
from .messages import (
    _PRODUCT_PREFIXES as _PRODUCT_PREFIXES,
)
from .messages import (
    _build_client_kexinit as _build_client_kexinit,
)
from .messages import (
    _fingerprint as _fingerprint,
)
from .messages import (
    _identify_product as _identify_product,
)
from .messages import (
    _read_certificate_fields as _read_certificate_fields,
)
from .messages import (
    _read_public_key_fields as _read_public_key_fields,
)
from .messages import (
    parse_banner as parse_banner,
)
from .messages import (
    parse_ext_info as parse_ext_info,
)
from .messages import (
    parse_host_key_blob as parse_host_key_blob,
)
from .messages import (
    parse_kexinit_payload as parse_kexinit_payload,
)
from .probe import (
    _negotiate as _negotiate,
)
from .probe import (
    _read_auth_response as _read_auth_response,
)
from .probe import (
    fetch_host_key as fetch_host_key,
)
from .probe import (
    measure_login_grace as measure_login_grace,
)
from .probe import (
    measure_max_startups as measure_max_startups,
)
from .probe import (
    probe_auth_methods as probe_auth_methods,
)
from .probe import (
    probe_server as probe_server,
)
from .transport import (
    DNS_CACHE_TTL as DNS_CACHE_TTL,
)
from .transport import (
    SSHTransport as SSHTransport,
)
from .transport import (
    _connect as _connect,
)
from .transport import (
    _describe_disconnect as _describe_disconnect,
)
from .transport import (
    _ExchangeContext as _ExchangeContext,
)
from .transport import (
    _KexReply as _KexReply,
)
from .transport import (
    _resolve as _resolve,
)
from .transport import (
    clear_dns_cache as clear_dns_cache,
)
from .wire import (
    Reader as Reader,
)
from .wire import (
    SSHConnectionError as SSHConnectionError,
)
from .wire import (
    SSHDisconnect as SSHDisconnect,
)
from .wire import (
    SSHDisconnectError as SSHDisconnectError,
)
from .wire import (
    SSHError as SSHError,
)
from .wire import (
    SSHProtocolError as SSHProtocolError,
)
from .wire import (
    _build_body as _build_body,
)
from .wire import (
    build_packet as build_packet,
)
from .wire import (
    pack_mpint as pack_mpint,
)
from .wire import (
    pack_name_list as pack_name_list,
)
from .wire import (
    pack_string as pack_string,
)
from .wire import (
    printable as printable,
)

__all__ = [
    "SSHConnectionError",
    "SSHError",
    "SSHProtocolError",
    "fetch_host_key",
    "measure_login_grace",
    "measure_max_startups",
    "parse_banner",
    "parse_ext_info",
    "parse_host_key_blob",
    "parse_kexinit_payload",
    "probe_auth_methods",
    "probe_server",
]
