"""Minimal public-key primitives used only to complete an SSH key exchange.

.. warning::

   These implementations are **not** constant-time and must never be used to
   protect real traffic. sshCryptoChecker only needs them to send a
   syntactically valid ephemeral public value so that the server replies with
   its host key; the resulting shared secret is discarded and the connection is
   dropped before any user data is exchanged.
"""

from __future__ import annotations

__all__ = ["dh", "ecc", "x25519"]
