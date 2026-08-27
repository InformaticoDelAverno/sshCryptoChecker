"""sshCryptoChecker -- audit the cryptography offered by SSH servers.

The package is deliberately dependency-free so it can be dropped onto any
host that has a reasonably modern Python 3 interpreter.

Public entry points:
    ssh_crypto_checker.cli.main          -- command line interface
    ssh_crypto_checker.scanner.scan      -- programmatic scanning API
    ssh_crypto_checker.policy.Policy     -- the algorithm database
"""

from __future__ import annotations

__all__ = ["CLIENT_BANNER", "PRODUCT_NAME", "__version__"]

__version__ = "1.1.0"

PRODUCT_NAME = "sshCryptoChecker"

#: Identification string sent to the scanned server. It is intentionally
#: recognisable so administrators can correlate the scan with their auth logs.
CLIENT_BANNER = f"SSH-2.0-sshCryptoChecker_{__version__}"
