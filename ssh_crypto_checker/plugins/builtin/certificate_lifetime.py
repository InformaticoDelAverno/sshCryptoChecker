"""Host certificates that are valid for too long.

The policy file can say when a certificate expires soon, because that is a
comparison against today. What it cannot say is how long the certificate was
issued *for*, because that is one date subtracted from another.

The distinction matters. A certificate valid for ten years is not expiring
soon and never will be, and it has given away the main thing certificates buy
over raw host keys: that a compromised key stops being trusted on its own,
without anyone having to reach every client's known_hosts. A ten-year host
certificate is a raw host key with extra steps.
"""

import time
from typing import Any

from ssh_crypto_checker.plugins import Detected

ID = "LONG-LIVED-HOST-CERTIFICATE"
NAME = "Host certificate issued for an excessive period"
SEVERITY = "medium"
DESCRIPTION = (
    "The certificate's validity window is long enough that a compromised host key stays "
    "trusted for years. The point of certifying host keys is that trust expires by itself; "
    "a long enough window removes that and leaves the operational cost."
)
REMEDIATION = (
    "Re-issue with a shorter window -- 'ssh-keygen -s ca -h -V +12w' is a common choice -- "
    "and automate the renewal. A certificate nobody can renew unattended is why these get "
    "issued for a decade."
)
REFERENCES = ["ssh-keygen(1), the -V option"]
NEEDS = ["host_keys"]

#: A year. Longer than most rotation policies and shorter than the ten-year
#: certificates that get issued to avoid ever thinking about it again.
_MAXIMUM_DAYS = 366

_DAY = 86400


def check(server: Any) -> Any:
    excessive = []
    for key in server.host_keys:
        certificate = getattr(key, "certificate", None)
        if certificate is None:
            continue
        start = getattr(certificate, "valid_after", None)
        end = getattr(certificate, "valid_before", None)
        if start is None or end is None:
            continue
        # A certificate with no upper bound is the extreme case of the same
        # problem, and OpenSSH writes it as the largest 64-bit value.
        if end >= 2**63 - 1:
            excessive.append(
                f"{certificate.key_id or key.algorithm}: valid forever, with no expiry at all"
            )
            continue
        days = (end - start) / _DAY
        if days > _MAXIMUM_DAYS:
            remaining = (end - time.time()) / _DAY
            excessive.append(
                f"{certificate.key_id or key.algorithm}: issued for {days:.0f} days "
                f"({remaining:.0f} still to run)"
            )

    if not excessive:
        return None
    return Detected(evidence=excessive)
