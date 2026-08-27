"""Host certificate validity.

One subject, one file. The three states a certificate can be in are read from
the same two fields and explained by the same paragraph, so splitting them
across three plugins would mean three copies of the same loop.
"""

import time
from typing import Any

from ssh_crypto_checker.plugins import Detected

ID = "host-certificate-expired"
NAME = "Host certificate has expired"
KIND = "check"
SEVERITY = "high"
DESCRIPTION = "Clients that verify host certificates will refuse to connect."
REMEDIATION = (
    "Reissue the certificate with "
    "'ssh-keygen -s ca_key -h -I <id> -n <principals> -V <window>'."
)
NEEDS = ["host_keys"]

_DAY = 86400


def _when(timestamp: Any) -> Any:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(timestamp))
    except (ValueError, OSError, OverflowError):
        return f"timestamp {timestamp}"


def check(server: Any) -> Any:
    now = time.time()
    warning_days = server.requirement("certificate_expiry_warning_days", 30)
    window = warning_days * _DAY

    expired, not_yet_valid, expiring = [], [], []
    for key in server.host_keys:
        certificate = getattr(key, "certificate", None)
        if certificate is None:
            continue
        identity = certificate.key_id or key.algorithm
        ends = certificate.valid_before
        starts = certificate.valid_after
        if ends is not None and ends < now:
            expired.append(f"{identity}: expired on {_when(ends)}")
        elif ends is not None and ends - now < window:
            expiring.append(f"{identity}: expires on {_when(ends)}")
        if starts is not None and starts > now:
            not_yet_valid.append(f"{identity}: not valid before {_when(starts)}")

    found = []
    if expired:
        found.append(Detected(evidence=expired))
    if not_yet_valid:
        found.append(
            Detected(
                id="host-certificate-not-yet-valid",
                name="Host certificate is not valid yet",
                description=(
                    "The certificate's validity window starts in the future. This usually "
                    "means the clock on the issuing host was wrong."
                ),
                remediation=(
                    "Reissue the certificate with a correct validity interval and check NTP."
                ),
                evidence=not_yet_valid,
            )
        )
    if expiring:
        found.append(
            Detected(
                id="host-certificate-expiring",
                name="Host certificate expires soon",
                severity="medium",
                description=f"The certificate expires within {warning_days} days.",
                remediation="Schedule the renewal before the expiry date.",
                evidence=expiring,
            )
        )
    return found
