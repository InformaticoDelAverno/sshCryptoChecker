"""Host keys presented by more than one server in the scan.

The first fleet check, and the reason that kind exists. A host key is not
shared in any sense that looking at one machine could reveal: it is shared
*relative to another key*, so no per-server check can ever find it, however
thorough.

It almost always means cloned virtual machines or a golden image with the key
baked in. The consequence is worse than it sounds: extracting the private key
from the least important of those hosts is enough to impersonate every one of
them, and no client can tell.
"""

from typing import Any, Dict, List

from ssh_crypto_checker.models import Finding, Severity
from ssh_crypto_checker.plugins import ForTarget

ID = "shared-host-key"
NAME = "This host key is shared with another scanned server"
KIND = "fleet"
SEVERITY = "high"
DESCRIPTION = (
    "The same host key is presented by more than one server in this scan. That usually means "
    "cloned virtual machines or an image with the key baked in. Anyone who extracts the "
    "private key from any one of them can impersonate all of them, and clients cannot tell "
    "the difference."
)
REMEDIATION = (
    "Regenerate the host keys on all but one machine: delete /etc/ssh/ssh_host_* and run "
    "'ssh-keygen -A', then restart sshd and update the clients' known_hosts. Fix the image or "
    "provisioning step that produced the duplicate."
)


def check(fleet: Any) -> Any:
    by_fingerprint: Dict[str, List[Any]] = {}
    for server in fleet.with_host_keys():
        for key in server.view.host_keys:
            if key.error is None and key.fingerprint_sha256:
                by_fingerprint.setdefault(key.fingerprint_sha256, []).append(server)

    found = []
    for fingerprint, sharing in by_fingerprint.items():
        names = sorted({server.target for server in sharing})
        if len(names) < 2:
            continue
        for server in sharing:
            peers = [name for name in names if name != server.target]
            found.append(
                ForTarget(
                    target=server.target,
                    finding=Finding(
                        id=ID,
                        severity=Severity.HIGH,
                        title=NAME,
                        description=DESCRIPTION,
                        remediation=REMEDIATION,
                        items=[fingerprint, "also presented by: " + ", ".join(peers)],
                    ),
                )
            )
    return found
