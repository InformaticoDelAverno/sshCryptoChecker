"""The server's key against what a client already has recorded.

Both outcomes come from the same comparison and mean the same class of thing:
the key on the wire is not the key somebody wrote down.
"""

from typing import Any

from ssh_crypto_checker.plugins import Detected

ID = "revoked-host-key"
NAME = "The server presents a host key marked @revoked"
KIND = "check"
SEVERITY = "critical"
DESCRIPTION = (
    "A local known_hosts file records this exact key as revoked, so a client configured with "
    "that file will refuse the connection outright. A revoked key still in service usually "
    "means a compromised key was never replaced."
)
REMEDIATION = "Generate a new host key, deploy it, and remove the revoked one."
#: No NEEDS on purpose. NEEDS is for a check that cannot answer -- where not
#: looking could be mistaken for not finding anything. This one is opt-in: its
#: data is absent because the operator did not ask for it, and reporting that
#: as "undetermined" on every ordinary scan would be noise, not honesty.



def check(server: Any) -> Any:
    record = server.known_hosts
    if record is None or not record.checked:
        return None
    found = []
    if record.revoked:
        found.append(Detected(evidence=record.revoked))
    if record.changed:
        found.append(
            Detected(
                id="host-key-changed",
                name="The host key differs from the one recorded locally",
                severity="high",
                description=(
                    "A known_hosts file records a different key of the same type for this "
                    "host. That is either an undocumented key rotation or an interception, and "
                    "a client using that file will refuse to connect until someone decides "
                    "which."
                ),
                remediation=(
                    "Confirm the current fingerprint out of band, then update the clients with "
                    "'ssh-keygen -R <host>' followed by a fresh connection."
                ),
                evidence=record.changed,
            )
        )
    return found
