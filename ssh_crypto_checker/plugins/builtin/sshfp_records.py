"""Host keys against the SSHFP records published for the name.

One subject: what DNS says about this server's keys. The four things that can
be wrong with that are read from one comparison, so they belong together.
"""

from typing import Any

from ssh_crypto_checker.plugins import Detected

ID = "no-sshfp-records"
NAME = "No SSHFP records published in DNS"
KIND = "check"
SEVERITY = "low"
DESCRIPTION = (
    "Without SSHFP records a client connecting for the first time has nothing to verify the "
    "host key against, so it either accepts it blindly or relies on the user to compare a "
    "fingerprint by hand."
)
REMEDIATION = (
    "Publish the records with 'ssh-keygen -r <hostname>' and sign the zone with DNSSEC, then "
    "clients can use 'VerifyHostKeyDNS yes'."
)
#: No NEEDS on purpose. NEEDS is for a check that cannot answer -- where not
#: looking could be mistaken for not finding anything. This one is opt-in: its
#: data is absent because the operator did not ask for it, and reporting that
#: as "undetermined" on every ordinary scan would be noise, not honesty.



def check(server: Any) -> Any:
    records = server.sshfp
    if records is None or not records.queried or records.error:
        return None
    if records.records_found == 0:
        return Detected()

    found = []
    if records.keys_without_record:
        found.append(
            Detected(
                id="host-key-without-sshfp",
                name="A host key has no matching SSHFP record",
                severity="medium",
                description=(
                    "DNS publishes SSHFP records for this name, but not for every key the "
                    "server presents. A client verifying by DNS will reject the unlisted key, "
                    "and the mismatch may mean the records are stale after a key rotation."
                ),
                remediation="Regenerate the records with 'ssh-keygen -r <hostname>' and republish.",
                evidence=records.keys_without_record,
            )
        )
    if records.unmatched_records:
        found.append(
            Detected(
                id="stale-sshfp-record",
                name="SSHFP records point at keys the server no longer presents",
                description=(
                    "These published fingerprints match none of the server's current keys, "
                    "which usually means a rotation left the zone behind."
                ),
                remediation="Remove the obsolete records from the zone.",
                evidence=records.unmatched_records,
            )
        )
    if records.matched and not records.dnssec_authenticated:
        found.append(
            Detected(
                id="sshfp-without-dnssec",
                name="SSHFP records are not DNSSEC-validated",
                description=(
                    "The records match the server's keys, but the resolver did not report a "
                    "validated answer. Unsigned SSHFP records can be forged by whoever controls "
                    "the DNS path, so OpenSSH will not trust them automatically."
                ),
                remediation="Sign the zone with DNSSEC so clients can rely on the records.",
                evidence=records.matched,
            )
        )
    return found
