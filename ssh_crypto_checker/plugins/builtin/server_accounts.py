"""Who can log in, and what they left lying around.

The account sweep and the private keys in home directories are one subject:
standing access. A key in authorized_keys grants it; a key in ~/.ssh is the
other half of somebody else's.
"""

from typing import Any, List

from ssh_crypto_checker.models import EffectiveConfig, Finding, Severity
from ssh_crypto_checker.policy import Policy

ID = "config-unrestricted-authorized-keys"
NAME = "Authorized keys carry no restrictions"
KIND = "check"
SEVERITY = "low"
DESCRIPTION = "Access that nobody has limited."
REMEDIATION = "Prefix entries with 'restrict' and add back only what is needed."


def check(server: Any) -> Any:
    config = server.config
    if config is None or not getattr(config, "available", False):
        return None
    findings: List[Finding] = []
    findings.extend(_authorized_key_findings(config, server.policy))
    findings.extend(_account_sweep_findings(config))
    findings.extend(_user_private_key_findings(config, server.policy))
    return findings




def _key_family_of(key_type: str) -> str:
    return _KEY_TYPE_FAMILIES.get(key_type.upper().replace("-CERT-V01@OPENSSH.COM", ""), "")


def _authorized_key_findings(
    config: EffectiveConfig, policy: Policy
) -> List[Finding]:
    """Entries in the audited account's authorized_keys.

    This is the one part of the audit that sees a user's access rather than the
    server's configuration, and it is where long-lived access accumulates: a
    key added for a contractor in 2019 is still a valid credential today unless
    somebody removed the line.
    """
    # The host-wide sweep includes the audited account, so when it worked it is
    # the complete picture and using both would report everything twice.
    if config.accounts:
        labelled = [
            (account.username, entry)
            for account in config.accounts
            for entry in account.entries
        ]
    else:
        labelled = [(config.username, entry) for entry in config.authorized_keys]

    def where(username: str) -> str:
        return f"{username}: " if len(config.accounts) > 1 or config.accounts else ""

    entries = [entry for _user, entry in labelled]
    if not entries:
        return []

    findings: List[Finding] = []
    usable = [(user, entry) for user, entry in labelled if entry.error is None]

    unreadable = [
        f"{where(user)}{entry.key_type or 'line'}: {entry.error}"
        for user, entry in labelled
        if entry.error
    ]
    if unreadable:
        findings.append(
            Finding(
                id="config-unreadable-authorized-key",
                severity=Severity.LOW,
                title="An authorized_keys line could not be parsed",
                description=(
                    "This tool could not read the line, so it cannot say what access it "
                    "grants. sshd may still be honouring it."
                ),
                remediation="Check the line by hand and remove it if it is not deliberate.",
                items=unreadable[:10],
            )
        )

    unrestricted = [
        f"{where(user)}{entry.summary}" for user, entry in usable if not entry.restricted
    ]
    if unrestricted:
        findings.append(
            Finding(
                id="config-unrestricted-authorized-keys",
                severity=Severity.LOW,
                title="Authorized keys carry no restrictions",
                description=(
                    f"{len(unrestricted)} authorized_keys entry(s) grant "
                    "a full interactive session with port forwarding. Options such as "
                    "from=, command=, restrict and no-port-forwarding limit what a stolen key "
                    "can do."
                ),
                remediation=(
                    "Prefix entries with 'restrict' and add back only what is needed, and use "
                    "from= to bind a key to the addresses it should come from."
                ),
                items=unrestricted[:10],
            )
        )

    deprecated = [
        f"{where(user)}{entry.summary}"
        for user, entry in usable
        if entry.key_type in {"ssh-dss", "ssh-rsa"}
    ]
    if deprecated:
        findings.append(
            Finding(
                id="config-weak-authorized-key",
                severity=Severity.MEDIUM,
                title="An authorized key uses a deprecated algorithm",
                description="DSA keys are 1024-bit, and ssh-rsa keys are signed with SHA-1.",
                remediation="Replace them with Ed25519 keys.",
                items=sorted(set(deprecated))[:10],
            )
        )

    # The size thresholds are the ones the policy sets for host keys: the maths
    # does not care which end of the connection a key authenticates.
    undersized = []
    for user, entry in usable:
        requirement = policy.size_requirement(entry.key_family)
        if requirement is None or entry.bits is None:
            continue
        if entry.bits < requirement.minimum_bits:
            undersized.append(
                f"{where(user)}{entry.summary} is below the "
                f"{requirement.minimum_bits}-bit minimum"
            )
    if undersized:
        findings.append(
            Finding(
                id="config-undersized-authorized-key",
                severity=Severity.HIGH,
                title="An authorized key is too short",
                description=(
                    "A key that grants access is only as strong as its size, and this one is "
                    "below the minimum this policy sets for the algorithm."
                ),
                remediation=(
                    "Have the owner generate a new key ('ssh-keygen -t ed25519') and remove "
                    "the old line."
                ),
                items=undersized[:10],
            )
        )

    expired = [f"{where(user)}{entry.summary}" for user, entry in usable if entry.expired]
    if expired:
        findings.append(
            Finding(
                id="config-expired-authorized-key",
                severity=Severity.LOW,
                title="An expired authorized key is still listed",
                description=(
                    "sshd refuses these entries, so they grant nothing today. They matter "
                    "because they show the file is not being pruned: the next entry to "
                    "outlive its purpose will not have an expiry-time to stop it."
                ),
                remediation="Remove the expired lines.",
                items=expired[:10],
            )
        )

    perpetual = [
        f"{where(user)}{entry.summary}"
        for user, entry in usable
        if entry.expires_at is None and not entry.is_certificate_authority
    ]
    if perpetual:
        findings.append(
            Finding(
                id="config-authorized-key-never-expires",
                severity=Severity.LOW,
                title="Authorized keys never expire",
                description=(
                    f"{len(perpetual)} entry(s) grant access indefinitely. Access that has to "
                    "be revoked by hand tends not to be: a key issued to somebody who has "
                    "since left keeps working until the line is deleted. An expiry-time "
                    "option, or certificates issued by a CA, make the lifetime explicit."
                ),
                remediation=(
                    "Add 'expiry-time=\"YYYYMMDD\"' to each entry, or move to certificates "
                    "with TrustedUserCAKeys and short validity."
                ),
                items=perpetual[:10],
            )
        )
    return findings


def _account_sweep_findings(config: EffectiveConfig) -> List[Finding]:
    """What the host-wide look at authorized_keys turned up."""
    findings: List[Finding] = []

    if config.unreadable_accounts:
        findings.append(
            Finding(
                id="config-accounts-unreadable",
                severity=Severity.INFO,
                title="Some accounts' authorized_keys could not be read",
                description=(
                    "These accounts have an authorized_keys file that this audit could not "
                    "open, so nothing above is claimed about them. Reading another user's "
                    "file needs root. They are listed because an account that was never "
                    "checked must not be counted as clean."
                ),
                remediation=(
                    "Run the audit as root, or grant the audit account passwordless sudo for "
                    "reading them, if you want them covered."
                ),
                items=sorted(config.unreadable_accounts)[:20],
            )
        )

    shared = [account for account in config.accounts if account.shared_with]
    for account in shared:
        everyone = sorted([account.username, *account.shared_with])
        findings.append(
            Finding(
                id="config-shared-authorized-keys",
                severity=Severity.HIGH,
                title="One authorized_keys file grants access to several accounts",
                description=(
                    f"AuthorizedKeysFile resolves to {account.path} for {len(everyone)} "
                    "accounts, because the path contains no %u. Every key in that file can "
                    "log in as any of them, including root if root is among them, and "
                    "removing somebody's access from one account removes it from all."
                ),
                remediation=(
                    "Put %u in the path, for example "
                    "'AuthorizedKeysFile /etc/ssh/authorized_keys/%u', and split the file."
                ),
                items=everyone[:20],
            )
        )
    return findings


def _user_private_key_findings(config: EffectiveConfig, policy: Policy) -> List[Finding]:
    """Private keys sitting in home directories on the audited host.

    Nothing about the server's configuration changes what these are: a
    credential in a file. A key with no passphrase is usable by whoever reads
    it, everywhere that key is trusted -- which is usually somewhere else.
    """
    keys = config.user_keys
    if not keys:
        return []
    findings: List[Finding] = []

    def describe(key: Any) -> str:
        parts = [f"{key.username}: {key.path}"]
        if key.key_type:
            parts.append(f"{key.bits or '?'}-bit {key.key_type}")
        if key.mode is not None:
            parts.append(f"mode {key.mode.mode}")
        return " ".join(parts)

    unencrypted = [describe(key) for key in keys if key.encrypted is False]
    if unencrypted:
        findings.append(
            Finding(
                id="config-unencrypted-user-key",
                severity=Severity.MEDIUM,
                title="A private key is stored without a passphrase",
                description=(
                    "Anyone who reads the file has the key, and a key stored in the clear "
                    "survives a backup, a snapshot and a stolen disk. Automation is the usual "
                    "reason, and the usual answer is a key restricted with from= and "
                    "command= so that reading it grants only the one operation it exists for."
                ),
                remediation=(
                    "Add a passphrase with 'ssh-keygen -p -f <key>', or restrict what the key "
                    "can do on the servers that trust it."
                ),
                items=unencrypted[:15],
            )
        )

    exposed = [describe(key) for key in keys if key.exposed]
    if exposed:
        findings.append(
            Finding(
                id="config-exposed-user-key",
                severity=Severity.HIGH,
                title="A private key is readable beyond its owner",
                description=(
                    "The file permissions let another account on this host read the key. "
                    "ssh refuses to use a key like this, which tends to mean somebody will "
                    "loosen something else rather than fix it."
                ),
                remediation="Run 'chmod 600' on the keys listed and check their ownership.",
                items=exposed[:15],
            )
        )

    undersized = []
    for key in keys:
        family = _key_family_of(key.key_type)
        requirement = policy.size_requirement(family) if family else None
        if requirement is None or key.bits is None:
            continue
        if key.bits < requirement.minimum_bits:
            undersized.append(
                f"{describe(key)} is below the {requirement.minimum_bits}-bit minimum"
            )
    if undersized:
        findings.append(
            Finding(
                id="config-undersized-user-key",
                severity=Severity.MEDIUM,
                title="A private key on this host is too short",
                description=(
                    "The key is below the minimum this policy sets for its algorithm. It is "
                    "as weak wherever it is trusted as it is here."
                ),
                remediation=(
                    "Replace it with 'ssh-keygen -t ed25519' and update the "
                    "servers that trust it."
                ),
                items=undersized[:15],
            )
        )

    unknown = [describe(key) for key in keys if key.encrypted is None]
    if unknown:
        findings.append(
            Finding(
                id="config-user-key-unreadable",
                severity=Severity.INFO,
                title="A private key could not be examined",
                description=(
                    "The file exists and this audit could not read enough of it to say "
                    "whether it has a passphrase. Nothing is claimed about it either way."
                ),
                remediation="Run the audit as root if you want these covered.",
                items=unknown[:15],
            )
        )
    return findings


#: Key type as ssh-keygen prints it -> the family the policy sets sizes for.
_KEY_TYPE_FAMILIES = {
    "RSA": "rsa",
    "DSA": "dsa",
    "ECDSA": "ecdsa",
    "ED25519": "ed25519",
    "ED448": "ed448",
    "SK-ECDSA": "ecdsa",
    "SK-ED25519": "ed25519",
}
