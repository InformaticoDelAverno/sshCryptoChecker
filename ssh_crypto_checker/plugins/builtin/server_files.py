"""The files sshd depends on: their permissions, its moduli, its package.

Three readings of the same host, all of them about what is on disk rather than
what is configured.
"""

from typing import Any, List

from ssh_crypto_checker.models import EffectiveConfig, Finding, Severity
from ssh_crypto_checker.policy import Policy

ID = "config-host-key-permissions"
NAME = "A host private key is readable beyond its owner"
KIND = "check"
SEVERITY = "critical"
DESCRIPTION = (
    "Anyone who can read the private key can impersonate this server to every client that "
    "trusts it, and no client can tell the difference."
)
REMEDIATION = (
    "Run 'chmod 600 /etc/ssh/ssh_host_*_key' and 'chown root:root' them, then treat the keys "
    "as compromised and rotate them."
)


def check(server: Any) -> Any:
    config = server.config
    if config is None or not getattr(config, "available", False):
        return None
    findings: List[Finding] = []
    findings.extend(_file_mode_findings(config))
    findings.extend(_moduli_findings(config, server.policy))
    findings.extend(_package_findings(config))
    return findings


def _file_mode_findings(config: EffectiveConfig) -> List[Finding]:
    """Permissions on the files sshd depends on."""
    exposed_private = [
        f"{mode.path} is mode {mode.mode}, owned by {mode.owner}"
        for mode in config.file_modes
        if mode.path.endswith("_key") and mode.readable_beyond_owner
    ]
    writable = [
        f"{mode.path} is mode {mode.mode}"
        for mode in config.file_modes
        if not mode.path.endswith("_key") and mode.group_or_world_writable
    ]
    findings = []
    if exposed_private:
        findings.append(
            Finding(
                id="config-host-key-permissions",
                severity=Severity.CRITICAL,
                title="A host private key is readable beyond its owner",
                description=(
                    "Anyone who can read the private key can impersonate this server to every "
                    "client that trusts it, and no client can tell the difference."
                ),
                remediation=(
                    "Run 'chmod 600 /etc/ssh/ssh_host_*_key' and 'chown root:root' them, then "
                    "treat the keys as compromised and rotate them."
                ),
                items=exposed_private,
            )
        )
    if writable:
        findings.append(
            Finding(
                id="config-file-permissions",
                severity=Severity.HIGH,
                title="A file sshd trusts is writable beyond its owner",
                description=(
                    "Whoever can write to it controls how the server authenticates."
                ),
                remediation="Run 'chmod go-w' on the paths listed and check their ownership.",
                items=writable,
            )
        )
    return findings


def _moduli_findings(config: EffectiveConfig, policy: Policy) -> List[Finding]:
    """Groups the server has on offer, not just the one it gave us.

    The measured group is the server's answer to this client's request. A
    client asking for less gets less, and that is what the file decides.
    """
    moduli = config.moduli
    if moduli is None or not moduli.sizes:
        return []
    minimum = policy.dh_requirement.minimum_bits
    small = moduli.below(minimum)
    if not small:
        return []
    return [
        Finding(
            id="config-small-moduli-available",
            severity=Severity.MEDIUM,
            title="Diffie-Hellman groups below the minimum are still available",
            description=(
                f"{sum(small.values())} of the {moduli.total} groups in {moduli.path} are "
                f"smaller than the {minimum}-bit minimum this policy sets, the smallest being "
                f"{moduli.smallest} bits. The size measured during a scan is only what the "
                "server offered this client; a client that asks for a smaller group is given "
                "one of these, and the smallest is what an attacker would ask for."
            ),
            remediation=(
                f"Strip the small groups: awk '$5 >= {minimum - 1}' {moduli.path} > "
                f"{moduli.path}.safe && mv {moduli.path}.safe {moduli.path}, then restart sshd. "
                "Regenerating them from scratch takes hours; filtering the shipped file does not."
            ),
            items=[f"{size}-bit: {count} group(s)" for size, count in sorted(small.items())],
        )
    ]


def _package_findings(config: EffectiveConfig) -> List[Finding]:
    """The distribution package behind the version string.

    Not a problem in itself. It is here because every version-based finding in
    this report comes with a caveat about backported fixes, and this is the
    thing that settles the caveat.
    """
    package = config.package
    if package is None or not package.known:
        return []
    detail = f"{package.name} {package.version} via {package.manager}"
    if package.os_name:
        detail += f" on {package.os_name}"
    description = (
        "The findings matched on the advertised version cannot tell a genuinely old "
        "release from one a distribution has patched in place. This is the package that "
        "provides sshd, so its changelog is what confirms or clears them."
    )
    if package.looks_patched:
        description += (
            " This version carries a distribution revision, which means the advertised "
            "version is definitely not the whole story."
        )
    command = {
        "dpkg": f"apt changelog {package.name}",
        "rpm": f"rpm -q --changelog {package.name}",
        "apk": f"apk info -a {package.name}",
    }.get(package.manager, "the package manager's changelog")

    items = [detail]
    if package.changelog_read:
        items.append(
            f"changelog read from {package.changelog_source}: "
            f"{len(package.changelog_cves)} CVE(s) named"
        )
        description += (
            " Its changelog was read, so the version-based findings it names are recorded at "
            "informational severity with the reason attached."
        )
        remediation = (
            "Nothing to do for the CVEs the changelog names. For the rest, check "
            f"{command} and the distribution's security tracker."
        )
    else:
        reason = package.changelog_error or "it was not found"
        items.append(f"no changelog available: {reason}")
        description += (
            " Its changelog could not be read, so none of the version-based findings above "
            "could be settled that way and all of them keep their severity. Container "
            "images commonly strip /usr/share/doc, which is where it lives."
        )
        remediation = f"Check the changelog for the CVEs reported above: {command}"

    return [
        Finding(
            id="config-package-version",
            severity=Severity.INFO,
            title="Distribution package providing sshd",
            description=description,
            remediation=remediation,
            items=items,
        )
    ]
