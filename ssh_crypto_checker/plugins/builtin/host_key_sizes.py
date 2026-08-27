"""How big the host keys are, and the group used to fetch them.

Reports what the assessment also measures. The two are deliberately separate:
``assessment.host_key_flags`` decides what the grade is allowed to be, this
decides what the report says about it. Deleting this file changes the report
and leaves the grade exactly where it was.
"""

from typing import Any, List

from ssh_crypto_checker.models import Finding, Severity

ID = "host-key-too-small"
NAME = "Host key below the minimum size"
KIND = "check"
SEVERITY = "high"
DESCRIPTION = "A host key is smaller than this policy allows."
REMEDIATION = "Generate a larger key, or an Ed25519 one."
NEEDS = ["host_keys"]


def check(server: Any) -> Any:
    return _host_key_findings(server.policy, server.host_keys)


def _host_key_findings(policy: Any, host_keys: Any) -> List[Finding]:
    """What the report says about host key sizes and the group they came over.

    It used to hand back three flags as well -- below minimum, below
    recommended, weak group -- and a `now` for judging certificate validity.
    Both jobs moved: the grade is decided by assessment.host_key_flags and
    certificates by the certificate_lifetime check. The flags kept being
    assigned to for a while after nothing read them, which is a comment that
    lies rather than a comment that is out of date.
    """
    findings: List[Finding] = []

    undersized: List[str] = []
    small: List[str] = []
    for key in host_keys:
        # A partially parsed blob can leave a bits value of 0 behind. Judging
        # it would invent an "RSA 0 bits" finding out of a parse failure.
        if key.error is not None or not key.bits or not key.key_family:
            continue
        requirement = policy.size_requirement(key.key_family)
        if requirement is None:
            continue
        label = (
            f"{key.algorithm} ({key.key_family.upper()} {key.bits} bits, "
            f"{key.fingerprint_sha256})"
        )
        if key.bits < requirement.minimum_bits:
            undersized.append(f"{label} < {requirement.minimum_bits} bits required")
        elif key.bits < requirement.recommended_bits:
            small.append(f"{label} < {requirement.recommended_bits} bits recommended")

    if undersized:
        findings.append(
            Finding(
                id="host-key-too-small",
                severity=Severity.HIGH,
                title="Host key below the minimum size",
                description=(
                    "A host key smaller than the policy minimum can be attacked by a "
                    "well-resourced adversary, allowing them to impersonate the server."
                ),
                remediation=(
                    "Generate a new key (ssh-keygen -t ed25519, or ssh-keygen -t rsa -b 4096), "
                    "point HostKey at it, restart sshd and remove the old key. Clients will need "
                    "their known_hosts entry updated."
                ),
                items=undersized,
            )
        )
    if small:
        findings.append(
            Finding(
                id="host-key-small",
                severity=Severity.LOW,
                title="Host key below the recommended size",
                description="The key is above the hard minimum but below the recommended size.",
                remediation="Plan a key rotation to the recommended size, ideally to Ed25519.",
                items=small,
            )
        )

    weak_groups = [
        f"{key.algorithm}: {key.dh_group_bits}-bit group via {key.kex_used}"
        for key in host_keys
        if key.dh_group_bits is not None and key.dh_group_bits < policy.dh_requirement.minimum_bits
    ]
    if weak_groups:
        findings.append(
            Finding(
                id="weak-dh-group",
                severity=Severity.HIGH,
                title="Diffie-Hellman group below the minimum size",
                description=(
                    "The server completed a key exchange using a modulus smaller than the policy "
                    "minimum. Small groups are vulnerable to precomputation attacks such as Logjam."
                ),
                remediation=(
                    "Remove short moduli: awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe "
                    "&& mv /etc/ssh/moduli.safe /etc/ssh/moduli, then restart sshd. Also disable "
                    "diffie-hellman-group1-sha1."
                ),
                items=weak_groups,
            )
        )


    errors = [f"{key.algorithm}: {key.error}" for key in host_keys if key.error]
    if errors and not any(key.error is None for key in host_keys):
        findings.append(
            Finding(
                id="host-key-unavailable",
                severity=Severity.INFO,
                title="Host keys could not be retrieved",
                description=(
                    "The algorithm analysis is complete, but no host key could be fetched, so key "
                    "sizes and fingerprints were not verified."
                ),
                remediation=(
                    "Check that the scanner is allowed to complete a key exchange "
                    "with the server."
                ),
                items=errors,
            )
        )

    return findings
