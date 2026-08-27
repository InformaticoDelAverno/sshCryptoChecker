"""The protocol-level properties of the negotiation.

Strict key exchange, post-quantum readiness, encrypt-then-MAC, AEAD and
whether anything was left unjudged. All of them are properties of the offer as
a whole rather than of one algorithm, and all are read from the same
classification.
"""

from typing import Any, List

from ssh_crypto_checker.models import Finding, PostQuantumStatus, Severity
from ssh_crypto_checker.policy import Policy

ID = "no-strict-kex"
NAME = "Strict key exchange is not negotiated"
KIND = "check"
SEVERITY = "medium"
DESCRIPTION = (
    "The server does not negotiate strict key exchange, so the handshake transcript is "
    "not authenticated and messages can be dropped from it without either end noticing."
)
REMEDIATION = "Upgrade to OpenSSH 9.6 or later."


def check(server: Any) -> Any:
    # A plugin must survive a view with nothing in it: that is the contract
    # every check here is held to, and tests/test_plugins.py walks all of them
    # with an empty one. The lab never produces such a view -- analyse stops
    # before any plugin runs when there is no offer -- so this line is covered
    # by that test and not by a server.
    if server.kexinit is None:
        return None
    return _protocol_findings(server, server.policy)


#: The tag the policy puts on a hybrid method, so this reads the policy's
#: opinion rather than carrying its own list of algorithm names.
_POST_QUANTUM = "post-quantum"
#: Read through the view rather than imported from the assessment: a plugin
#: that reaches into another module's internals is coupled to them, and the
#: view is the surface that is meant to stay put.
_AEAD = "aead"
_ETM = "etm"


def _protocol_findings(server: Any, policy: Policy) -> List[Finding]:
    kexinit = server.kexinit
    strict_kex = server.strict_kex
    post_quantum = server.post_quantum
    kex_assessment = server.assessment("kex")
    pq_algorithms = [
        a.name
        for a in (kex_assessment.algorithms if kex_assessment else [])
        if _POST_QUANTUM in a.tags
    ]
    findings: List[Finding] = []

    if not strict_kex and policy.require_strict_kex:
        findings.append(
            Finding(
                id="no-strict-kex",
                severity=Severity.MEDIUM,
                title="Strict key exchange is not implemented",
                description=(
                    "The server does not advertise kex-strict-s-v00@openssh.com, so the "
                    "handshake transcript is not authenticated. No cipher currently enabled "
                    "turns that into prefix truncation (CVE-2023-48795), but nothing stops a "
                    "later change to the cipher list from doing so."
                ),
                remediation=(
                    "Upgrade to OpenSSH 9.6 or later, or the equivalent release of your SSH "
                    "implementation."
                ),
                references=["https://terrapin-attack.com/", "CVE-2023-48795"],
            )
        )

    if post_quantum is PostQuantumStatus.NOT_READY:
        findings.append(
            Finding(
                id="no-post-quantum-kex",
                severity=Severity.MEDIUM if policy.require_post_quantum else Severity.LOW,
                title="No post-quantum key exchange offered",
                description=(
                    "Every key exchange method offered relies on problems a cryptographically "
                    "relevant quantum computer would solve. Traffic recorded today could be "
                    "decrypted later ('harvest now, decrypt later'), which matters for sessions "
                    "whose confidentiality must outlive the arrival of such a machine."
                ),
                remediation=(
                    "Enable a hybrid method such as mlkem768x25519-sha256 or "
                    "sntrup761x25519-sha512@openssh.com (OpenSSH 9.0 and later). Hybrids stay "
                    "safe even if the post-quantum component is later broken."
                ),
                items=[
                    a.name
                    for a in (kex_assessment.algorithms if kex_assessment else [])
                    if a.category.is_scored
                ],
            )
        )
    elif post_quantum is PostQuantumStatus.READY:
        findings.append(
            Finding(
                id="post-quantum-ready",
                severity=Severity.INFO,
                title="Post-quantum key exchange available",
                description=(
                    "The server offers a hybrid post-quantum key exchange. Sessions only benefit "
                    "when the client also supports it, and clients that do not will silently fall "
                    "back to a classical method."
                ),
                remediation=(
                    "To require it, list only post-quantum methods in KexAlgorithms once every "
                    "client has been upgraded."
                ),
                items=list(pq_algorithms),
            )
        )

    ciphers = set(kexinit.encryption_c2s) | set(kexinit.encryption_s2c)
    macs = set(kexinit.mac_c2s) | set(kexinit.mac_s2c)

    if policy.require_aead_cipher and not any(
        _AEAD in server.tags("cipher", name) for name in ciphers
    ):
        findings.append(
            Finding(
                id="no-aead-cipher",
                severity=Severity.LOW,
                title="No authenticated encryption cipher offered",
                description=(
                    "The server offers no AEAD cipher, so integrity relies entirely on a separate "
                    "MAC algorithm."
                ),
                remediation=(
                    "Add aes256-gcm@openssh.com or chacha20-poly1305@openssh.com "
                    "to Ciphers."
                ),
            )
        )

    if policy.require_etm_mac and macs and not any(
        _ETM in server.tags("mac", name) for name in macs
    ):
        findings.append(
            Finding(
                id="no-etm-mac",
                severity=Severity.LOW,
                title="No encrypt-then-MAC algorithm offered",
                description=(
                    "Every MAC offered uses the legacy encrypt-and-MAC order, which authenticates "
                    "the plaintext instead of the ciphertext and has a weaker security proof."
                ),
                remediation=(
                    "Add hmac-sha2-256-etm@openssh.com and "
                    "hmac-sha2-512-etm@openssh.com to MACs."
                ),
                items=sorted(macs),
            )
        )


    unscored = [
        a.label
        for a in server.assessments
        if a.score is None and policy.class_weights.get(a.key, 0) > 0
    ]
    if unscored:
        findings.append(
            Finding(
                id="unscored-classes",
                severity=Severity.MEDIUM,
                title="Part of the configuration could not be judged",
                description=(
                    "The policy file recognises none of the algorithms the server offers for "
                    "these classes, so they were left out of the score. The result below is "
                    "incomplete until the policy is updated."
                ),
                remediation=(
                    f"Add the algorithms listed above to {policy.source.name}, then scan again."
                ),
                items=unscored,
            )
        )

    return findings
