"""The scanning machine's own ssh client.

A server audit assumes the client will hold up its end. It frequently does
not: the strongest host key on earth is not checked at all by a client told to
accept any of them.
"""

from typing import Any, List

from ssh_crypto_checker.models import Category, Finding, Severity
from ssh_crypto_checker.policy import Policy, check_expectation

ID = "client-config-unavailable"
NAME = "The client configuration could not be read"
KIND = "check"
SEVERITY = "info"
DESCRIPTION = "This check describes the machine the scan ran from."
REMEDIATION = "Check that an 'ssh' binary is on PATH."


def check(server: Any) -> Any:
    if server.client_config is None or not getattr(server.client_config, "attempted", False):
        return None
    return _client_config_findings(server, server.policy)


#: The client directive holding each algorithm class, so the client's own
#: lists are judged by the same policy as the server's.
_CLIENT_ALGORITHM_DIRECTIVES = {
    "kex": "kexalgorithms",
    "host_key": "hostkeyalgorithms",
    "cipher": "ciphers",
    "mac": "macs",
}


def _client_config_findings(server: Any, policy: Policy) -> List[Finding]:
    """Judge the scanning machine's own client configuration.

    A server audit assumes the client will hold up its end. It frequently does
    not: the strongest host key on earth is not checked at all by a client told
    to accept any of them.
    """
    # check() has already established that the audit was attempted; this is
    # only ever called with a result to judge.
    config = server.client_config
    if not config.available:
        return [
            Finding(
                id="client-config-unavailable",
                severity=Severity.INFO,
                title="The client configuration could not be read",
                description=(
                    "Everything else in this report describes the server. This check "
                    "describes the machine the scan ran from, and it could not be resolved."
                ),
                remediation="Check that an 'ssh' binary is on PATH.",
                items=[config.error or "unknown error"],
            )
        ]

    findings: List[Finding] = []
    for check in policy.client_checks:
        value = config.value(check.directive)
        alternatives = [config.value(name) for name in check.alternatives]
        if check_expectation(check.expect, value) or any(
            alternative is not None for alternative in alternatives
        ):
            continue
        if True:
            findings.append(
                Finding(
                    id=f"client-{check.id}",
                    severity=check.severity,
                    title=check.title,
                    description=check.description,
                    remediation=check.remediation,
                    items=[f"{check.directive} {value}" if value else f"{check.directive} unset"],
                )
            )

    # The client's own algorithm lists, judged by the same policy as the
    # server's. A client offering 3des-cbc will negotiate it against a server
    # that still allows it, however the server is graded here.
    offered: List[str] = []
    for algorithm_class, directive in _CLIENT_ALGORITHM_DIRECTIVES.items():
        raw = config.value(directive)
        if not raw:
            continue
        klass = policy.classes[algorithm_class]
        for name in raw.split(","):
            name = name.strip()
            if not name:
                continue
            entry = klass.lookup(name)
            if entry.category in {Category.WEAK, Category.INSECURE}:
                offered.append(f"{directive}: {name} ({entry.category.value})")
    if offered:
        findings.append(
            Finding(
                id="client-weak-algorithms",
                severity=Severity.MEDIUM,
                title="The client offers algorithms this policy rejects",
                description=(
                    "Negotiation picks something both ends accept, so a client carrying weak "
                    "algorithms will use them against any server that still allows them. "
                    "Hardening the servers does not remove this; hardening the client does."
                ),
                remediation=(
                    "Set Ciphers, MACs, KexAlgorithms and HostKeyAlgorithms in ssh_config, "
                    "or remove the weak entries with the '-' prefix, for example "
                    "'Ciphers -3des-cbc,*-cbc'."
                ),
                items=sorted(set(offered))[:15],
            )
        )

    # Cross-reference: one of the client CVEs only bites with this option on.
    if str(config.value("verifyhostkeydns") or "").lower() in {"yes", "true"}:
        findings.append(
            Finding(
                id="client-verify-host-key-dns",
                severity=Severity.LOW,
                title="The client trusts SSHFP records from DNS",
                description=(
                    "VerifyHostKeyDNS lets an unsigned DNS answer decide whether a host key "
                    "is genuine, and it is the precondition for CVE-2025-26465, which let an "
                    "on-path attacker impersonate any server. It is only sound with DNSSEC "
                    "validation all the way to the resolver."
                ),
                remediation=(
                    "Set 'VerifyHostKeyDNS no' unless the resolver validates with DNSSEC, and "
                    "make sure the client is OpenSSH 9.9p2 or later."
                ),
                items=[f"verifyhostkeydns {config.value('verifyhostkeydns')}"],
            )
        )
    return findings
