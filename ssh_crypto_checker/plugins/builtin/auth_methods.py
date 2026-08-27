"""What the server will accept as proof of identity.

All of these come from one probe -- a single deliberately failing
authentication request -- so they are read together and belong together.
"""

from typing import Any, List

from ssh_crypto_checker.models import Category, Finding, Severity
from ssh_crypto_checker.policy import Policy

ID = "auth-methods"
NAME = "Authentication methods offered"
KIND = "check"
SEVERITY = "info"
DESCRIPTION = "The methods the server will accept."
REMEDIATION = ""
#: No NEEDS on purpose. NEEDS is for a check that cannot answer -- where not
#: looking could be mistaken for not finding anything. This one is opt-in: its
#: data is absent because the operator did not ask for it, and reporting that
#: as "undetermined" on every ordinary scan would be noise, not honesty.



def check(server: Any) -> Any:
    if server.auth_methods is None:
        return None
    return _auth_method_findings(server, server.policy)


def _auth_method_findings(server: Any, policy: Policy) -> List[Finding]:
    """What the server's authentication offer says about its exposure."""
    # check() has already established that the probe ran; this is only ever
    # called with an answer to judge.
    auth = server.auth_methods
    if not auth.available:
        return [
            Finding(
                id="auth-methods-unavailable",
                severity=Severity.INFO,
                title="Authentication methods could not be read",
                description="The scan could not complete a session far enough to ask.",
                remediation="No action; the rest of the report is unaffected.",
                items=[auth.error],
            )
        ]

    findings: List[Finding] = []
    if auth.accepted_without_credentials:
        return [
            Finding(
                id="auth-none-accepted",
                severity=Severity.CRITICAL,
                title="The server grants access with no credentials at all",
                description=(
                    "The server accepted the 'none' authentication method, which means anyone "
                    "who can reach the port gets a session. This is almost always a "
                    "misconfiguration and should be treated as a live compromise until proven "
                    "otherwise."
                ),
                remediation=(
                    "Check PermitEmptyPasswords, the PAM stack and any Match block that could "
                    "have disabled authentication for this account, then rotate credentials and "
                    "review the auth log."
                ),
                items=[f"probed as user '{auth.username}'"],
            )
        ]

    offered = set(auth.methods)
    password_methods = sorted(offered & {"password", "keyboard-interactive"})
    if password_methods:
        findings.append(
            Finding(
                id="password-authentication-enabled",
                severity=Severity.MEDIUM,
                title="Password authentication is enabled",
                description=(
                    "The server accepts passwords, so it is exposed to credential stuffing and "
                    "online guessing. This is the single most common route into an SSH server, "
                    "and no cipher list protects against it. Note that keyboard-interactive "
                    "usually reaches a password prompt through PAM."
                ),
                remediation=(
                    "Set 'PasswordAuthentication no' and 'KbdInteractiveAuthentication no' in "
                    "sshd_config once every user has a working key, and check that no Match "
                    "block re-enables them."
                ),
                items=password_methods,
            )
        )
    if "publickey" not in offered and auth.methods:
        findings.append(
            Finding(
                id="no-publickey-authentication",
                severity=Severity.LOW,
                title="Public key authentication is not offered",
                description="The server does not accept keys, leaving only weaker methods.",
                remediation="Enable 'PubkeyAuthentication yes' and migrate users to keys.",
                items=sorted(offered),
            )
        )
    if "hostbased" in offered:
        findings.append(
            Finding(
                id="hostbased-authentication-enabled",
                severity=Severity.MEDIUM,
                title="Host-based authentication is enabled",
                description=(
                    "Host-based authentication trusts the client machine rather than the user, "
                    "so compromising any trusted host grants access to every account it can "
                    "claim."
                ),
                remediation="Set 'HostbasedAuthentication no' unless a documented need exists.",
                items=["hostbased"],
            )
        )
    weak_signatures = [
        name
        for name in auth.server_sig_algs
        if policy.lookup("host_key", name).category in {Category.WEAK, Category.INSECURE}
    ]
    if weak_signatures:
        findings.append(
            Finding(
                id="weak-client-signature-algorithms",
                severity=Severity.MEDIUM,
                title="Weak signature algorithms accepted for client authentication",
                description=(
                    "The server advertises these in server-sig-algs (RFC 8308), meaning it will "
                    "accept them when a client authenticates with a key. This is invisible in "
                    "the algorithm lists above: a server can present a strong host key and "
                    "still accept SHA-1 signatures from its users."
                ),
                remediation=(
                    "Set PubkeyAcceptedAlgorithms in sshd_config to exclude them, for example "
                    "'PubkeyAcceptedAlgorithms -ssh-rsa,-ssh-dss,-*-cert-v00@openssh.com'."
                ),
                items=weak_signatures,
            )
        )

    if not findings and auth.methods:
        findings.append(
            Finding(
                id="auth-methods",
                severity=Severity.INFO,
                title="Authentication methods offered",
                description="Read before authenticating, with the 'none' method.",
                remediation="No action needed.",
                items=sorted(offered),
            )
        )
    return findings
