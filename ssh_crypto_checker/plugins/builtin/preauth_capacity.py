"""How cheaply the pre-authentication slots can be exhausted.

Two measurements of one property. How many connections the server will hold
and how long it holds them are the two halves of what it costs to lock real
users out, and reading them together is the only way the trade-off makes
sense: lowering the grace period is what makes a small MaxStartups tolerable.
"""

from typing import Any

from ssh_crypto_checker.plugins import Detected

ID = "low-max-startups"
NAME = "The server accepts few concurrent unauthenticated connections"
KIND = "check"
SEVERITY = "low"
DESCRIPTION = "The server stops accepting new connections after very few."
REMEDIATION = (
    "Raise MaxStartups (for example '10:30:100', which starts dropping randomly rather than "
    "refusing outright) and lower LoginGraceTime so each slot frees sooner."
)

#: Below this, one script holds the door shut.
_FEW_SLOTS = 10
#: Above this, each slot is expensive to free.
_LONG_GRACE_SECONDS = 60


def check(server: Any) -> Any:
    found = []

    accepted = server.max_startups
    if accepted is not None and accepted <= _FEW_SLOTS:
        found.append(
            Detected(
                description=(
                    f"It stopped accepting new connections after {accepted}. Anyone able to "
                    "reach the port can hold those slots open for the whole login grace "
                    "period and keep real users out, which costs the attacker almost nothing."
                ),
                evidence=[f"{accepted} concurrent connections accepted"],
            )
        )

    grace = server.login_grace_seconds
    if grace is not None and grace >= _LONG_GRACE_SECONDS:
        found.append(
            Detected(
                id="long-login-grace",
                name="Unauthenticated connections are held open for a long time",
                description=(
                    f"The server kept an unauthenticated connection open for {grace:.0f} "
                    "seconds. Every such connection occupies one of the MaxStartups slots, so "
                    "a long grace period makes it cheaper to exhaust them and lock out real "
                    "users."
                ),
                remediation=(
                    "Reduce LoginGraceTime to something like 30 seconds. Note the opposite "
                    "trade-off: setting it to 0 was the documented stop-gap for CVE-2024-6387 "
                    "but removes the timeout entirely."
                ),
                evidence=[f"{grace:.0f} seconds"],
            )
        )
    return found
