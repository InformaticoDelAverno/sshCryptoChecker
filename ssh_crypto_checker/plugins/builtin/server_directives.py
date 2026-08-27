"""The directives sshd actually resolved, and the Match blocks that override them.

The expectations themselves live in the policy file, under
``sshd_config_checks``; this runs them. Match blocks are here rather than in
their own file because deciding whether one *weakens* anything means comparing
it against the very same global values.
"""

from typing import Any, Dict, List, Tuple

from ssh_crypto_checker.models import EffectiveConfig, Finding, Severity
from ssh_crypto_checker.policy import Policy, check_expectation

ID = "config-audit-unavailable"
NAME = "The server configuration could not be read"
KIND = "check"
SEVERITY = "info"
DESCRIPTION = (
    "Everything else in this report came from the network. Reading the configuration needs "
    "an account, and reading it with 'sshd -T' needs that account to be root or to have "
    "passwordless sudo for it."
)
REMEDIATION = "Check the credentials in the inventory and the sudo rule."


def check(server: Any) -> Any:
    config = server.config
    if config is None or not getattr(config, "attempted", False):
        return None
    if not config.available:
        return [
            Finding(
                id=ID,
                severity=Severity.INFO,
                title=NAME,
                description=DESCRIPTION,
                remediation=REMEDIATION,
                items=[config.error or "unknown error"],
            )
        ]

    findings: List[Finding] = []
    for rule in server.policy.config_checks:
        value = config.value(rule.directive)
        alternatives = [config.value(name) for name in rule.alternatives]
        if check_expectation(rule.expect, value) or any(a is not None for a in alternatives):
            continue
        findings.append(
            Finding(
                id=f"config-{rule.id}",
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                remediation=rule.remediation,
                items=[
                    f"{rule.directive} {value}" if value is not None
                    else f"{rule.directive} is not set"
                ],
            )
        )
    findings.extend(_match_block_findings(config, server.policy))
    return findings


def _match_block_findings(config: EffectiveConfig, policy: Policy) -> List[Finding]:
    """What each Match block actually changes, resolved rather than guessed.

    Only a weakening is reported. A block that *tightens* something is the
    reason blocks exist, and a directive already failing globally has been
    reported once already -- repeating it per context would bury the one thing
    worth seeing, which is a setting that looks right until you are the user
    the block was written for.
    """
    if not config.match_blocks and not config.match_contexts:
        return []

    findings: List[Finding] = []
    resolved = [context for context in config.match_contexts if context.resolved]
    unresolved = [context for context in config.match_contexts if not context.resolved]

    # Keyed by what changed rather than by which block changed it. sshd applies
    # every block a connection matches, so 'sshd -T -C' returns the combined
    # result and no single block can be blamed for a value without guessing.
    # Naming the connections that end up with it is both accurate and the thing
    # somebody has to act on.
    weakened: Dict[Tuple[str, str, str], List[str]] = {}
    for context in resolved:
        for check in policy.config_checks:
            global_value = config.value(check.directive)
            context_value = context.value(check.directive)
            if context_value is None or context_value == global_value:
                continue
            if not check_expectation(check.expect, global_value):
                # Already wrong for everyone; reported once above.
                continue
            if check_expectation(check.expect, context_value):
                continue
            key = (check.directive, str(global_value), str(context_value))
            entry = weakened.setdefault(key, [])
            label = context.criteria or context.context
            if label not in entry:
                entry.append(label)

    if weakened:
        findings.append(
            Finding(
                id="config-match-block-weakens",
                severity=Severity.HIGH,
                title="A Match block relaxes the configuration for some connections",
                description=(
                    "The global configuration is sound for these directives, and a Match "
                    "block undoes it for the connections listed. This is the shape of "
                    "problem that survives review: the file reads correctly from the top, "
                    "and the exception at the bottom is what most logins actually get. "
                    "sshd applies every block a connection matches, so what is named here "
                    "is the connection that ends up with the weaker value, not the single "
                    "block responsible for it."
                ),
                remediation=(
                    "Narrow or remove the block. Verify with "
                    "'sshd -T -C user=<name>,addr=<address>', which is how these were read."
                ),
                items=[
                    f"{directive} is {context_value} (globally {global_value}) for "
                    f"connections matching: " + "; ".join(sorted(contexts))
                    for (directive, global_value, context_value), contexts in sorted(
                        weakened.items()
                    )
                ][:20],
            )
        )

    if resolved and not weakened:
        findings.append(
            Finding(
                id="config-match-blocks-checked",
                severity=Severity.INFO,
                title="Match blocks were resolved and weaken nothing",
                description=(
                    "Each block was re-read with 'sshd -T -C' using a connection context it "
                    "would match, and none of them relaxes a directive that is sound "
                    "globally. Reported so that a configuration with Match blocks is not "
                    "silently indistinguishable from one without."
                ),
                remediation="",
                items=[f"{c.criteria} -> {c.context}" for c in resolved][:20],
            )
        )

    if unresolved:
        findings.append(
            Finding(
                id="config-match-blocks",
                severity=Severity.INFO,
                title="Some Match blocks still need reading by hand",
                description=(
                    "No single connection context represents these, so what they change was "
                    "not established. A block that was never resolved must not be mistaken "
                    "for one that was found harmless."
                ),
                remediation=(
                    "Inspect each block, and check it with "
                    "'sshd -T -C user=<name>,host=<host>,addr=<address>' for a connection it "
                    "would match."
                ),
                items=[
                    f"{context.criteria}: {context.error or 'no reason recorded'}"
                    for context in unresolved
                ][:20],
            )
        )
    elif not config.match_contexts and config.match_blocks:
        # An older sshd with no -C support, or a probe that produced nothing.
        findings.append(
            Finding(
                id="config-match-blocks",
                severity=Severity.INFO,
                title="The configuration contains Match blocks",
                description=(
                    "Everything checked above is the global configuration. A Match block can "
                    "relax any of it for a particular user, group or network, and none of "
                    "these could be resolved."
                ),
                remediation=(
                    "Inspect each block, and check it with "
                    "'sshd -T -C user=<name>,host=<host>,addr=<address>'."
                ),
                items=config.match_blocks,
            )
        )
    return findings
