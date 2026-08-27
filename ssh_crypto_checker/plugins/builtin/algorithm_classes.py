"""What the policy thinks of each algorithm the server offers.

Reads the classification, never the score. The same classification feeds the
number at the top of the report, but this only reports it: removing this file
changes what the report says and not what the server is graded.
"""

from collections.abc import Sequence
from typing import Any, List

from ssh_crypto_checker.models import Category, ClassAssessment, Finding, Severity
from ssh_crypto_checker.policy import Policy

ID = "insecure-cipher"
NAME = "Insecure algorithms offered"
KIND = "check"
SEVERITY = "critical"
DESCRIPTION = "The server accepts algorithms this policy rejects."
REMEDIATION = "Remove them from the corresponding sshd_config directive."


def check(server: Any) -> Any:
    # The same contract as every other check here: given nothing, report
    # nothing. See tests/test_plugins.py, which holds all of them to it.
    if not server.assessments:
        return None
    return _algorithm_findings(server.policy, server.assessments)


def _algorithm_findings(policy: Policy, assessments: Sequence[ClassAssessment]) -> List[Finding]:
    findings: List[Finding] = []
    for assessment in assessments:
        directive = policy.classes[assessment.key].sshd_config_directive
        reported_offenders = False
        for category, severity, verb in (
            (Category.INSECURE, Severity.CRITICAL, "must be disabled"),
            (Category.WEAK, Severity.MEDIUM, "should be disabled"),
        ):
            offenders = assessment.by_category(category)
            if not offenders:
                continue
            reported_offenders = True
            findings.append(
                Finding(
                    id=f"{category.value}-{assessment.key}",
                    severity=severity,
                    title=(
                        f"{policy.category_label(category)} {assessment.label.lower()} "
                        f"algorithm(s) offered"
                    ),
                    description=(
                        f"The server accepts {len(offenders)} {category.value} "
                        f"{assessment.label.lower()} algorithm(s). "
                        + " ".join(f"{a.name}: {a.notes}" for a in offenders if a.notes)
                    ).strip(),
                    remediation=(
                        f"Remove these algorithms from the {directive} directive in "
                        f"sshd_config; they {verb}."
                        if directive
                        else f"Remove these algorithms from the server configuration; they {verb}."
                    ),
                    items=[a.name for a in offenders],
                )
            )

        unknown = assessment.by_category(Category.UNKNOWN)
        if unknown:
            findings.append(
                Finding(
                    id=f"unknown-{assessment.key}",
                    severity=Severity.INFO,
                    title=f"Unclassified {assessment.label.lower()} algorithm(s)",
                    description=(
                        "These algorithms are not described by the policy file, so they were "
                        "excluded from the score. Review them and add an entry so future scans "
                        "judge them."
                    ),
                    remediation=(
                        f"Add the algorithms to algorithms.{assessment.key}.entries in "
                        f"{policy.source.name}."
                    ),
                    items=[a.name for a in unknown],
                )
            )

        # Only worth saying when nothing worse was already reported for this
        # class; otherwise it just restates the finding above it.
        preferred = assessment.preferred
        if preferred is not None:
            entry = policy.lookup(assessment.key, preferred)
            if entry.category in {Category.WEAK, Category.INSECURE}:
                findings.append(
                    Finding(
                        id=f"weak-preferred-{assessment.key}",
                        severity=Severity.MEDIUM,
                        title=(
                            f"The server's first choice of "
                            f"{assessment.label.lower()} is {entry.category.value}"
                        ),
                        description=(
                            f"{preferred} is listed first, so it is what a client that accepts "
                            "anything will negotiate. Ordering matters as much as membership: "
                            "the strong algorithms further down the list never get used."
                        ),
                        remediation=(
                            f"Reorder the {directive} directive so a recommended algorithm comes "
                            "first, and remove this one."
                            if directive
                            else "Reorder the list so a recommended algorithm comes first."
                        ),
                        items=[preferred],
                    )
                )

        scored = [a for a in assessment.algorithms if a.category.is_scored]
        if scored and not reported_offenders and not assessment.by_category(Category.RECOMMENDED):
            findings.append(
                Finding(
                    id=f"no-recommended-{assessment.key}",
                    severity=Severity.LOW,
                    title=f"No recommended {assessment.label.lower()} algorithm offered",
                    description=(
                        "Every algorithm the server accepts for this class is merely tolerated by "
                        "the policy. Clients cannot negotiate anything the policy considers "
                        "state of the art."
                    ),
                    remediation=(
                        f"Add at least one recommended algorithm to {directive}."
                        if directive
                        else "Enable at least one recommended algorithm for this class."
                    ),
                    items=[a.name for a in scored],
                )
            )
    return findings
