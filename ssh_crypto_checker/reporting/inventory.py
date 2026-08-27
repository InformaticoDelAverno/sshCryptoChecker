"""Cryptographic inventory, in the shape an auditor asks for.

PCI DSS v4.0 requirement 12.3.3 is not a scan; it is a document. From
31 March 2025 an assessed entity has to keep an inventory of the cipher suites
and protocols in use, review it at least every twelve months, watch for
algorithms losing their standing, and hold a written plan for replacing them.

A scan already collects every fact that inventory needs -- which algorithms are
offered, by which servers, and what this policy thinks of each one. What was
missing was the framing: an auditor wants one document listing the estate's
cryptography, not fifty per-server reports to collate by hand.

The output is Markdown so it can be pasted into a compliance system, printed,
or committed next to the evidence from other tools. Nothing here is a new
judgement: every status comes from the policy file, so an inventory produced
today and one produced after the next policy update differ exactly where the
industry's view of an algorithm has changed, which is the review this
requirement is really asking for.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import PRODUCT_NAME, __version__
from ..models import Category, ScanReport, ScanStatus
from ..policy import Policy
from .common import RenderOptions

__all__ = ["render"]

#: What each algorithm class is for, in the terms 12.3.3 asks for ("purpose").
_PURPOSE = {
    "kex": "Key establishment: agrees the session keys and authenticates the server",
    "host_key": "Server authentication: proves the server's identity to the client",
    "cipher": "Confidentiality: encrypts the session traffic",
    "mac": "Integrity: detects modification of the session traffic",
    "compression": "Compression: applied before encryption",
}

#: Wording an assessor can read without knowing this tool's vocabulary.
_STANDING = {
    Category.RECOMMENDED: "Approved",
    Category.ACCEPTABLE: "Permitted, migration recommended",
    Category.WEAK: "Deprecated, replace",
    Category.INSECURE: "Prohibited, remove",
    Category.INFORMATIONAL: "No security claim",
    Category.UNKNOWN: "Not in the policy, review by hand",
}


def _standing(category: Category, definition: Any) -> str:
    """How an assessor should read this algorithm's status."""
    text = _STANDING.get(category, category.value)
    tags = getattr(definition, "tags", ()) or ()
    if "post-quantum" in tags or "hybrid-pq" in tags:
        text += " (post-quantum)"
    return text


def _scanned(report: ScanReport) -> List:
    return [r for r in report.results if r.status is ScanStatus.OK]


def _collect(
    report: ScanReport,
) -> Tuple[Dict[str, Dict[str, Tuple[Category, Set[str]]]], Dict[str, str]]:
    """Algorithm -> which servers offer it, grouped by class, plus class labels."""
    inventory: Dict[str, Dict[str, Tuple[Category, Set[str]]]] = defaultdict(dict)
    labels: Dict[str, str] = {}
    for result in _scanned(report):
        address = str(result.target)
        for assessment in result.assessments:
            labels.setdefault(assessment.key, assessment.label)
            for algorithm in assessment.algorithms:
                entry = inventory[assessment.key].get(algorithm.name)
                if entry is None:
                    inventory[assessment.key][algorithm.name] = (
                        algorithm.category,
                        {address},
                    )
                else:
                    entry[1].add(address)
    return inventory, labels


def _describe(policy: Policy, class_key: str, name: str) -> Optional[Any]:
    """The policy's entry for an algorithm, or None if the class is unknown."""
    try:
        return policy.lookup(class_key, name)
    except Exception:  # an inventory must never fail to render
        return None


def _table(rows: List[List[str]], headers: List[str]) -> List[str]:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in row) + " |")
    return lines


def _where_used(servers: Set[str], total: int) -> str:
    if len(servers) == total:
        return f"all {total} server(s)"
    if len(servers) <= 4:
        return ", ".join(sorted(servers))
    return f"{len(servers)} of {total} servers"


def render(report: ScanReport, policy: Policy, options: RenderOptions) -> str:
    """Render the cryptographic inventory."""
    del options
    scanned = _scanned(report)
    inventory, labels = _collect(report)
    total = len(scanned)

    lines: List[str] = [
        "# Cryptographic inventory: SSH",
        "",
        "Evidence for PCI DSS v4.0 requirement 12.3.3 (inventory of cryptographic",
        "cipher suites and protocols in use, reviewed at least every 12 months).",
        "",
    ]

    lines += _table(
        [
            ["Scope", "SSH servers reachable from the scanning host"],
            ["Servers inventoried", str(total)],
            ["Servers unreachable", str(len(report.results) - total)],
            ["Compiled", report.finished_at or report.started_at],
            ["Method", "Automated protocol negotiation; no credentials required"],
            ["Tool", f"{PRODUCT_NAME} {__version__}"],
            ["Policy", policy.describe()],
            ["Next review due", "Within 12 months of the date above"],
        ],
        ["Field", "Value"],
    )

    unreachable = [r for r in report.results if r.status is not ScanStatus.OK]
    if unreachable:
        lines += [
            "",
            "### Scope exclusions",
            "",
            "These servers were in scope and could not be inventoried. Each one is a gap "
            "in this evidence and needs either a successful scan or a documented reason "
            "for being out of scope.",
            "",
        ]
        lines += _table(
            [
                [str(result.target), result.target.label or "", result.error or result.status.value]
                for result in unreachable
            ],
            ["Server", "Label", "Why it could not be inventoried"],
        )

    lines += ["", "## 1. Systems in scope", ""]
    lines += [
        "The servers this inventory covers, and the implementation each one runs. The",
        "implementation matters as much as the algorithm list: it determines which",
        "algorithms can be offered at all, and it is what has to be upgraded when one",
        "of them loses its standing.",
        "",
    ]
    lines += _table(
        [
            [
                str(result.target),
                result.target.label or "",
                result.banner.software if result.banner else "unknown",
                result.grade or "-",
                "yes" if result.post_quantum.value == "ready" else "no",
            ]
            for result in scanned
        ],
        ["Server", "Label", "Implementation", "Grade", "Post-quantum"],
    )

    lines += ["", "## 2. Cipher suites and protocols in use", ""]
    lines += [
        "Every algorithm each server offers, its purpose, and its standing under the",
        "policy above. An algorithm appears once, with the servers that offer it.",
        "",
    ]

    if not inventory:
        lines += ["No server could be inventoried; there is nothing to report.", ""]

    for class_key in ("kex", "host_key", "cipher", "mac", "compression"):
        algorithms = inventory.get(class_key)
        if not algorithms:
            continue
        label = labels.get(class_key, class_key)
        lines += [f"### {label}", "", _PURPOSE.get(class_key, ""), ""]
        rows = []
        # Extension markers travel in the same negotiation lists as algorithms
        # but are not cryptography, so they are listed apart rather than left
        # to look like ciphers an assessor has to have an opinion about.
        markers = []
        for name in sorted(algorithms):
            category, servers = algorithms[name]
            definition = _describe(policy, class_key, name)
            if category is Category.INFORMATIONAL:
                markers.append(f"`{name}` ({_where_used(servers, total)})")
                continue
            rows.append(
                [
                    f"`{name}`",
                    _standing(category, definition),
                    str(definition.security_strength_bits or "-")
                    if definition is not None
                    else "-",
                    _where_used(servers, total),
                ]
            )
        if rows:
            lines += _table(rows, ["Algorithm", "Standing", "Strength (bits)", "Where used"])
            lines.append("")
        if markers:
            lines += [
                "Also negotiated in this list, and not cryptographic algorithms: "
                + ", ".join(markers)
                + ".",
                "",
            ]

    lines += ["## 3. Algorithms requiring action", ""]
    problems: List[list] = []
    for class_key, algorithms in inventory.items():
        for name, (category, servers) in algorithms.items():
            if category not in (Category.WEAK, Category.INSECURE, Category.UNKNOWN):
                continue
            definition = _describe(policy, class_key, name)
            problems.append(
                [
                    f"`{name}`",
                    labels.get(class_key, class_key),
                    _standing(category, definition),
                    (definition.notes if definition is not None and definition.notes else ""),
                    _where_used(servers, total),
                    category,
                ]
            )
    if problems:
        # Worst first: an assessor should not have to read to the bottom.
        severity = {
            Category.INSECURE: 0,
            Category.WEAK: 1,
            Category.UNKNOWN: 2,
        }
        problems.sort(key=lambda row: (severity.get(row[-1], 3), row[0]))
        problems = [row[:-1] for row in problems]
        lines += _table(
            problems, ["Algorithm", "Class", "Standing", "Reason", "Where used"]
        )
    else:
        lines.append("No algorithm in use is deprecated or prohibited under this policy.")
    lines.append("")

    lines += ["## 4. Post-quantum readiness", ""]
    ready = [str(r.target) for r in scanned if r.post_quantum.value == "ready"]
    lines += [
        "Store-now-decrypt-later means traffic recorded today can be read once a",
        "cryptographically relevant quantum computer exists. A server is counted as",
        "ready when it offers a hybrid key exchange, so the session key survives even",
        "if the classical half is broken retrospectively.",
        "",
        f"- Ready: {len(ready)} of {total} server(s)",
        f"- Not ready: {total - len(ready)} of {total} server(s)",
        "",
    ]
    if ready and len(ready) < total:
        lines += ["Ready: " + ", ".join(sorted(ready)), ""]

    lines += ["## 5. Response strategy", ""]
    lines += [
        "The documented plan for responding to changes in the standing of an algorithm.",
        "",
        "1. The algorithm lists live in a single policy file, versioned in the same",
        "   repository as this tool. Changing an algorithm's standing is a change to",
        "   that file, reviewed like any other change.",
        "2. Scans run automatically and fail the pipeline when a server offers",
        "   something the policy prohibits, so a regression is caught when it is",
        "   introduced rather than at the next annual review.",
        "3. Reports are compared against the previous scan, so an algorithm appearing",
        "   or disappearing after a package upgrade is visible without reading the",
        "   whole report.",
        "4. Hybrid post-quantum key exchange is already deployed where the software",
        "   supports it; the servers that are not ready are listed above.",
        "",
    ]

    remediations: Dict[str, Set[str]] = defaultdict(set)
    for result in scanned:
        for finding in result.findings:
            if finding.remediation:
                remediations[finding.remediation].add(str(result.target))
    if remediations:
        lines += ["### Outstanding actions from this scan", ""]
        lines += _table(
            [
                [action, _where_used(servers, total)]
                for action, servers in sorted(remediations.items())
            ],
            ["Action", "Servers"],
        )
        lines.append("")

    if report.summary.conformance_by_profile:
        lines.append("## Conformance by normativa")
        lines.append("")
        lines += _table(
            [
                [
                    pc.name,
                    pc.authority,
                    f"{len(pc.passed)}/{pc.assessed}",
                    str(len(pc.failed)),
                    str(len(pc.not_assessed)),
                ]
                for pc in report.summary.conformance_by_profile
            ],
            ["Profile", "Authority", "Conform", "Fail", "Not assessed"],
        )
        lines.append("")
        for pc in report.summary.conformance_by_profile:
            if not pc.failed:
                continue
            lines.append(f"**{pc.name}** &mdash; not met by:")
            lines.append("")
            for server in pc.failed:
                offenders = pc.offenders.get(server)
                detail = f": {', '.join(offenders)}" if offenders else ""
                lines.append(f"- `{server}`{detail}")
            for fix in pc.remediation:
                lines.append(f"- _To comply:_ {fix}")
            lines.append("")

    lines += [
        "---",
        "",
        f"Generated by {PRODUCT_NAME} {__version__}. This inventory records what the",
        "servers offer, which is what a client can negotiate. It is not a statement",
        "about what any particular session used.",
        "",
    ]
    return "\n".join(lines)
