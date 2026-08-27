"""One row per finding, for spreadsheets and ticket imports.

The JSON report is complete but nested, which is the wrong shape for the two
things people most often want: filtering a fleet's findings by severity, and
pasting a list of work into a tracker. A flat table is.

Targets with no findings still get a row, so a scan of fifty servers produces
fifty-plus rows rather than silently omitting the healthy ones and leaving the
reader to guess whether they were scanned.

The file has a second table after a blank line: conformance by normativa, one
row per (profile, server, status), so 'which servers fail ISO?' is a filter on
a column rather than a nested lookup.
"""

from __future__ import annotations

import csv
import io
from typing import List

from ..models import ScanReport
from ..policy import Policy
from .common import RenderOptions

__all__ = ["COLUMNS", "CONFORMANCE_COLUMNS", "render"]

#: Header of the second table: conformance by normativa.
CONFORMANCE_COLUMNS = [
    "conformance_profile", "authority", "edition", "target", "status",
    "detail", "remediation",
]

COLUMNS = [
    "target",
    "label",
    "address",
    "status",
    "grade",
    "score",
    "security_strength_bits",
    "strength_level",
    "verdict",
    "post_quantum",
    "compression",
    "strict_kex",
    "software",
    "finding_id",
    "severity",
    "finding_title",
    "finding_items",
    "remediation",
]


def render(report: ScanReport, policy: Policy, options: RenderOptions) -> str:
    """Render the report as CSV, one row per finding."""
    del policy, options
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)

    for result in report.results:
        strength = result.security_strength
        base: List[str] = [
            str(result.target),
            result.target.label or "",
            f"{result.resolved_address or result.target.host}:{result.target.port}",
            result.status.value,
            result.grade or "",
            "" if result.score is None else str(result.score),
            ""
            if strength is None or strength.effective_bits is None
            else str(strength.effective_bits),
            "" if strength is None else strength.level_id,
            result.verdict.value,
            result.post_quantum.value,
            result.compression.value,
            "yes" if result.strict_kex else "no",
            result.banner.software if result.banner else (result.error or ""),
        ]

        if not result.findings:
            writer.writerow([*base, "", "", "", "", ""])
            continue

        for finding in result.findings:
            writer.writerow(
                [
                    *base, finding.id, finding.severity.value, finding.title,
                    "; ".join(finding.items), finding.remediation,
                ]
            )

    # Second table: conformance by normativa, separated by a blank line so a
    # reader (or a csv parser pointed at one section) can take them apart.
    if report.summary.conformance_by_profile:
        writer.writerow([])
        writer.writerow(CONFORMANCE_COLUMNS)
        for pc in report.summary.conformance_by_profile:
            remediation = "; ".join(pc.remediation)
            for status, servers in (
                ("pass", pc.passed),
                ("fail", pc.failed),
                ("not-assessed", pc.not_assessed),
            ):
                for server in servers:
                    detail = ", ".join(pc.offenders.get(server, [])) if status == "fail" else ""
                    writer.writerow([
                        pc.profile_id, pc.authority, pc.edition, server, status,
                        detail, remediation if status == "fail" else "",
                    ])

    return buffer.getvalue()
