"""OpenMetrics output, for a scrape rather than a report.

A report answers a question somebody asked. Metrics answer questions nobody is
awake for: a host whose grade dropped overnight, a fleet whose post-quantum
coverage stopped rising, a scan that quietly stopped running. Those need a
series and an alert rule, not a document.

The output is the text exposition format, so it can be written straight into
node_exporter's textfile collector directory or served by anything that can
cat a file. It ends with the ``# EOF`` marker that OpenMetrics requires and
Prometheus tolerates.

Grades are exported as an ordinal rather than a label, because "the grade got
worse" is the alert people actually want and comparing labels cannot express
it. Zero is the best grade, so an alert reads ``ssh_target_grade > 2``.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .. import PRODUCT_NAME, __version__
from ..models import (
    ComplianceStatus,
    CompressionStatus,
    ScanReport,
    ScanStatus,
    Severity,
)
from ..policy import Policy
from .common import RenderOptions

__all__ = ["render"]

_SEVERITIES = [severity.value for severity in Severity]


def _escape(value: str) -> str:
    """Escape a label value (backslash, quote and newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(pairs: Dict[str, str]) -> str:
    inner = ",".join(f'{key}="{_escape(value)}"' for key, value in pairs.items() if value != "")
    return f"{{{inner}}}" if inner else ""


class _Writer:
    def __init__(self) -> None:
        self.lines: List[str] = []
        self._declared: set = set()

    def metric(self, name: str, kind: str, help_text: str) -> None:
        if name in self._declared:
            return
        self._declared.add(name)
        self.lines.append(f"# HELP {name} {help_text}")
        self.lines.append(f"# TYPE {name} {kind}")

    def sample(
        self, name: str, value: float, labels: Optional[Dict[str, str]] = None
    ) -> None:
        rendered = _labels(labels or {})
        # Integers are written without a decimal point; a float that happens to
        # be whole should not change the series' appearance between scans.
        text = str(int(value)) if float(value).is_integer() else repr(float(value))
        self.lines.append(f"{name}{rendered} {text}")


def render(report: ScanReport, policy: Policy, options: RenderOptions) -> str:
    """Render the scan as OpenMetrics text."""
    del options
    ladder = policy.grade_ladder
    writer = _Writer()

    writer.metric(
        "ssh_scan_info", "gauge", "Always 1, carrying the tool and policy versions as labels."
    )
    writer.sample(
        "ssh_scan_info",
        1,
        {
            "tool": PRODUCT_NAME,
            "version": __version__,
            "policy": str(report.policy.get("name", "")),
            "policy_version": str(report.policy.get("version", "")),
        },
    )

    writer.metric("ssh_scan_targets", "gauge", "Targets in this scan.")
    writer.sample("ssh_scan_targets", report.summary.total)
    writer.metric("ssh_scan_targets_reachable", "gauge", "Targets that answered.")
    writer.sample("ssh_scan_targets_reachable", report.summary.succeeded)
    writer.metric("ssh_scan_duration_seconds", "gauge", "Wall clock time of the scan.")
    writer.sample("ssh_scan_duration_seconds", (report.duration_ms or 0) / 1000)
    writer.metric(
        "ssh_scan_average_score", "gauge", "Mean score across the targets that answered."
    )
    writer.sample("ssh_scan_average_score", report.summary.average_score or 0)

    writer.metric(
        "ssh_target_up", "gauge", "1 when the target answered, 0 when it could not be scanned."
    )
    writer.metric(
        "ssh_target_duration_seconds", "gauge", "Time spent scanning this target."
    )
    writer.metric("ssh_target_score", "gauge", "Score out of 100.")
    writer.metric(
        "ssh_target_grade",
        "gauge",
        "Grade as an ordinal, 0 being the best. Alert on an increase.",
    )
    writer.metric(
        "ssh_target_security_strength_bits", "gauge", "Effective security strength in bits."
    )
    writer.metric(
        "ssh_target_post_quantum", "gauge", "1 when a hybrid post-quantum key exchange is offered."
    )
    writer.metric(
        "ssh_target_strict_kex", "gauge", "1 when strict key exchange is negotiated."
    )
    writer.metric(
        "ssh_target_compression_preauth",
        "gauge",
        "1 when the server offers compression that starts before authentication.",
    )
    writer.metric(
        "ssh_target_findings", "gauge", "Findings on this target, by severity."
    )
    writer.metric(
        "ssh_target_vulnerabilities",
        "gauge",
        "Known vulnerabilities matched on this target, by severity.",
    )
    writer.metric(
        "ssh_target_vulnerabilities_undetermined",
        "gauge",
        "Vulnerability checks that could not be settled with the data collected.",
    )
    writer.metric(
        "ssh_target_profile_conformance",
        "gauge",
        "1 when the target conforms to the profile. 0 covers both a failure and a "
        "requirement the scan could not check -- see ssh_target_profile_not_assessed.",
    )
    writer.metric(
        "ssh_target_profile_not_assessed",
        "gauge",
        "1 when the profile makes a requirement this scan could not test at all.",
    )

    for result in report.results:
        labels = {"target": str(result.target), "label": result.target.label or ""}
        up = 1 if result.status is ScanStatus.OK else 0
        writer.sample("ssh_target_up", up, labels)
        writer.sample("ssh_target_duration_seconds", (result.duration_ms or 0) / 1000, labels)
        if not up:
            continue

        writer.sample("ssh_target_score", result.score or 0, labels)
        if result.grade in ladder:
            writer.sample("ssh_target_grade", ladder.index(result.grade), labels)
        strength = result.security_strength
        if strength is not None and strength.effective_bits is not None:
            writer.sample("ssh_target_security_strength_bits", strength.effective_bits, labels)
        writer.sample(
            "ssh_target_post_quantum",
            1 if result.post_quantum.value in {"ready", "enforced"} else 0,
            labels,
        )
        writer.sample("ssh_target_strict_kex", 1 if result.strict_kex else 0, labels)
        writer.sample(
            "ssh_target_compression_preauth",
            1 if result.compression is CompressionStatus.PRE_AUTH else 0,
            labels,
        )

        by_severity = dict.fromkeys(_SEVERITIES, 0)
        for finding in result.findings:
            by_severity[finding.severity.value] += 1
        for severity, count in by_severity.items():
            writer.sample("ssh_target_findings", count, {**labels, "severity": severity})

        matched = [v for v in result.vulnerabilities if not v.undetermined]
        vulnerable = dict.fromkeys(_SEVERITIES, 0)
        for match in matched:
            vulnerable[match.severity.value] += 1
        for severity, count in vulnerable.items():
            writer.sample("ssh_target_vulnerabilities", count, {**labels, "severity": severity})
        writer.sample(
            "ssh_target_vulnerabilities_undetermined",
            sum(1 for v in result.vulnerabilities if v.undetermined),
            labels,
        )

        for entry in result.compliance:
            if entry.status.value == "not-assessed":
                continue
            writer.sample(
                "ssh_target_profile_conformance",
                1 if entry.status is ComplianceStatus.PASS else 0,
                {**labels, "profile": entry.profile_id},
            )
            writer.sample(
                "ssh_target_profile_not_assessed",
                1 if entry.status is ComplianceStatus.NOT_ASSESSED else 0,
                {**labels, "profile": entry.profile_id},
            )

    # Estate seen by normativa: servers per profile and outcome, so a
    # 'conformance by profile' panel needs no `sum by` over per-target series.
    writer.metric(
        "ssh_scan_profile_targets",
        "gauge",
        "Servers per conformance profile and outcome "
        "(status=pass|fail|not-assessed).",
    )
    for pc in report.summary.conformance_by_profile:
        for status, servers in (
            ("pass", pc.passed),
            ("fail", pc.failed),
            ("not-assessed", pc.not_assessed),
        ):
            writer.sample(
                "ssh_scan_profile_targets",
                len(servers),
                {"profile": pc.profile_id, "status": status},
            )

    writer.lines.append("# EOF")
    return "\n".join(writer.lines) + "\n"
