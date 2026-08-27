"""Plain text renderer, meant to be attached to a ticket or an email.

Same content as the console renderer but without any escape sequence, with a
document header and an appendix explaining how to read the result.
"""

from __future__ import annotations

from typing import List

from ..models import ScanReport, Severity, Verdict
from ..policy import Policy
from .common import (
    Ansi,
    RenderOptions,
    format_table,
    severity_label,
    summary_headers,
    summary_rows,
    verdict_label,
    wrap,
)
from .console import render_target

__all__ = ["render"]

_PLAIN = Ansi(False)


def render(report: ScanReport, policy: Policy, options: RenderOptions) -> str:
    """Render the report as a self-contained text document."""
    text_options = RenderOptions(
        color=False,
        unicode=options.unicode,
        width=max(72, min(options.width, 100)),
        summary_only=options.summary_only,
        include_config_snippet=True,
        show_algorithm_notes=options.show_algorithm_notes,
        translator=options.translator,
    )

    lines: List[str] = []
    lines.extend(_document_header(report, text_options))

    if not text_options.summary_only:
        for result in report.results:
            lines.append("")
            lines.extend(render_target(result, policy, text_options, _PLAIN))
            lines.append("")

    lines.extend(_summary_section(report, text_options))
    lines.append("")
    lines.extend(_legend(policy, text_options))

    return "\n".join(lines) + "\n"


def _document_header(report: ScanReport, options: RenderOptions) -> List[str]:
    t = options.translator
    rule = "=" * options.width
    policy_name = report.policy.get("name", "policy")
    policy_version = report.policy.get("version", "?")
    policy_updated = report.policy.get("updated", "?")
    fields = [
        ("rep.txt.lbl_generated", report.finished_at or report.started_at),
        ("rep.txt.lbl_targets",
         t("rep.txt.targets_value", total=report.summary.total, failed=report.summary.failed)),
        ("rep.txt.lbl_policy",
         t("rep.txt.policy_value", name=policy_name, version=policy_version,
           updated=policy_updated)),
        ("rep.txt.lbl_policy_source", report.policy.get("source", "-")),
        ("rep.txt.lbl_command", report.command_line or "-"),
    ]
    label_w = max(len(t(key)) for key, _ in fields)
    return [
        rule,
        t("rep.txt.doc_title", tool=report.tool, version=report.version)
        .center(options.width).rstrip(),
        rule,
        "",
        *(f"{t(key).ljust(label_w)} : {value}" for key, value in fields),
        "",
        rule,
    ]


def _summary_section(report: ScanReport, options: RenderOptions) -> List[str]:
    t = options.translator
    summary = report.summary
    lines = ["=" * options.width, t("rep.txt.summary_title"), "=" * options.width, ""]
    lines.extend(
        format_table(
            summary_headers(t), summary_rows(report.results, t),
            options.width, _PLAIN, options.unicode,
        )
    )
    lines.append("")

    # Labels line up in a column; the width is set by the widest one used here.
    label_keys = [
        "rep.txt.lbl_verdicts", "rep.txt.lbl_grades", "rep.txt.lbl_average_score",
        "rep.txt.lbl_post_quantum", "rep.txt.lbl_most_widespread", "rep.txt.lbl_findings",
        "rep.txt.lbl_strength", "rep.txt.lbl_duration",
    ]
    label_w = max(len(t(key)) for key in label_keys)

    def _line(label_key: str, value: str) -> str:
        return f"{t(label_key).ljust(label_w)} : {value}"

    if summary.by_verdict:
        # by_verdict is keyed by the enum's string value; Verdict is a str enum
        # so the lookup below matches on value.
        parts = [
            f"{count} {verdict_label(t, Verdict(verdict))}"
            for verdict, count in sorted(summary.by_verdict.items())
        ]
        lines.append(_line("rep.txt.lbl_verdicts", ", ".join(parts)))
    if summary.by_grade:
        lines.append(_line(
            "rep.txt.lbl_grades",
            ", ".join(f"{grade}: {count}" for grade, count in sorted(summary.by_grade.items())),
        ))
    if summary.average_score is not None:
        lines.append(_line("rep.txt.lbl_average_score", f"{summary.average_score}/100"))
    lines.append(_line(
        "rep.txt.lbl_post_quantum",
        t("rep.txt.pq_ready_of", ready=summary.post_quantum_ready, total=summary.total),
    ))
    if summary.by_vulnerability:
        # Las mas extendidas primero, que es lo que decide por donde empezar
        # a arreglar. Aqui no hay ninguna CVE con trato de favor: hubo una
        # linea dedicada a Terrapin, y una vulnerabilidad con seccion propia
        # parece mas importante que las demas sin serlo.
        widespread = list(summary.by_vulnerability.items())[:5]
        lines.append(_line(
            "rep.txt.lbl_most_widespread",
            ", ".join(f"{identifier} ({count})" for identifier, count in widespread),
        ))
    if summary.by_severity:
        lines.append(_line(
            "rep.txt.lbl_findings",
            ", ".join(
                f"{count} {severity_label(t, Severity(severity))}"
                for severity, count in sorted(summary.by_severity.items())
            ),
        ))
    if summary.by_strength_level:
        lines.append(_line(
            "rep.txt.lbl_strength",
            ", ".join(
                f"{count} {level}"
                for level, count in sorted(summary.by_strength_level.items())
            ),
        ))
    if summary.conformance_by_profile:
        lines.append("")
        lines.append(t("rep.txt.conformance_heading"))
        for pc in summary.conformance_by_profile:
            lines.append(f"  {pc.profile_id.ljust(24)} {len(pc.passed)}/{pc.assessed}")
            for server in pc.failed:
                offenders = pc.offenders.get(server)
                if offenders:
                    lines.extend(wrap(
                        t("rep.txt.fail_offenders", server=server, items=", ".join(offenders)),
                        options.width, "      ",
                    ))
                else:
                    lines.append(f"      {t('rep.txt.fail_server', server=server)}")
            for index, fix in enumerate(pc.remediation):
                spec = pc.remediation_specs[index] if index < len(pc.remediation_specs) else None
                text = t(spec[0], **spec[1]) if spec and spec[0] else fix
                lines.extend(wrap(t("rep.txt.to_comply", fix=text), options.width, "        "))
            if pc.not_assessed:
                lines.append(f"      {t('rep.txt.not_assessed', items=', '.join(pc.not_assessed))}")
    lines.append("")
    lines.append(_line("rep.txt.lbl_duration", f"{report.duration_ms / 1000:.1f}s"))
    return lines


def _legend(policy: Policy, options: RenderOptions) -> List[str]:
    t = options.translator
    lines = ["=" * options.width, t("rep.txt.legend_title"), "=" * options.width, ""]

    lines.append(t("rep.txt.algorithm_categories"))
    for info in policy.categories.values():
        lines.append(f"  [{info.short}] {info.label}")
        lines.extend(wrap(info.description, options.width, "        "))
    lines.append("")
    lines.extend(wrap(t("rep.txt.rating_source"), options.width, "  "))
    lines.append("")

    lines.append(t("rep.txt.severities_heading"))
    lines.append("  " + "  ".join(f"[{severity_label(t, s)}]" for s in Severity))
    lines.append("")

    lines.extend(wrap(t("rep.txt.scoring"), options.width))
    lines.append("")
    lines.extend(wrap(t("rep.txt.unknown_algorithms", source=policy.source), options.width))
    lines.append("")

    lines.append(t("rep.txt.conformance_heading2"))
    lines.extend(wrap(t("rep.txt.conformance_intro"), options.width, "  "))
    lines.append("")
    for profile in policy.profiles.values():
        lines.append(f"  {profile.name} ({profile.authority})")
        if profile.edition:
            lines.extend(
                wrap(t("rep.txt.edition_checked", edition=profile.edition), options.width, "      ")
            )
        lines.extend(wrap(profile.reference, options.width, "      "))
        # No "if summary" here: wrap answers an empty string with no lines,
        # and asking twice is how the two answers drift apart.
        lines.extend(wrap(profile.summary, options.width, "      "))
        lines.append("")
    return lines
