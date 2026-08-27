"""Terminal renderer.

Also provides the building blocks reused by the plain text renderer, so the two
never drift apart.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import List, Optional

from ..models import (
    SEVERITY_ORDER,
    ClassAssessment,
    ComplianceStatus,
    CompressionStatus,
    Finding,
    ScanReport,
    Severity,
    TargetResult,
)
from ..policy import Policy
from .common import (
    Ansi,
    RenderOptions,
    category_color,
    compression_label,
    describe_host_key,
    format_table,
    grade_color,
    post_quantum_label,
    severity_color,
    severity_label,
    summary_headers,
    summary_rows,
    verdict_color,
    verdict_label,
    wrap,
    wrap_comment,
)

__all__ = ["render", "render_summary", "render_target"]

_INDENT = "  "


def render(report: ScanReport, policy: Policy, options: RenderOptions) -> str:
    """Render the whole report for a terminal."""
    ansi = Ansi(options.color)
    lines: List[str] = []
    lines.extend(_render_header(report, options, ansi))

    if not options.summary_only:
        for result in report.results:
            lines.append("")
            lines.extend(render_target(result, policy, options, ansi))

    if len(report.results) > 1 or options.summary_only:
        lines.append("")
        lines.extend(render_summary(report, options, ansi))

    if not options.summary_only:
        t = options.translator
        lines.append("")
        hint = "" if options.show_algorithm_notes else t("rep.con.notes_hint")
        lines.extend(
            ansi(line, "dim")
            for line in wrap(
                t("rep.con.rating_source", hint=hint),
                options.width, "",
            )
        )

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #


def _rule(options: RenderOptions, heavy: bool = False) -> str:
    if not options.unicode:
        return ("=" if heavy else "-") * options.width
    return ("━" if heavy else "─") * options.width


def _render_header(report: ScanReport, options: RenderOptions, ansi: Ansi) -> List[str]:
    t = options.translator
    policy_name = report.policy.get("name", "policy")
    policy_version = report.policy.get("version", "?")
    separator = "  ·  " if options.unicode else " | "
    parts = [
        t("rep.con.policy", name=policy_name, version=policy_version),
        t("rep.con.started", when=report.started_at),
    ]

    subtitle = separator.join(parts)
    # Narrow terminals get one fact per line instead of a line that wraps
    # mid-word.
    subtitle_lines = [subtitle] if len(subtitle) <= options.width else parts

    return [
        _rule(options, heavy=True),
        ansi(f"{report.tool} {report.version}", "bold"),
        *(ansi(line, "dim") for line in subtitle_lines),
        _rule(options, heavy=True),
    ]


# --------------------------------------------------------------------------- #
# One target
# --------------------------------------------------------------------------- #


def render_target(
    result: TargetResult,
    policy: Policy,
    options: RenderOptions,
    ansi: Optional[Ansi] = None,
) -> List[str]:
    """Render the full detail block for a single scanned server."""
    ansi = ansi or Ansi(options.color)
    marker = "▐" if options.unicode else ">"
    heading = f"{marker} {result.target.display_name}"
    if result.target.label:
        heading += f"  ({result.target})"
    if result.resolved_address and result.resolved_address != result.target.host:
        heading += f"  [{result.resolved_address}]"

    lines = [ansi(heading, "bold"), _rule(options)]

    if not result.ok:
        unreachable = options.translator("rep.con.unreachable")
        lines.append(
            f"{_INDENT}{verdict_color(ansi, result.verdict, unreachable)}: {result.error}"
        )
        return lines

    lines.extend(_render_overview(result, options, ansi))
    lines.append("")

    for assessment in result.assessments:
        lines.extend(_render_class(assessment, policy, options, ansi))
        lines.append("")

    if result.host_keys:
        lines.extend(_render_host_keys(result, options, ansi))
        lines.append("")

    # max_startups_probe_limit, not max_startups: the probe reports "more than
    # N accepted" when it finds no limit, and that is an answer. Asking whether
    # a limit was *found* hid every scan where the server accepted everything
    # asked of it, which reads exactly like a probe that never ran.
    if any((result.auth_methods, result.sshfp, result.login_grace_seconds,
            result.known_hosts, result.max_startups_probe_limit is not None,
            result.effective_config)):
        lines.extend(_render_remote_checks(result, options, ansi))
        lines.append("")

    if result.compliance:
        lines.extend(_render_compliance(result, options, ansi))
        lines.append("")

    # Always rendered, even when nothing matched: "none matched" is evidence
    # that the check ran, and its absence would leave a reader guessing.
    lines.extend(_render_vulnerabilities(result, options, ansi))
    lines.append("")

    if result.findings:
        # The vulnerabilities have their own section above; repeating them here
        # would double the length of the longest part of the report.
        other = [f for f in result.findings if not f.id.startswith("vuln-")]
        if other:
            lines.extend(_render_findings(other, options, ansi))
            lines.append("")

    if options.include_config_snippet and result.recommendations:
        lines.extend(_render_recommendations(result, options, ansi))

    while lines and not lines[-1]:
        lines.pop()
    return lines


def _render_overview(result: TargetResult, options: RenderOptions, ansi: Ansi) -> List[str]:
    t = options.translator
    banner = result.banner
    grade = result.grade or "-"
    score = f"{result.score}/100" if result.score is not None else "-"
    verdict_text = verdict_label(t, result.verdict)

    rows = [
        (
            t("rep.field.grade"),
            f"{grade_color(ansi, result.grade, grade)}   "
            f"{t('rep.con.score', score=score)}   "
            f"{verdict_color(ansi, result.verdict, verdict_text)}",
        ),
        (t("rep.field.strength"), _strength_text(result, options, ansi)),
        (t("rep.field.post_quantum"), _post_quantum_text(result, options, ansi)),
        (t("rep.field.strict_kex"), _strict_kex_text(result, options, ansi)),
        (t("rep.field.compression"), _compression_text(result, options, ansi)),
    ]
    if banner is not None:
        software = banner.software or t("rep.con.software_unknown")
        if banner.comments:
            software += f" ({banner.comments})"
        rows.insert(0, (t("rep.field.software"), software))
        rows.insert(1, (t("rep.field.protocol"),
                        t("rep.con.protocol", version=banner.protocol_version or "?")))

    label_width = max(len(label) for label, _ in rows)
    lines = [f"{_INDENT}{label.ljust(label_width)}  {value}" for label, value in rows]

    if banner is not None and banner.pre_banner_lines:
        lines.append(f"{_INDENT}{t('rep.field.login_banner').ljust(label_width)}  "
                     f"{t('rep.con.login_banner_lines', n=len(banner.pre_banner_lines))}")
    return lines


def _strength_text(result: TargetResult, options: RenderOptions, ansi: Ansi) -> str:
    t = options.translator
    strength = result.security_strength
    if strength is None or strength.effective_bits is None:
        return ansi(t("rep.con.strength_unknown"), "dim")
    styles = {
        "high": ("bright_green", "bold"),
        "moderate": ("green",),
        "legacy": ("yellow",),
        "inadequate": ("bright_red", "bold"),
    }.get(strength.level_id, ("dim",))
    return ansi(
        t("rep.con.strength_value", bits=strength.effective_bits, label=strength.level_label),
        *styles,
    )


def _post_quantum_text(result: TargetResult, options: RenderOptions, ansi: Ansi) -> str:
    label = post_quantum_label(options.translator, result.post_quantum)
    styles = {
        "enforced": ("bright_green", "bold"),
        "ready": ("green",),
        "not-ready": ("yellow",),
        "unknown": ("dim",),
    }[result.post_quantum.value]
    return ansi(label, *styles)


def _compression_text(result: TargetResult, options: RenderOptions, ansi: Ansi) -> str:
    """One line saying whether the server compresses, and when it starts."""
    t = options.translator
    state = result.compression
    label = compression_label(t, state)
    if state is CompressionStatus.PRE_AUTH:
        return ansi(label, "bright_red", "bold") + ansi(
            t("rep.con.compression_preauth_note"), "dim"
        )
    if state is CompressionStatus.DISABLED:
        return ansi(label, "green")
    if state is CompressionStatus.POST_AUTH:
        return ansi(label, "green") + ansi(
            t("rep.con.compression_postauth_note"), "dim"
        )
    return ansi(label, "dim")


def _strict_kex_text(result: TargetResult, options: RenderOptions, ansi: Ansi) -> str:
    """La contramedida esta o no esta.

    Nombraba a Terrapin y su CVE en la propia fila, que es dar a una
    vulnerabilidad un sitio que ninguna otra tiene. Lo que se sigue de que
    falte se lee en los hallazgos, junto a todo lo demas.
    """
    t = options.translator
    if result.strict_kex:
        return ansi(t("rep.cell.yes"), "green")
    return ansi(t("rep.cell.no"), "yellow")


def _render_class(
    assessment: ClassAssessment, policy: Policy, options: RenderOptions, ansi: Ansi
) -> List[str]:
    t = options.translator
    if not assessment.algorithms:
        return [f"{_INDENT}{ansi(assessment.label, 'bold')}",
                f"{_INDENT}  {t('rep.con.none_offered')}"]

    title = assessment.label
    if assessment.score is not None:
        title += f"  [{assessment.score}/100]"
    if assessment.directions_differ:
        title += "  " + t("rep.con.directions_differ")
    if assessment.preferred:
        title += "  " + t("rep.con.first_choice", name=assessment.preferred)
    lines = [f"{_INDENT}{ansi(title, 'bold')}"]

    label_width = max(
        len(policy.category_short(a.category)) for a in assessment.algorithms
    )
    name_width = max(len(a.name) for a in assessment.algorithms)

    for algorithm in assessment.algorithms:
        badge = policy.category_short(algorithm.category).ljust(label_width)
        badge = category_color(ansi, algorithm.category, f"[{badge}]")
        annotations = list(algorithm.tags)
        if algorithm.directions and len(algorithm.directions) == 1:
            annotations.append(algorithm.directions[0])
        suffix = f"  {ansi(', '.join(annotations), 'dim')}" if annotations else ""
        lines.append(f"{_INDENT}  {badge} {algorithm.name.ljust(name_width)}{suffix}".rstrip())
        # An algorithm with no notes produces no lines, decided by wrap.
        if options.show_algorithm_notes:
            lines.extend(
                ansi(line, "dim")
                for line in wrap(
                    algorithm.notes, options.width,
                    _INDENT + "  " + " " * (label_width + 3),
                )
            )
    return lines


def _render_host_keys(result: TargetResult, options: RenderOptions, ansi: Ansi) -> List[str]:
    t = options.translator
    lines = [f"{_INDENT}{ansi(t('rep.sec.host_keys'), 'bold')}"]
    for key in result.host_keys:
        # One description, whether the key parsed or not: the console used to
        # write its own for the error case, which threw away the fingerprint
        # of a key that had given one up before failing further in.
        described = describe_host_key(key)
        if key.error:
            lines.append(f"{_INDENT}  {ansi(described, 'dim')}")
            continue
        if len(described) + len(_INDENT) + 2 > options.width:
            # A SHA-256 fingerprint cannot be broken, so give it its own line
            # rather than letting the terminal split it at an arbitrary column.
            head, _, fingerprint = described.rpartition(key.fingerprint_sha256)
            lines.append(f"{_INDENT}  {head.strip()}")
            lines.append(f"{_INDENT}    {key.fingerprint_sha256}{fingerprint}")
        else:
            lines.append(f"{_INDENT}  {described}")
        certificate = key.certificate
        if certificate is not None and certificate.ca_fingerprint:
            if certificate.ca_key_type:
                lines.append(
                    f"{_INDENT}    "
                    + t("rep.con.signed_by", type=certificate.ca_key_type,
                        fp=certificate.ca_fingerprint)
                )
            else:
                # The signing key arrived and its type did not parse. Printing
                # the type as "None" reads as a certificate signed by nothing.
                lines.append(
                    f"{_INDENT}    "
                    + t("rep.con.signed_by_unreadable", fp=certificate.ca_fingerprint)
                )
    if any(key.dh_group_bits for key in result.host_keys):
        bits = next(key.dh_group_bits for key in result.host_keys if key.dh_group_bits)
        lines.append(f"{_INDENT}  {t('rep.con.dh_group', bits=bits)}")
    return lines


def _render_remote_checks(
    result: TargetResult, options: RenderOptions, ansi: Ansi
) -> List[str]:
    """Checks that need more than the algorithm offer."""
    t = options.translator
    # A fixed column width keeps the check names aligned; the labels are short
    # in both languages, so the widest one sets it.
    label_w = max(len(t(k)) for k in (
        "rep.con.rc_auth_methods", "rep.con.rc_login_grace", "rep.con.rc_max_startups",
        "rep.con.rc_known_hosts", "rep.con.rc_sshd_t", "rep.con.rc_authorized_keys",
        "rep.con.rc_sshfp",
    ))

    def _row(label_key: str, value: str) -> str:
        return f"{_INDENT}  {t(label_key).ljust(label_w)}  {value}"

    lines = [f"{_INDENT}{ansi(t('rep.sec.remote_checks'), 'bold')}"]
    auth = result.auth_methods
    if auth is not None:
        if not auth.available:
            lines.append(_row("rep.con.rc_auth_methods", ansi(auth.error or "", "dim")))
        elif auth.accepted_without_credentials:
            lines.append(_row("rep.con.rc_auth_methods",
                              ansi(t("rep.con.auth_none_accepted"), "bright_red", "bold")))
        else:
            risky = {"password", "keyboard-interactive"} & set(auth.methods)
            text = ", ".join(auth.methods) or t("rep.con.auth_none_offered")
            lines.append(_row(
                "rep.con.rc_auth_methods",
                (ansi(text, "yellow") if risky else ansi(text, "green"))
                + ansi(t("rep.con.auth_as_user", user=auth.username), "dim"),
            ))
    if result.login_grace_seconds is not None:
        lines.append(_row("rep.con.rc_login_grace",
                          t("rep.con.login_grace_hangup",
                            secs=f"{result.login_grace_seconds:.0f}")))
    if result.max_startups_probe_limit is not None:
        if result.max_startups is None:
            text = t("rep.con.max_startups_more_than", n=result.max_startups_probe_limit)
        else:
            text = t("rep.con.max_startups_refused", n=result.max_startups)
        lines.append(_row("rep.con.rc_max_startups", text))
    known = result.known_hosts
    if known is not None and known.checked:
        if known.entries_found == 0:
            state = ansi(t("rep.con.kh_no_record"), "dim")
        elif known.revoked:
            # Not the same thing as a mismatch, and saying so sends whoever
            # reads it looking for the wrong problem. The key matches its
            # record exactly; the record is the one that says it is revoked.
            state = ansi(t("rep.con.kh_revoked"), "bright_red", "bold")
        elif known.changed:
            state = ansi(t("rep.con.kh_changed"), "bright_red", "bold")
        else:
            state = ansi(t("rep.con.kh_match", n=len(known.matched)), "green")
        lines.append(_row("rep.con.rc_known_hosts", state))
    config = result.effective_config
    if config is not None and config.attempted:
        if config.available:
            state = ansi(
                t("rep.con.cfg_directives", n=len(config.directives), user=config.username),
                "green",
            )
        else:
            state = ansi(config.error or t("rep.con.cfg_unavailable"), "dim")
        lines.append(_row("rep.con.rc_sshd_t", state))
        if config.authorized_keys:
            entries = config.authorized_keys
            restricted = sum(1 for entry in entries if entry.restricted)
            detail = t("rep.con.ak_entries", n=len(entries), restricted=restricted)
            expired = sum(1 for entry in entries if entry.expired)
            if expired:
                detail += ansi(t("rep.con.ak_expired", n=expired), "yellow")
            lines.append(_row("rep.con.rc_authorized_keys", detail))
    check = result.sshfp
    if check is not None and check.queried:
        if check.error:
            lines.append(_row("rep.con.rc_sshfp", ansi(check.error, "dim")))
        elif check.records_found == 0:
            lines.append(_row("rep.con.rc_sshfp", ansi(t("rep.con.sshfp_no_records"), "yellow")))
        else:
            state = t("rep.con.sshfp_match", matched=len(check.matched), found=check.records_found)
            if check.dnssec_authenticated:
                state += t("rep.con.sshfp_dnssec_ok")
            else:
                state += t("rep.con.sshfp_dnssec_no")
            lines.append(_row("rep.con.rc_sshfp", state))
    return lines


def _render_compliance(
    result: TargetResult, options: RenderOptions, ansi: Ansi
) -> List[str]:
    """Per-standard conformance, kept separate from this tool's own grade."""
    t = options.translator
    lines = [f"{_INDENT}{ansi(t('rep.sec.conformance'), 'bold')}"]
    strength = result.security_strength
    if strength is not None and strength.effective_bits is not None:
        held = (
            t("rep.con.held_down_by", items=", ".join(strength.limiting[:3]))
            if strength.limiting
            else ""
        )
        lines.extend(
            ansi(line, "dim")
            for line in wrap(
                t("rep.con.effective_strength", bits=strength.effective_bits,
                  label=strength.level_label, desc=strength.level_description) + held,
                options.width,
                _INDENT + "  ",
            )
        )
        lines.append("")

    name_width = max(len(entry.name) for entry in result.compliance)
    body_indent = _INDENT + "      "
    for entry in result.compliance:
        passed = entry.status is ComplianceStatus.PASS
        if passed:
            badge = ansi(t("rep.con.badge_pass"), "green", "bold")
        elif entry.status is ComplianceStatus.NOT_ASSESSED:
            # Deliberately not a failure and deliberately not a pass: the scan
            # did not establish either, and the report must not pick one.
            badge = ansi(t("rep.con.badge_unknown"), "yellow", "bold")
        else:
            badge = ansi(t("rep.con.badge_fail"), "bright_red", "bold")
        lines.append(
            f"{_INDENT}  {badge} {entry.name.ljust(name_width)}  "
            f"{ansi(entry.authority, 'dim')}"
        )
        # Only when that is the verdict. A profile that failed has its answer;
        # listing what else went unchecked would bury it.
        if entry.status is ComplianceStatus.NOT_ASSESSED:
            for reason in entry.unverified:
                lines.extend(
                    ansi(line, "yellow")
                    for line in wrap(
                        t("rep.con.not_assessed", reason=reason),
                        options.width, body_indent,
                    )
                )
        if not passed:
            for violation in entry.violations[:6]:
                subject = violation.subject
                lines.append(f"{body_indent}- {subject}")
            if len(entry.violations) > 6:
                lines.append(
                    ansi(f"{body_indent}  "
                         + t("rep.con.and_more", n=len(entry.violations) - 6), "dim")
                )
            reasons = []
            for violation in entry.violations:
                text = (
                    t(violation.reason_key, **violation.reason_args)
                    if violation.reason_key else violation.reason
                )
                if text and text not in reasons:
                    reasons.append(text)
            for reason in reasons[:2]:
                lines.extend(ansi(line, "dim") for line in wrap(reason, options.width, body_indent))
    return lines


def _render_vulnerabilities(
    result: TargetResult, options: RenderOptions, ansi: Ansi
) -> List[str]:
    """Known vulnerabilities, as their own section.

    They are separated from the configuration findings because they answer a
    different question. A finding says the server is configured in a way this
    policy dislikes; a vulnerability says somebody published an attack against
    the software it runs, with an identifier the reader can look up.
    """
    t = options.translator
    matched = [v for v in result.vulnerabilities if not v.undetermined]
    unknown = [v for v in result.vulnerabilities if v.undetermined]

    lines = [f"{_INDENT}{ansi(t('rep.sec.vulnerabilities'), 'bold')}"]
    body_indent = _INDENT + "    "

    if not matched:
        lines.append(f"{_INDENT}  {ansi(t('rep.con.none_matched'), 'green')}")
    for match in sorted(matched, key=lambda m: SEVERITY_ORDER.index(m.severity)):
        badge = severity_color(ansi, match.severity, f"[{severity_label(t, match.severity)}]")
        lines.append(f"{_INDENT}  {badge} {match.id}: {match.name}")
        if match.affects == "client":
            lines.append(
                ansi(f"{body_indent}{t('rep.con.affects_client')}", "dim")
            )
        lines.extend(
            ansi(line, "dim") for line in wrap(match.description, options.width, body_indent)
        )
        for item in match.evidence:
            lines.append(f"{body_indent}- {item}")
        if match.version_based:
            lines.extend(
                ansi(line, "dim")
                for line in wrap(t("rep.con.version_based"), options.width, body_indent)
            )
        if match.remediation:
            lines.extend(wrap(t("rep.con.fix", text=match.remediation), options.width, body_indent))
        if match.references:
            lines.extend(
                ansi(line, "dim")
                for line in wrap(
                    t("rep.con.see", refs=", ".join(match.references)), options.width, body_indent
                )
            )

    if unknown:
        lines.append("")
        needed = sorted({item for match in unknown for item in match.needs})
        lines.append(
            f"{_INDENT}  {ansi(t('rep.con.not_determined'), 'yellow')}: "
            f"{t('rep.con.not_determined_detail', n=len(unknown))}"
        )
        lines.extend(
            ansi(line, "dim")
            for line in wrap(
                ", ".join(f"{m.id} ({m.name})" for m in unknown), options.width, body_indent
            )
        )
        lines.extend(
            wrap(t("rep.con.rerun_with", needed=", ".join(needed)), options.width, body_indent)
        )
    return lines


def _render_findings(
    findings: Sequence[Finding], options: RenderOptions, ansi: Ansi
) -> List[str]:
    t = options.translator
    lines = [f"{_INDENT}{ansi(t('rep.sec.findings'), 'bold')}"]
    body_indent = _INDENT + "    "
    for finding in findings:
        badge = severity_color(ansi, finding.severity, f"[{severity_label(t, finding.severity)}]")
        lines.append(f"{_INDENT}  {badge} {finding.title}")
        lines.extend(
            ansi(line, "dim")
            for line in wrap(finding.description, options.width, body_indent)
        )
        for item in finding.items:
            lines.append(f"{body_indent}- {item}")
        if finding.remediation:
            lines.extend(
                wrap(t("rep.con.fix", text=finding.remediation), options.width, body_indent)
            )
        if finding.references:
            lines.extend(
                ansi(line, "dim")
                for line in wrap(
                    t("rep.con.see", refs=", ".join(finding.references)), options.width, body_indent
                )
            )
    return lines


def _render_recommendations(
    result: TargetResult, options: RenderOptions, ansi: Ansi
) -> List[str]:
    t = options.translator
    lines = [
        f"{_INDENT}{ansi(t('rep.sec.recommendations'), 'bold')}",
    ]
    lines.extend(
        ansi(line, "dim")
        for line in wrap(
            t("rep.con.recommendations_intro"),
            options.width,
            _INDENT + "  ",
        )
    )
    for recommendation in result.recommendations:
        lines.extend(
            ansi(line, "dim")
            for line in wrap_comment(recommendation.comment, options.width, _INDENT + "  ")
        )
        lines.append(f"{_INDENT}  {ansi(recommendation.as_config_line(), 'cyan')}")
    return lines


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #


def render_summary(report: ScanReport, options: RenderOptions, ansi: Ansi) -> List[str]:
    """Render the aggregate table and counters."""
    t = options.translator
    summary = report.summary
    lines = [_rule(options, heavy=True), ansi(t("rep.sec.summary"), "bold"), ""]

    lines.extend(
        format_table(
            summary_headers(t),
            summary_rows(report.results, t),
            options.width,
            ansi,
            options.unicode,
        )
    )
    lines.append("")

    counters = [t("rep.con.targets_scanned", n=summary.total)]
    if summary.failed:
        counters.append(t("rep.con.unreachable_count", n=summary.failed))
    if summary.average_score is not None:
        counters.append(t("rep.con.average_score", score=summary.average_score))
    counters.append(t("rep.con.pq_ready_count", n=summary.post_quantum_ready))
    lines.append(", ".join(counters))

    if summary.by_vulnerability:
        # Ordenadas por cuantas maquinas las comparten, que es lo que decide
        # por donde empezar. Sin CVE destacadas: Terrapin tenia su propio
        # contador aqui y ninguna otra lo tenia.
        lines.append("")
        lines.append(ansi(t("rep.con.most_widespread"), "bold"))
        for identifier, count in list(summary.by_vulnerability.items())[:5]:
            share = f"{count}/{summary.total}"
            lines.append(
                f"  {identifier.ljust(24)} {share.rjust(7)} {t('rep.con.widespread_targets')}"
            )

    if summary.conformance_by_profile:
        lines.append("")
        lines.append(ansi(t("rep.con.conformance_by_profile"), "bold"))
        for pc in summary.conformance_by_profile:
            passed, total = len(pc.passed), pc.assessed
            style = "green" if passed == total else ("yellow" if passed else "bright_red")
            lines.append(
                f"  {pc.profile_id.ljust(24)} "
                f"{ansi(t('rep.con.conform', passed=passed, total=total), style)}"
            )
            for server in pc.failed:
                offenders = pc.offenders.get(server)
                if offenders:
                    for line in wrap(
                        t("rep.con.fail_offenders", server=server, items=", ".join(offenders)),
                        options.width, "      "
                    ):
                        lines.append(ansi(line, "bright_red"))
                else:
                    lines.append(f"      {ansi(t('rep.con.fail'), 'bright_red')} {server}")
            for index, fix in enumerate(pc.remediation):
                spec = pc.remediation_specs[index] if index < len(pc.remediation_specs) else None
                text = t(spec[0], **spec[1]) if spec and spec[0] else fix
                lines.extend(
                    ansi(line, "cyan")
                    for line in wrap(t("rep.con.to_comply", fix=text), options.width, "        ")
                )
            if pc.not_assessed:
                lines.append(f"      {ansi('[?] ', 'yellow')}{', '.join(pc.not_assessed)}")

    if summary.by_severity:
        lines.append("")
        # by_severity only ever holds severities somebody actually found, so
        # a non-empty table always produces a non-empty line.
        parts = [
            severity_color(ansi, severity, f"{count} {severity_label(t, severity).lower()}")
            for severity in Severity
            for count in (summary.by_severity.get(severity.value, 0),)
            if count
        ]
        lines.append(t("rep.con.findings_prefix") + ", ".join(parts))

    lines.append(t("rep.con.completed_in", secs=f"{report.duration_ms / 1000:.1f}"))
    return lines
