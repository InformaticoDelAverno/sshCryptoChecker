"""Self-contained HTML renderer.

The output has no external references at all -- no fonts, no scripts, no
stylesheets -- so the file can be mailed, archived or opened from a share
without leaking anything to the network. It adapts to the reader's light or
dark theme and prints cleanly.
"""

from __future__ import annotations

import html
import re
from collections.abc import Sequence
from typing import List, Optional

from ..i18n import Translator
from ..models import (
    SEVERITY_ORDER,
    ClassAssessment,
    ComplianceStatus,
    CompressionStatus,
    Finding,
    PostQuantumStatus,
    ScanReport,
    ScanSummary,
    Severity,
    TargetResult,
    Verdict,
)
from ..policy import Policy
from .common import (
    RenderOptions,
    compression_label,
    post_quantum_label,
    severity_label,
    verdict_label,
)

__all__ = ["render"]

#: NIST security-strength band -> badge CSS class.
_STRENGTH_CLASSES = {
    "high": "recommended",
    "moderate": "acceptable",
    "legacy": "weak",
    "inadequate": "insecure",
}

#: Verdict -> badge CSS class.
_VERDICT_CLASSES = {
    Verdict.SECURE: "recommended",
    Verdict.ACCEPTABLE: "acceptable",
    Verdict.WEAK: "weak",
    Verdict.INSECURE: "insecure",
    Verdict.UNKNOWN: "unknown",
    Verdict.ERROR: "unknown",
}


_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #f5f6f8;
  --surface: #ffffff;
  --surface-alt: #f0f2f5;
  --border: #d9dee5;
  --text: #1b1f24;
  --muted: #5c6773;
  --accent: #2563eb;
  --ok: #17803d;
  --ok-bg: #e7f6ec;
  --acceptable: #1d4ed8;
  --acceptable-bg: #e6edfe;
  --weak: #a35a00;
  --weak-bg: #fdf0dc;
  --insecure: #b3261e;
  --insecure-bg: #fbe6e4;
  --unknown: #6b3fa0;
  --unknown-bg: #f0e9f9;
  --info: #55606d;
  --info-bg: #eceff3;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14171c;
    --surface: #1c2027;
    --surface-alt: #232830;
    --border: #333b46;
    --text: #e6e9ee;
    --muted: #9aa5b1;
    --accent: #7aa2f7;
    --ok: #4ade80; --ok-bg: #14301f;
    --acceptable: #7aa2f7; --acceptable-bg: #172136;
    --weak: #fbbf24; --weak-bg: #33260a;
    --insecure: #f87171; --insecure-bg: #3a1a18;
    --unknown: #c4a2f5; --unknown-bg: #271a38;
    --info: #9aa5b1; --info-bg: #242a32;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 0 1rem 4rem;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
  font-size: 15px;
  line-height: 1.55;
}
.wrap { max-width: 1100px; margin: 0 auto; }
code, pre, .mono {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
    "Liberation Mono", monospace;
}
h1, h2, h3 { line-height: 1.25; margin: 0; }
h1 { font-size: 1.6rem; }
h2 { font-size: 1.2rem; margin-bottom: .75rem; }
h3 {
  font-size: .95rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  margin-bottom: .5rem;
}
a { color: var(--accent); }
header.page {
  padding: 2rem 0 1.25rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 1.5rem;
}
header.page .meta { color: var(--muted); font-size: .875rem; margin-top: .5rem; }
header.page .meta span { margin-right: 1.25rem; white-space: nowrap; }
section { margin-bottom: 2rem; }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.25rem;
}
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: .75rem;
  margin-bottom: 1.5rem;
}
.stat {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: .9rem 1rem;
}
.stat .value { font-size: 1.75rem; font-weight: 650; line-height: 1.1; }
.stat .label {
  color: var(--muted);
  font-size: .8rem;
  text-transform: uppercase;
  letter-spacing: .05em;
  margin-top: .2rem;
}
.table-scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td {
  text-align: left;
  padding: .5rem .65rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
th {
  font-size: .78rem;
  text-transform: uppercase;
  letter-spacing: .05em;
  color: var(--muted);
  font-weight: 600;
  white-space: nowrap;
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--surface-alt); }
.badge {
  display: inline-block;
  padding: .1rem .5rem;
  border-radius: 999px;
  font-size: .74rem;
  font-weight: 650;
  letter-spacing: .03em;
  white-space: nowrap;
}
.badge.recommended { color: var(--ok); background: var(--ok-bg); }
.badge.acceptable { color: var(--acceptable); background: var(--acceptable-bg); }
.badge.weak { color: var(--weak); background: var(--weak-bg); }
.badge.insecure { color: var(--insecure); background: var(--insecure-bg); }
.badge.unknown { color: var(--unknown); background: var(--unknown-bg); }
.badge.informational, .badge.info { color: var(--info); background: var(--info-bg); }
.badge.critical { color: #fff; background: var(--insecure); }
.badge.high { color: var(--insecure); background: var(--insecure-bg); }
.badge.medium { color: var(--weak); background: var(--weak-bg); }
.badge.low { color: var(--acceptable); background: var(--acceptable-bg); }
.grade {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 3rem;
  height: 3rem;
  border-radius: 10px;
  font-size: 1.5rem;
  font-weight: 700;
  padding: 0 .5rem;
}
.grade.g-Aplus, .grade.g-A { color: var(--ok); background: var(--ok-bg); }
.grade.g-B { color: var(--acceptable); background: var(--acceptable-bg); }
.grade.g-C, .grade.g-D { color: var(--weak); background: var(--weak-bg); }
.grade.g-F { color: #fff; background: var(--insecure); }
.grade.g-none { color: var(--info); background: var(--info-bg); }
.target { margin-bottom: 1.5rem; }
.target > summary {
  cursor: pointer;
  list-style: none;
  padding: 1rem 1.25rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
}
.target[open] > summary { border-radius: 10px 10px 0 0; border-bottom: none; }
.target > summary::-webkit-details-marker { display: none; }
.target > summary:hover { background: var(--surface-alt); }
.target .name { font-size: 1.1rem; font-weight: 650; }
.target .sub { color: var(--muted); font-size: .85rem; }
.target .spacer { flex: 1 1 auto; }
.target .body {
  border: 1px solid var(--border);
  border-top: 1px solid var(--border);
  border-radius: 0 0 10px 10px;
  padding: 1.25rem;
  background: var(--surface);
}
.kv {
  display: grid;
  grid-template-columns: minmax(7rem, max-content) 1fr;
  gap: .3rem 1rem;
  font-size: .9rem;
  margin-bottom: 1.5rem;
}
.kv dt { color: var(--muted); }
.kv dd { margin: 0; overflow-wrap: anywhere; }
.finding {
  border-left: 3px solid var(--border);
  padding: .1rem 0 .1rem .9rem;
  margin-bottom: 1.1rem;
}
.finding.critical, .finding.high { border-left-color: var(--insecure); }
.finding.medium { border-left-color: var(--weak); }
.finding.low { border-left-color: var(--acceptable); }
.finding.info { border-left-color: var(--info); }
.finding .title { font-weight: 650; margin-left: .4rem; }
.finding p { margin: .4rem 0; }
.finding .fix { color: var(--muted); }
.finding ul { margin: .4rem 0; padding-left: 1.2rem; }
.finding li {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .85rem;
  overflow-wrap: anywhere;
}
pre.config {
  background: var(--surface-alt);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: .9rem 1rem;
  overflow-x: auto;
  font-size: .85rem;
  margin: 0;
}
pre.config .comment { color: var(--muted); }
.tags { color: var(--muted); font-size: .8rem; }
.note { color: var(--muted); font-size: .85rem; }
.error { color: var(--insecure); font-weight: 600; }
footer {
  border-top: 1px solid var(--border);
  padding-top: 1rem;
  margin-top: 2rem;
  color: var(--muted);
  font-size: .82rem;
}
@media print {
  body { background: #fff; padding: 0; font-size: 11pt; }
  .card, .stat, .target > summary, .target .body { border-color: #bbb; break-inside: avoid; }
  .target > summary { background: #fff; }
  details { display: block; }
  details > summary { list-style: none; }
}
"""

_SCRIPT = """
document.addEventListener('click', function (event) {
  var action = event.target && event.target.dataset ? event.target.dataset.action : null;
  if (!action) return;
  var open = action === 'expand';
  document.querySelectorAll('details.target').forEach(function (node) { node.open = open; });
});
"""


def _e(value: object) -> str:
    """HTML-escape any value."""
    return html.escape(str(value), quote=True)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "target"


def _grade_class(grade: Optional[str]) -> str:
    if not grade:
        return "g-none"
    return "g-" + grade.replace("+", "plus")


def _badge(text: str, css_class: str) -> str:
    return f'<span class="badge {_e(css_class)}">{_e(text)}</span>'


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #


def _header(report: ScanReport, t: Translator) -> str:
    policy_name = report.policy.get("name", "policy")
    policy_version = report.policy.get("version", "?")
    return (
        '<header class="page"><div class="wrap">'
        f"<h1>{_e(report.tool)} &mdash; {_e(t('rep.html.audit_title'))}</h1>"
        '<div class="meta">'
        f"<span>{_e(t('rep.html.generated', when=report.finished_at or report.started_at))}</span>"
        f"<span>{_e(t('rep.html.targets_count', count=report.summary.total))}</span>"
        f"<span>{_e(t('rep.html.policy', name=policy_name, version=policy_version))}</span>"
        f"<span>{_e(report.tool)} {_e(report.version)}</span>"
        "</div></div></header>"
    )


def _stat(t: Translator, value: object, label_key: str, css_class: str = "") -> str:
    style = f' style="color: var(--{css_class})"' if css_class else ""
    return (
        f'<div class="stat"><div class="value"{style}>{_e(value)}</div>'
        f'<div class="label">{_e(t(label_key))}</div></div>'
    )


def _conf_group(t: Translator, label_key: str, names: List[str], css_class: str) -> str:
    if not names:
        return ""
    items = "".join(f"<li>{_e(name)}</li>" for name in names)
    return (
        f'<div class="conf-group"><h4>{_e(t(label_key))} '
        f'{_badge(str(len(names)), css_class)}</h4><ul>{items}</ul></div>'
    )


def _conformance_by_profile(t: Translator, summary: ScanSummary) -> str:
    """One collapsible accordion per profile: the estate seen by normativa."""
    if not summary.conformance_by_profile:
        return ""
    blocks = []
    for pc in summary.conformance_by_profile:
        passed, total = len(pc.passed), pc.assessed
        css_class = "recommended" if passed == total else (
            "insecure" if passed == 0 else "acceptable"
        )
        meta = f" &middot; {_e(pc.authority)}" if pc.authority else ""
        edition = f' <span class="mono">{_e(pc.edition)}</span>' if pc.edition else ""
        fail_group = ""
        if pc.failed:
            items = "".join(
                f"<li>{_e(server)}"
                + (
                    ': <span class="mono">' + _e(", ".join(pc.offenders[server])) + "</span>"
                    if pc.offenders.get(server)
                    else ""
                )
                + "</li>"
                for server in pc.failed
            )
            fail_group = (
                '<div class="conf-group"><h4>'
                f'{_e(t("rep.html.conf_fail"))} {_badge(str(len(pc.failed)), "insecure")}'
                f"</h4><ul>{items}</ul></div>"
            )
        remediation = ""
        if pc.remediation:
            fix_texts = []
            for index, fix in enumerate(pc.remediation):
                spec = pc.remediation_specs[index] if index < len(pc.remediation_specs) else None
                fix_texts.append(t(spec[0], **spec[1]) if spec and spec[0] else fix)
            fixes = "".join(f"<li>{_e(fix)}</li>" for fix in fix_texts)
            remediation = (
                f'<div class="conf-group"><h4>{_e(t("rep.html.conf_to_comply"))}</h4><ul>'
                + fixes + "</ul></div>"
            )
        groups = (
            _conf_group(t, "rep.html.conf_conform", pc.passed, "recommended")
            + fail_group
            + _conf_group(t, "rep.html.conf_not_assessed", pc.not_assessed, "weak")
            + remediation
        )
        blocks.append(
            f'<details class="profile"><summary>{_e(pc.name)}{meta}{edition} '
            f'{_badge(t("rep.html.conf_summary", passed=passed, total=total), css_class)}</summary>'
            f'<div class="conf-groups">{groups}</div></details>'
        )
    return (
        f'<div class="card"><h2>{_e(t("rep.html.conformance_heading"))}</h2>'
        f'<p class="note">{_e(t("rep.html.conformance_intro"))}</p>'
        f'{"".join(blocks)}</div>'
    )


def _summary_section(report: ScanReport, t: Translator) -> str:
    summary = report.summary
    cards = [
        _stat(t, summary.total, "rep.html.stat_targets"),
        _stat(t, summary.by_verdict.get(Verdict.SECURE.value, 0), "rep.html.stat_secure", "ok"),
        _stat(
            t,
            summary.by_verdict.get(Verdict.WEAK.value, 0)
            + summary.by_verdict.get(Verdict.INSECURE.value, 0),
            "rep.html.stat_need_action",
            "insecure",
        ),
        _stat(t, f"{summary.post_quantum_ready}/{summary.total}", "rep.html.stat_pq_ready"),
        _stat(t, summary.vulnerable, "rep.html.stat_cve", "insecure"),
        _stat(
            t,
            summary.average_score if summary.average_score is not None else "-",
            "rep.html.stat_avg_score",
        ),
    ]
    if summary.failed:
        cards.append(_stat(t, summary.failed, "rep.html.stat_unreachable", "weak"))

    rows = []
    for result in report.results:
        anchor = _slug(str(result.target))
        pq = {
            PostQuantumStatus.ENFORCED: _badge(t("rep.pqcell.enforced"), "recommended"),
            PostQuantumStatus.READY: _badge(t("rep.pqcell.ready"), "acceptable"),
            PostQuantumStatus.NOT_READY: _badge(t("rep.pqcell.no"), "weak"),
            PostQuantumStatus.UNKNOWN: _badge("-", "info"),
        }[result.post_quantum]
        verdict_class = _VERDICT_CLASSES[result.verdict]
        software = result.banner.software if result.banner else (result.error or "")
        strict_kex = (
            t("rep.cell.yes") if result.strict_kex
            else ("-" if not result.ok else t("rep.cell.no"))
        )
        rows.append(
            "<tr>"
            f'<td><a href="#{_e(anchor)}">{_e(result.target.display_name)}</a></td>'
            f'<td><strong>{_e(result.grade or "-")}</strong></td>'
            f'<td>{_e(result.score if result.score is not None else "-")}</td>'
            f"<td>{_badge(verdict_label(t, result.verdict), verdict_class)}"
            "</td>"
            f"<td>{pq}</td>"
            f'<td>{_e(strict_kex)}</td>'
            f'<td class="mono">{_e(software)}</td>'
            "</tr>"
        )

    # Las vulnerabilidades que mas maquinas comparten, que es lo que decide
    # por donde empezar a arreglar. Aqui hubo una tarjeta dedicada a Terrapin:
    # una CVE con seccion propia parece mas importante que las demas sin
    # serlo, y esta lista las trata a todas por el mismo criterio.
    widespread = ""
    if summary.by_vulnerability:
        filas = "".join(
            f"<tr><td class=\"mono\">{_e(identifier)}</td>"
            f"<td>{_e(t('rep.html.count_of', count=count, total=summary.total))}</td></tr>"
            for identifier, count in list(summary.by_vulnerability.items())[:10]
        )
        widespread = (
            f'<div class="card"><h2>{_e(t("rep.html.widespread_heading"))}</h2>'
            '<div class="table-scroll"><table>'
            f"<thead><tr><th>{_e(t('rep.html.col_identifier'))}</th>"
            f"<th>{_e(t('rep.html.col_targets'))}</th></tr></thead>"
            f"<tbody>{filas}</tbody></table></div></div>"
        )

    return (
        '<section id="summary">'
        f'<div class="cards">{"".join(cards)}</div>'
        f"{widespread}"
        f"{_conformance_by_profile(t, summary)}"
        f'<div class="card"><h2>{_e(t("rep.html.all_targets"))}</h2>'
        '<div class="table-scroll"><table>'
        f"<thead><tr><th>{_e(t('rep.sumhdr.target'))}</th><th>{_e(t('rep.field.grade'))}</th>"
        f"<th>{_e(t('rep.sumhdr.score'))}</th><th>{_e(t('rep.sumhdr.verdict'))}</th>"
        f"<th>{_e(t('rep.field.post_quantum'))}</th><th>{_e(t('rep.field.strict_kex'))}</th>"
        f"<th>{_e(t('rep.field.software'))}</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div></div></section>"
    )


def _overview(result: TargetResult, t: Translator) -> str:
    banner = result.banner
    entries = []
    if banner is not None:
        software = banner.software or t("rep.html.software_unknown")
        if banner.comments:
            software += f" ({banner.comments})"
        entries.append((t("rep.field.software"), _e(software)))
        entries.append(
            (t("rep.html.identification"), f'<span class="mono">{_e(banner.raw)}</span>')
        )
    if result.resolved_address:
        entries.append((
            t("rep.html.address"),
            f'<span class="mono">{_e(result.resolved_address)}:'
            f'{_e(result.target.port)}</span>',
        ))
    strength = result.security_strength
    if strength is not None and strength.effective_bits is not None:
        entries.append(
            (
                t("rep.html.security_strength"),
                f"{_badge(strength.level_label, _STRENGTH_CLASSES.get(strength.level_id, 'info'))} "
                f"{_e(t('rep.html.n_bit', bits=strength.effective_bits))}",
            )
        )
    entries.append(
        (
            t("rep.field.post_quantum"),
            _e(post_quantum_label(t, result.post_quantum)),
        )
    )
    # Una propiedad de la negociacion, como la preparacion post-cuantica de
    # la fila de arriba: si esta o no esta. Lo que se sigue de que falte -- una
    # CVE concreta, con su severidad y su remedio -- va en los hallazgos, con
    # las demas y sin trato aparte.
    entries.append(
        (
            t("rep.field.strict_kex"),
            _e(t("rep.cell.yes") if result.strict_kex else t("rep.cell.no")),
        )
    )

    compression = _e(compression_label(t, result.compression))
    if result.compression is CompressionStatus.PRE_AUTH:
        compression = (
            f'<span class="error">{compression}</span> &mdash; '
            f"{_e(t('rep.html.compression_preauth_note'))}"
        )
    entries.append((t("rep.field.compression"), compression))
    entries.append((t("rep.html.scanned_at"), _e(result.scanned_at)))
    entries.append((t("rep.html.duration"), f"{result.duration_ms} ms"))

    items = "".join(f"<dt>{_e(label)}</dt><dd>{value}</dd>" for label, value in entries)
    return f'<dl class="kv">{items}</dl>'


def _algorithm_table(assessment: ClassAssessment, policy: Policy, t: Translator) -> str:
    if not assessment.algorithms:
        return (
            f"<h3>{_e(assessment.label)}</h3>"
            f'<p class="note">{_e(t("rep.html.nothing_offered"))}</p>'
        )

    rows = []
    for algorithm in assessment.algorithms:
        tags = ", ".join(algorithm.tags)
        if algorithm.directions and len(algorithm.directions) == 1:
            tags = f"{tags}, {algorithm.directions[0]}" if tags else algorithm.directions[0]
        rows.append(
            "<tr>"
            f"<td>{_badge(policy.category_short(algorithm.category), algorithm.category.value)}"
            "</td>"
            f'<td class="mono">{_e(algorithm.name)}</td>'
            f'<td class="tags">{_e(tags)}</td>'
            f'<td class="note">{_e(algorithm.notes)}</td>'
            "</tr>"
        )

    title = _e(assessment.label)
    if assessment.score is not None:
        title += f' <span class="note">({assessment.score}/100)</span>'
    if assessment.directions_differ:
        title += f' <span class="note">&mdash; {_e(t("rep.html.directions_differ"))}</span>'
    return (
        f"<h3>{title}</h3>"
        '<div class="table-scroll"><table><thead><tr>'
        f"<th>{_e(t('rep.html.col_rating'))}</th><th>{_e(t('rep.html.col_algorithm'))}</th>"
        f"<th>{_e(t('rep.html.col_properties'))}</th><th>{_e(t('rep.html.col_notes'))}</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _host_key_table(result: TargetResult, t: Translator) -> str:
    if not result.host_keys:
        return ""
    rows = []
    for key in result.host_keys:
        if key.error and not key.key_type:
            # Nothing was read but the name it was asked for, so there are no
            # columns to fill.
            rows.append(
                f'<tr><td class="mono">{_e(key.algorithm)}</td>'
                f'<td colspan="3" class="note">{_e(key.error)}</td></tr>'
            )
            continue
        extra = ""
        if key.error:
            # Read part way: the fields it gave up are worth as much as they
            # would be from a key that parsed, and the fingerprint is the one
            # somebody can compare against a record they hold.
            extra = f'<div class="note">{_e(key.error)}</div>'
        certificate = key.certificate
        if certificate is not None:
            details = []
            if certificate.key_id:
                details.append(t("rep.html.cert_id", id=certificate.key_id))
            if certificate.cert_type:
                details.append(t("rep.html.cert_type", type=certificate.cert_type))
            if certificate.principals:
                details.append(
                    t("rep.html.cert_principals", items=", ".join(certificate.principals))
                )
            if certificate.ca_fingerprint:
                details.append(
                    t("rep.html.cert_ca", type=certificate.ca_key_type,
                      fp=certificate.ca_fingerprint)
                    if certificate.ca_key_type
                    else t("rep.html.cert_ca_unreadable", fp=certificate.ca_fingerprint)
                )
            extra += f'<div class="note">{_e("; ".join(details))}</div>'
        rows.append(
            "<tr>"
            f'<td class="mono">{_e(key.algorithm)}</td>'
            f"<td>{_e(key.key_type)}</td>"
            f"<td>{_e(key.bits) if key.bits else '-'}</td>"
            f'<td class="mono">{_e(key.fingerprint_sha256)}{extra}</td>'
            "</tr>"
        )
    return (
        f"<h3>{_e(t('rep.sec.host_keys'))}</h3>"
        '<div class="table-scroll"><table><thead><tr>'
        f"<th>{_e(t('rep.html.col_algorithm'))}</th><th>{_e(t('rep.html.col_type'))}</th>"
        f"<th>{_e(t('rep.html.col_bits'))}</th><th>{_e(t('rep.html.col_fingerprint'))}</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _compliance_block(result: TargetResult, t: Translator) -> str:
    """Per-standard conformance, independent of this tool's own grade."""
    if not result.compliance:
        return ""

    intro = ""
    strength = result.security_strength
    if strength is not None and strength.effective_bits is not None:
        limiting = ""
        if strength.limiting:
            limiting = " " + _e(
                t("rep.html.held_down_by", items=", ".join(strength.limiting[:3]))
            )
        intro = (
            '<p class="note"><strong>'
            f"{_e(t('rep.html.effective_strength_bits', bits=strength.effective_bits))}</strong> "
            f"({_e(strength.level_label)}). {_e(strength.level_description)}"
            f"{limiting} {_e(t('rep.html.source', ref=strength.reference))}.</p>"
        )

    rows = []
    for entry in result.compliance:
        passed = entry.status is ComplianceStatus.PASS
        if passed:
            badge = _badge(t("rep.html.badge_pass"), "recommended")
        elif entry.status is ComplianceStatus.NOT_ASSESSED:
            badge = _badge(t("rep.html.badge_not_assessed"), "weak")
        else:
            badge = _badge(t("rep.html.badge_fail"), "insecure")
        detail = f'<div class="note">{_e(entry.summary)}</div>'
        if entry.status is ComplianceStatus.NOT_ASSESSED:
            detail += "".join(
                f'<p class="note">{_e(t("rep.html.not_assessed_reason", reason=reason))}</p>'
                for reason in entry.unverified
            )
        if not passed:
            items = "".join(
                f"<li>{_e(violation.subject)}</li>" for violation in entry.violations[:10]
            )
            if len(entry.violations) > 10:
                items += f"<li>{_e(t('rep.html.and_more', n=len(entry.violations) - 10))}</li>"
            reasons = []
            for violation in entry.violations:
                text = (
                    t(violation.reason_key, **violation.reason_args)
                    if violation.reason_key else violation.reason
                )
                if text and text not in reasons:
                    reasons.append(text)
            detail += f"<ul>{items}</ul>"
            detail += "".join(f'<p class="note">{_e(reason)}</p>' for reason in reasons[:3])
        elif entry.caveats:
            detail += "".join(
                f'<p class="note">{_e(t("rep.html.conditional_on", caveat=caveat))}</p>'
                for caveat in entry.caveats[:2]
            )
        name = _e(entry.name)
        if entry.url:
            name = f'<a href="{_e(entry.url)}" rel="noreferrer">{name}</a>'
        rows.append(
            "<tr>"
            f"<td>{badge}</td>"
            f"<td><strong>{name}</strong>"
            f'<div class="note">{_e(entry.authority)}'
            + (f" &middot; {_e(entry.edition)}" if entry.edition else "")
            + "</div></td>"
            f"<td>{detail}</td>"
            "</tr>"
        )

    return (
        f"<h3>{_e(t('rep.sec.conformance'))}</h3>"
        + intro
        + '<div class="table-scroll"><table><thead><tr>'
        f"<th>{_e(t('rep.html.col_result'))}</th><th>{_e(t('rep.html.col_standard'))}</th>"
        f"<th>{_e(t('rep.html.col_detail'))}</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _vulnerabilities_block(result: TargetResult, t: Translator) -> str:
    """Known vulnerabilities, kept apart from the configuration findings.

    They answer a different question: a finding says the configuration is not
    what this policy wants, a vulnerability says somebody published an attack
    against the software, with an identifier the reader can look up.
    """
    matched = [v for v in result.vulnerabilities if not v.undetermined]
    unknown = [v for v in result.vulnerabilities if v.undetermined]

    blocks = []
    for match in sorted(matched, key=lambda m: SEVERITY_ORDER.index(m.severity)):
        evidence = ""
        if match.evidence:
            evidence = "<ul>" + "".join(f"<li>{_e(item)}</li>" for item in match.evidence) + "</ul>"
        client = (
            f'<p class="note">{_e(t("rep.html.affects_client"))}</p>'
            if match.affects == "client"
            else ""
        )
        caveat = (
            f'<p class="note">{_e(t("rep.html.version_based"))}</p>'
            if match.version_based
            else ""
        )
        fix = (
            f'<p class="fix"><strong>{_e(t("rep.html.fix_label"))}</strong> '
            f"{_e(match.remediation)}</p>"
            if match.remediation
            else ""
        )
        references = (
            f'<p class="note">{_e(t("rep.html.see_label"))} {_e(", ".join(match.references))}</p>'
            if match.references
            else ""
        )
        blocks.append(
            f'<div class="finding {_e(match.severity.value)}">'
            f'<h4><span class="badge {_e(match.severity.value)}">'
            f"{_e(severity_label(t, match.severity))}</span> "
            f"{_e(match.id)}: {_e(match.name)}</h4>"
            f"<p>{_e(match.description)}</p>{client}{evidence}{caveat}{fix}{references}"
            "</div>"
        )

    if not matched:
        blocks.append(f'<p class="note">{_e(t("rep.html.none_matched"))}</p>')

    if unknown:
        needed = sorted({item for match in unknown for item in match.needs})
        names = ", ".join(f"{match.id} ({match.name})" for match in unknown)
        blocks.append(
            '<div class="finding info"><h4><span class="badge info">'
            f'{_e(t("rep.html.badge_not_determined"))}</span> '
            f"{_e(t('rep.html.checks_incomplete', n=len(unknown)))}</h4>"
            f'<p>{_e(t("rep.html.not_determined_detail"))}</p>'
            f"<p>{_e(names)}</p>"
            f'<p class="fix"><strong>{_e(t("rep.html.rerun_with_label"))}</strong> '
            f'{_e(", ".join(needed))}</p></div>'
        )
    return f"<h3>{_e(t('rep.sec.vulnerabilities'))}</h3>" + "".join(blocks)


def _findings_block(findings: Sequence[Finding], t: Translator) -> str:
    if not findings:
        return (
            f"<h3>{_e(t('rep.sec.findings'))}</h3>"
            f'<p class="note">{_e(t("rep.html.no_issue"))}</p>'
        )
    blocks = []
    for finding in findings:
        severity = finding.severity.value
        items = ""
        if finding.items:
            items = "<ul>" + "".join(f"<li>{_e(item)}</li>" for item in finding.items) + "</ul>"
        fix = (
            f'<p class="fix"><strong>{_e(t("rep.html.fix_label"))}</strong> '
            f"{_e(finding.remediation)}</p>"
            if finding.remediation
            else ""
        )
        references = (
            f'<p class="note">{_e(t("rep.html.see_label"))} {_e(", ".join(finding.references))}</p>'
            if finding.references
            else ""
        )
        blocks.append(
            f'<div class="finding {_e(severity)}">'
            f'{_badge(severity_label(t, finding.severity), severity)}'
            f'<span class="title">{_e(finding.title)}</span>'
            f"<p>{_e(finding.description)}</p>{items}{fix}{references}</div>"
        )
    return f"<h3>{_e(t('rep.sec.findings'))}</h3>" + "".join(blocks)


def _config_block(result: TargetResult, t: Translator) -> str:
    if not result.recommendations:
        return ""
    lines = []
    for recommendation in result.recommendations:
        # Every recommendation carries its reason; the type says so.
        lines.append(f'<span class="comment"># {_e(recommendation.comment)}</span>')
        lines.append(_e(recommendation.as_config_line()))
    return (
        f"<h3>{_e(t('rep.sec.recommendations'))}</h3>"
        f'<p class="note">{_e(t("rep.html.config_intro"))}</p>'
        f'<pre class="config">{chr(10).join(lines)}</pre>'
    )


def _target_section(result: TargetResult, policy: Policy, t: Translator) -> str:
    anchor = _slug(str(result.target))
    grade = result.grade or "-"
    verdict = verdict_label(t, result.verdict)
    verdict_class = _VERDICT_CLASSES[result.verdict]

    subtitle = str(result.target) if result.target.label else ""
    critical = sum(
        1 for f in result.findings if f.severity in {Severity.CRITICAL, Severity.HIGH}
    )
    finding_note = t("rep.html.finding_note", n=critical) if critical else ""

    summary = (
        "<summary>"
        f'<span class="grade {_grade_class(result.grade)}">{_e(grade)}</span>'
        "<span>"
        f'<span class="name">{_e(result.target.display_name)}</span><br>'
        f'<span class="sub">{_e(subtitle)}</span>'
        "</span>"
        '<span class="spacer"></span>'
        f"{_badge(verdict, verdict_class)}"
        f'<span class="sub">{_e(finding_note)}</span>'
        "</summary>"
    )

    if not result.ok:
        body = (
            '<div class="body"><p class="error">'
            f'{_e(t("rep.html.scan_failed", error=result.error or t("rep.html.unknown_error")))}'
            "</p></div>"
        )
        return f'<details class="target" id="{_e(anchor)}">{summary}{body}</details>'

    parts = [_overview(result, t)]
    parts.append(_compliance_block(result, t))
    parts.extend(_algorithm_table(assessment, policy, t) for assessment in result.assessments)
    parts.append(_host_key_table(result, t))
    parts.append(_vulnerabilities_block(result, t))
    # The vulnerabilities have their own block above.
    parts.append(
        _findings_block([f for f in result.findings if not f.id.startswith("vuln-")], t)
    )
    parts.append(_config_block(result, t))
    body = f'<div class="body">{"".join(part for part in parts if part)}</div>'
    return f'<details class="target" id="{_e(anchor)}" open>{summary}{body}</details>'


def _legend(policy: Policy, t: Translator) -> str:
    rows = [
        f"<tr><td>{_badge(info.short, category.value)}</td><td>{_e(info.label)}</td>"
        f'<td class="note">{_e(info.description)}</td></tr>'
        for category, info in policy.categories.items()
    ]
    source_span = f'<span class="mono">{_e(policy.source)}</span>'
    doc_span = '<span class="mono">docs/auditoria-integridad.md</span>'
    return (
        f'<section class="card"><h2>{_e(t("rep.html.legend_heading"))}</h2>'
        '<div class="table-scroll"><table><tbody>' + "".join(rows) + "</tbody></table></div>"
        f'<p class="note">{t("rep.html.rating_source_html", source=source_span, doc=doc_span)}</p>'
        f'<p class="note">{t("rep.html.scoring")}</p>'
        f'<p class="note">{t("rep.html.unknown_algorithms_html", source=source_span)}</p>'
        "</section>"
    )


def render(report: ScanReport, policy: Policy, options: RenderOptions) -> str:
    """Render the report as a single self-contained HTML document."""
    t = options.translator
    targets = "".join(_target_section(result, policy, t) for result in report.results)
    controls = (
        f'<p class="note"><a href="#" data-action="expand">{_e(t("rep.html.expand_all"))}</a> '
        f'&middot; <a href="#" data-action="collapse">{_e(t("rep.html.collapse_all"))}</a></p>'
        if len(report.results) > 1
        else ""
    )
    return (
        "<!DOCTYPE html>\n"
        f'<html lang="{_e(t.language)}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{t('rep.html.doc_title', tool=_e(report.tool), count=_e(report.summary.total))}"
        "</title>"
        f"<style>{_STYLE}</style></head><body>"
        + _header(report, t)
        + '<div class="wrap">'
        + _summary_section(report, t)
        + f'<section><h2>{_e(t("rep.html.details_heading"))}</h2>{controls}{targets}</section>'
        + _legend(policy, t)
        + "<footer>"
        + f"{_e(t('rep.html.footer_generated_by', tool=report.tool, version=report.version))} "
        + f"{_e(t('rep.html.footer_command'))} "
        + f"<span class=\"mono\">{_e(report.command_line or '-')}</span>. "
        + _e(t("rep.html.footer_reflects"))
        + "</footer></div>"
        + f"<script>{_SCRIPT}</script>"
        + "</body></html>\n"
    )
