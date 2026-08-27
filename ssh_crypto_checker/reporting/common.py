"""Helpers shared by the report renderers."""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import IO, ClassVar, Dict, List, Optional

from ..i18n import DEFAULT_LANGUAGE, Translator
from ..messages import MESSAGES
from ..models import (
    Category,
    CompressionStatus,
    HostKeyInfo,
    PostQuantumStatus,
    Severity,
    TargetResult,
    Verdict,
)


def _default_translator() -> Translator:
    """English by default, so a plain ``RenderOptions()`` needs no language."""
    return Translator(DEFAULT_LANGUAGE, MESSAGES)

__all__ = [
    "COMPRESSION_LABELS",
    "POST_QUANTUM_LABELS",
    "SEVERITY_LABELS",
    "VERDICT_LABELS",
    "Ansi",
    "RenderOptions",
    "category_color",
    "compression_label",
    "describe_host_key",
    "grade_color",
    "post_quantum_label",
    "severity_color",
    "severity_label",
    "summary_headers",
    "supports_color",
    "supports_unicode",
    "verdict_color",
    "verdict_label",
    "wrap",
]


@dataclass
class RenderOptions:
    """Presentation choices that apply to every format."""

    color: bool = False
    unicode: bool = True
    width: int = 100
    summary_only: bool = False
    include_config_snippet: bool = True
    show_algorithm_notes: bool = False
    #: The language every renderer speaks. Defaults to English; the CLI builds
    #: it from --lang (or the locale) so the whole report follows one language.
    translator: Translator = field(default_factory=_default_translator)

    @classmethod
    def for_stream(
        cls,
        stream: Optional[IO[str]] = None,
        color_mode: str = "auto",
        **kwargs: object,
    ) -> RenderOptions:
        """Build options adapted to a terminal (or to a file being redirected)."""
        stream = stream or sys.stdout
        width = shutil.get_terminal_size(fallback=(100, 24)).columns
        return cls(
            color=supports_color(stream, color_mode),
            unicode=supports_unicode(stream),
            width=max(60, min(width, 140)),
            **kwargs,  # type: ignore[arg-type]
        )


# --------------------------------------------------------------------------- #
# Terminal capabilities
# --------------------------------------------------------------------------- #


def supports_color(stream: IO[str], mode: str = "auto") -> bool:
    """Whether ANSI colour should be emitted on ``stream``.

    Honours the ``NO_COLOR`` and ``FORCE_COLOR`` conventions.
    """
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM", "") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        # A closed or substituted stream: no terminal, so no colour.
        return False


def supports_unicode(stream: IO[str]) -> bool:
    encoding = getattr(stream, "encoding", None) or ""
    return "utf" in encoding.lower()


class Ansi:
    """Minimal ANSI styling that collapses to a no-op when colour is off."""

    RESET = "\033[0m"
    _CODES: ClassVar[Dict[str, str]] = {
        "bold": "1",
        "dim": "2",
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "white": "37",
        "bright_red": "91",
        "bright_green": "92",
        "bright_yellow": "93",
        "bright_blue": "94",
        "bright_magenta": "95",
        "bright_cyan": "96",
        "on_red": "41",
        "on_green": "42",
        "on_yellow": "43",
        "on_blue": "44",
        "on_magenta": "45",
    }

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        """Style ``text``, or return it unchanged when colour is off.

        A style name that is not one of these is a typo, and it is raised
        rather than ignored. Dropping it silently means a finding renders
        without the colour that says how bad it is -- and the one place that
        matters most is a critical finding on a terminal somebody is skimming.
        """
        if not self.enabled or not styles:
            return text
        unknown = [style for style in styles if style not in self._CODES]
        if unknown:
            raise KeyError(
                f"unknown ANSI style {', '.join(sorted(unknown))}; valid names are "
                + ", ".join(sorted(self._CODES))
            )
        return f"\033[{';'.join(self._CODES[style] for style in styles)}m{text}{self.RESET}"


# --------------------------------------------------------------------------- #
# Colour maps
# --------------------------------------------------------------------------- #

_CATEGORY_STYLES: Dict[Category, Sequence[str]] = {
    Category.RECOMMENDED: ("green",),
    Category.ACCEPTABLE: ("cyan",),
    Category.WEAK: ("yellow",),
    Category.INSECURE: ("bright_red", "bold"),
    Category.INFORMATIONAL: ("dim",),
    Category.UNKNOWN: ("magenta",),
}

_SEVERITY_STYLES: Dict[Severity, Sequence[str]] = {
    Severity.CRITICAL: ("bright_red", "bold"),
    Severity.HIGH: ("red", "bold"),
    Severity.MEDIUM: ("yellow",),
    Severity.LOW: ("cyan",),
    Severity.INFO: ("dim",),
}

_VERDICT_STYLES: Dict[Verdict, Sequence[str]] = {
    Verdict.SECURE: ("green", "bold"),
    Verdict.ACCEPTABLE: ("cyan", "bold"),
    Verdict.WEAK: ("yellow", "bold"),
    Verdict.INSECURE: ("bright_red", "bold"),
    Verdict.UNKNOWN: ("magenta", "bold"),
    Verdict.ERROR: ("magenta", "bold"),
}

_GRADE_STYLES: Dict[str, Sequence[str]] = {
    "A+": ("bright_green", "bold"),
    "A": ("green", "bold"),
    "B": ("cyan", "bold"),
    "C": ("yellow", "bold"),
    "D": ("bright_yellow", "bold"),
    "F": ("bright_red", "bold"),
}

SEVERITY_LABELS: Dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

VERDICT_LABELS: Dict[Verdict, str] = {
    Verdict.SECURE: "SECURE",
    Verdict.ACCEPTABLE: "ACCEPTABLE",
    Verdict.WEAK: "WEAK",
    Verdict.INSECURE: "INSECURE",
    Verdict.UNKNOWN: "UNJUDGED",
    Verdict.ERROR: "UNREACHABLE",
}

POST_QUANTUM_LABELS: Dict[PostQuantumStatus, str] = {
    PostQuantumStatus.ENFORCED: "ENFORCED (only post-quantum methods offered)",
    PostQuantumStatus.READY: "READY (hybrid method available)",
    PostQuantumStatus.NOT_READY: "NOT READY (no post-quantum method offered)",
    PostQuantumStatus.UNKNOWN: "UNKNOWN",
}


#: Enum -> catalog key, for the human formats. Machine formats keep the English
#: enum value and never look these up.
_VERDICT_KEYS: Dict[Verdict, str] = {
    Verdict.SECURE: "rep.verdict.secure",
    Verdict.ACCEPTABLE: "rep.verdict.acceptable",
    Verdict.WEAK: "rep.verdict.weak",
    Verdict.INSECURE: "rep.verdict.insecure",
    Verdict.UNKNOWN: "rep.verdict.unjudged",
    Verdict.ERROR: "rep.verdict.unreachable",
}
_SEVERITY_KEYS: Dict[Severity, str] = {
    Severity.CRITICAL: "rep.severity.critical",
    Severity.HIGH: "rep.severity.high",
    Severity.MEDIUM: "rep.severity.medium",
    Severity.LOW: "rep.severity.low",
    Severity.INFO: "rep.severity.info",
}
_POST_QUANTUM_KEYS: Dict[PostQuantumStatus, str] = {
    PostQuantumStatus.ENFORCED: "rep.pq.enforced",
    PostQuantumStatus.READY: "rep.pq.ready",
    PostQuantumStatus.NOT_READY: "rep.pq.not_ready",
    PostQuantumStatus.UNKNOWN: "rep.pq.unknown",
}
_COMPRESSION_KEYS: Dict[CompressionStatus, str] = {
    CompressionStatus.DISABLED: "rep.compression.disabled",
    CompressionStatus.POST_AUTH: "rep.compression.post_auth",
    CompressionStatus.PRE_AUTH: "rep.compression.pre_auth",
    CompressionStatus.UNKNOWN: "rep.compression.unknown",
}


def verdict_label(t: Translator, verdict: Verdict) -> str:
    return t(_VERDICT_KEYS.get(verdict, "rep.verdict.unjudged"))


def severity_label(t: Translator, severity: Severity) -> str:
    return t(_SEVERITY_KEYS[severity])


def post_quantum_label(t: Translator, status: PostQuantumStatus) -> str:
    return t(_POST_QUANTUM_KEYS[status])


def compression_label(t: Translator, state: CompressionStatus) -> str:
    return t(_COMPRESSION_KEYS[state])


def category_color(ansi: Ansi, category: Category, text: str) -> str:
    return ansi(text, *_CATEGORY_STYLES.get(category, ()))


def severity_color(ansi: Ansi, severity: Severity, text: str) -> str:
    return ansi(text, *_SEVERITY_STYLES.get(severity, ()))


def verdict_color(ansi: Ansi, verdict: Verdict, text: str) -> str:
    return ansi(text, *_VERDICT_STYLES.get(verdict, ()))


def grade_color(ansi: Ansi, grade: Optional[str], text: str) -> str:
    return ansi(text, *_GRADE_STYLES.get(grade or "", ()))


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #


def wrap(text: str, width: int, indent: str = "") -> List[str]:
    """Wrap ``text`` to ``width``, prefixing every line with ``indent``."""
    if not text:
        return []
    return textwrap.wrap(
        text,
        width=max(20, width - len(indent)),
        initial_indent=indent,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


def wrap_comment(text: str, width: int, indent: str = "") -> List[str]:
    """Wrap ``text`` as a configuration file comment.

    Every produced line starts with ``#`` so the block stays valid when it is
    copied straight into ``sshd_config``.
    """
    if not text:
        return []
    return textwrap.wrap(
        text,
        width=max(24, width - len(indent)),
        initial_indent=indent + "# ",
        subsequent_indent=indent + "# ",
        break_long_words=False,
        break_on_hyphens=False,
    )


def describe_host_key(key: HostKeyInfo) -> str:
    """One-line description of a host key, without colour.

    A key that failed to parse is described by whatever was read before it
    failed, and then by the reason. The two are not exclusive: a certificate
    can give up its type and its fingerprint and still be truncated further
    in, and throwing away the fingerprint because the tail was unreadable
    discards the one field somebody can compare against a record they hold.
    """
    if key.error and not key.key_type:
        return f"{key.algorithm}: {key.error}"
    parts = [key.algorithm or key.key_type]
    if key.key_type and key.key_type != key.algorithm:
        parts.append(f"({key.key_type})")
    if key.bits:
        parts.append(f"{key.bits} bits")
    if key.is_certificate and key.certificate is not None:
        certificate = key.certificate
        if certificate.key_id:
            parts.append(f"id={certificate.key_id}")
        if certificate.cert_type:
            parts.append(f"type={certificate.cert_type}")
    parts.append(key.fingerprint_sha256)
    described = "  ".join(part for part in parts if part)
    return f"{described}: {key.error}" if key.error else described


def summary_rows(
    results: Sequence[TargetResult], t: Optional[Translator] = None
) -> List[List[str]]:
    """Rows of the multi-target summary table.

    ``t`` translates the verdict and post-quantum cells for a human format;
    left out, the English labels are used (which is also what a machine format
    would want, though none currently calls this).
    """
    translate = t or _default_translator()
    pq_cell = {
        PostQuantumStatus.ENFORCED: translate("rep.pqcell.enforced"),
        PostQuantumStatus.READY: translate("rep.pqcell.ready"),
        PostQuantumStatus.NOT_READY: translate("rep.pqcell.no"),
        PostQuantumStatus.UNKNOWN: "-",
    }
    rows = []
    for result in results:
        rows.append(
            [
                result.target.display_name,
                result.grade or "-",
                str(result.score) if result.score is not None else "-",
                (
                    f"{result.security_strength.effective_bits}-bit"
                    if result.security_strength is not None
                    and result.security_strength.effective_bits is not None
                    else "-"
                ),
                verdict_label(translate, result.verdict),
                pq_cell[result.post_quantum],
                translate("rep.cell.yes") if result.strict_kex
                else ("-" if not result.ok else translate("rep.cell.no")),
                result.banner.software if result.banner else (result.error or ""),
            ]
        )
    return rows


#: English headers, kept for the renderers not yet translated. New code should
#: call ``summary_headers(t)``.
SUMMARY_HEADERS = [
    "Target", "Grade", "Score", "Strength", "Verdict", "PQ", "StrictKEX", "Software"
]

_SUMMARY_HEADER_KEYS = [
    "rep.sumhdr.target", "rep.sumhdr.grade", "rep.sumhdr.score", "rep.sumhdr.strength",
    "rep.sumhdr.verdict", "rep.sumhdr.pq", "rep.sumhdr.strict_kex", "rep.sumhdr.software",
]


def summary_headers(t: Optional[Translator] = None) -> List[str]:
    """The summary-table headers in the translator's language (English if None)."""
    translate = t or _default_translator()
    return [translate(key) for key in _SUMMARY_HEADER_KEYS]


def format_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    width: int,
    ansi: Optional[Ansi] = None,
    unicode_borders: bool = True,
) -> List[str]:
    """Render a simple aligned table, truncating the last column if needed."""
    if not rows:
        return []
    columns = len(headers)
    widths = [len(header) for header in headers]
    for row in rows:
        for index in range(columns):
            widths[index] = max(widths[index], len(str(row[index])))

    overflow = sum(widths) + 2 * (columns - 1) - width
    if overflow > 0:
        widths[-1] = max(10, widths[-1] - overflow)

    separator = "─" if unicode_borders else "-"
    styler = ansi or Ansi(False)

    def format_row(cells: Sequence[str]) -> str:
        parts = []
        for index, cell in enumerate(cells):
            text = str(cell)
            if len(text) > widths[index]:
                text = text[: widths[index] - 1] + "…" if unicode_borders else text[: widths[index]]
            parts.append(text.ljust(widths[index]))
        return "  ".join(parts).rstrip()

    lines = [styler(format_row(headers), "bold")]
    lines.append(separator * min(width, sum(widths) + 2 * (columns - 1)))
    lines.extend(format_row(row) for row in rows)
    return lines


#: How each compression state reads in a report. The wording says *when*
#: rather than whether, because that is the part that decides whether it is a
#: problem.
COMPRESSION_LABELS: Dict[CompressionStatus, str] = {
    CompressionStatus.DISABLED: "disabled (no compression offered)",
    CompressionStatus.POST_AUTH: "enabled, after authentication only",
    CompressionStatus.PRE_AUTH: "enabled BEFORE authentication",
    CompressionStatus.UNKNOWN: "unknown",
}
