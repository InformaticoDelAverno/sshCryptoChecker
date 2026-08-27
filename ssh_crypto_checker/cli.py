"""Command line interface.

Exit codes:

===  ==========================================================================
0    every target was scanned and nothing crossed the ``--fail-on`` threshold
1    a finding at or above the ``--fail-on`` severity was reported
2    the command line was invalid, or a policy file could not be loaded
3    at least one target could not be scanned (and nothing crossed the threshold)
===  ==========================================================================
"""

from __future__ import annotations

import argparse
import shutil
import socket
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import IO, Any, Callable, Dict, List, Optional, Tuple

from . import PRODUCT_NAME, __version__
from .compare import BaselineError, load_baseline
from .compare import compare as compare_reports
from .compare import summarise as summarise_comparison
from .history import HistoryError
from .history import append as append_history
from .history import summarise as summarise_history
from .i18n import DEFAULT_LANGUAGE, LANGUAGES, Translator, resolve_language
from .messages import MESSAGES
from .models import SEVERITY_ORDER, AuthMode, Credentials, ScanReport, Severity
from .plugins import load_plugins
from .policy import (
    ENV_VAR,
    PROFILE_DIRECTORY,
    Policy,
    PolicyError,
    candidate_policy_paths,
    default_policy_path,
    load_policy,
    profile_directory_for,
)
from .reporting import EXTENSIONS, FORMATS, RenderOptions, render
from .reporting.json_report import build_document as build_json_document
from .scanner import ScanOptions, scan
from .targets import DEFAULT_PORT, TargetError, build_targets

__all__ = ["build_parser", "main"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_SCAN_ERROR = 3

#: Help-ish arguments that argparse would otherwise REJECT: '--h' is ambiguous
#: (matches --help, --history, --history-report), and '-help' / '-?' are not
#: options at all. Intercepted before argparse -- wherever they appear in the
#: line, because '-h' works anywhere and '--h --lang es' asking for Spanish
#: help used to die with 'ambiguous option' instead. '-h', '--help' and the
#: unambiguous '--he'/'--hel' are left to argparse, which already handles them.
_HELP_REQUESTS = frozenset({"--h", "-help", "-?"})

class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keeps the description and the examples verbatim, and widens the help column."""

    def __init__(self, prog: str) -> None:
        width = shutil.get_terminal_size(fallback=(100, 24)).columns
        super().__init__(prog, max_help_position=30, width=max(80, min(width, 110)))


def build_parser(t: Optional[Translator] = None) -> argparse.ArgumentParser:
    """Build the argument parser, with help text in the translator's language.

    ``t`` defaults to English, which is what the documentation tests and any
    other caller that does not care about language get. ``main`` passes a
    translator resolved from ``--lang`` (or the locale) so ``--help`` comes out
    in the chosen language.
    """
    if t is None:
        t = Translator(DEFAULT_LANGUAGE, MESSAGES)

    parser = argparse.ArgumentParser(
        prog="ssh-crypto-checker",
        description=t("cli.desc"),
        epilog=t("cli.epilog"),
        formatter_class=_HelpFormatter,
    )

    parser.add_argument(
        "targets",
        nargs="*",
        metavar=t("cli.mv.target"),
        help=t("cli.h.targets"),
    )

    parser.add_argument(
        "-w",
        "--wizard",
        action="store_true",
        help=t("cli.h.wizard"),
    )

    parser.add_argument(
        "--lang",
        choices=list(LANGUAGES),
        help=t("cli.h.lang"),
    )

    source = parser.add_argument_group(t("cli.grp.sources"))
    source.add_argument(
        "-f",
        "--file",
        dest="files",
        action="append",
        default=[],
        metavar=t("cli.mv.file"),
        type=Path,
        help=t("cli.h.file"),
    )
    source.add_argument(
        "--user",
        metavar=t("cli.mv.name"),
        help=t("cli.h.user"),
    )
    source.add_argument(
        "--auth",
        choices=[mode.value for mode in AuthMode],
        default=AuthMode.ANY.value,
        help=t("cli.h.auth"),
    )
    source.add_argument(
        "-i",
        "--identity",
        metavar=t("cli.mv.file"),
        help=t("cli.h.identity"),
    )
    source.add_argument(
        "--password-file",
        metavar=t("cli.mv.file"),
        help=t("cli.h.password_file"),
    )
    source.add_argument(
        "--password-env",
        metavar=t("cli.mv.var"),
        help=t("cli.h.password_env"),
    )
    source.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        metavar=t("cli.mv.port"),
        help=t("cli.h.port"),
    )

    scan_group = parser.add_argument_group(t("cli.grp.scanning"))
    scan_group.add_argument(
        "-t", "--timeout", type=float, default=5.0, metavar=t("cli.mv.seconds"),
        help=t("cli.h.timeout"),
    )
    scan_group.add_argument(
        "-c", "--concurrency", type=int, default=8, metavar=t("cli.mv.n"),
        help=t("cli.h.concurrency"),
    )
    scan_group.add_argument(
        "-r", "--retries", type=int, default=1, metavar=t("cli.mv.n"),
        help=t("cli.h.retries"),
    )
    scan_group.add_argument(
        "--no-host-keys",
        action="store_true",
        help=t("cli.h.no_host_keys"),
    )
    scan_group.add_argument(
        "--no-cert-probes",
        action="store_true",
        help=t("cli.h.no_cert_probes"),
    )
    family = scan_group.add_mutually_exclusive_group()
    family.add_argument(
        "-4", "--ipv4", action="store_true", help=t("cli.h.ipv4")
    )
    family.add_argument(
        "-6", "--ipv6", action="store_true", help=t("cli.h.ipv6")
    )
    scan_group.add_argument(
        "-J",
        "--jump-host",
        metavar=t("cli.mv.jump"),
        help=t("cli.h.jump_host"),
    )
    scan_group.add_argument(
        "--jump-option",
        metavar=t("cli.mv.opt"),
        action="append",
        help=t("cli.h.jump_option"),
    )
    scan_group.add_argument(
        "--source-ip", metavar=t("cli.mv.addr"), help=t("cli.h.source_ip")
    )

    remote = parser.add_argument_group(t("cli.grp.remote"))
    remote.add_argument(
        "--auth-methods",
        action="store_true",
        help=t("cli.h.auth_methods"),
    )
    remote.add_argument(
        "--sshfp",
        action="store_true",
        help=t("cli.h.sshfp"),
    )
    remote.add_argument(
        "--audit-client",
        action="store_true",
        help=t("cli.h.audit_client"),
    )
    remote.add_argument(
        "--client-config",
        metavar=t("cli.mv.file"),
        help=t("cli.h.client_config"),
    )
    remote.add_argument(
        "--dns-server",
        metavar=t("cli.mv.addr"),
        action="append",
        help=t("cli.h.dns_server"),
    )
    remote.add_argument(
        "--login-grace",
        nargs="?",
        type=float,
        const=130.0,
        metavar=t("cli.mv.seconds"),
        help=t("cli.h.login_grace"),
    )
    remote.add_argument(
        "--known-hosts",
        nargs="?",
        const="",
        metavar=t("cli.mv.file"),
        help=t("cli.h.known_hosts"),
    )
    remote.add_argument(
        "--max-startups",
        nargs="?",
        type=int,
        const=20,
        metavar=t("cli.mv.n"),
        help=t("cli.h.max_startups"),
    )
    remote.add_argument(
        "--audit-config",
        action="store_true",
        help=t("cli.h.audit_config"),
    )
    remote.add_argument(
        "--all-checks",
        action="store_true",
        help=t("cli.h.all_checks"),
    )

    policy_group = parser.add_argument_group(t("cli.grp.policy"))
    policy_group.add_argument(
        "--config",
        metavar=t("cli.mv.file"),
        type=Path,
        help=t("cli.h.config", env_var=ENV_VAR),
    )
    policy_group.add_argument(
        "--export-policy",
        metavar=t("cli.mv.file"),
        type=Path,
        help=t("cli.h.export_policy"),
    )
    policy_group.add_argument(
        "--show-policy", action="store_true", help=t("cli.h.show_policy")
    )
    policy_group.add_argument(
        "--plugin-dir",
        metavar=t("cli.mv.dir"),
        action="append",
        type=Path,
        help=t("cli.h.plugin_dir"),
    )
    policy_group.add_argument(
        "--list-plugins",
        action="store_true",
        help=t("cli.h.list_plugins"),
    )
    policy_group.add_argument(
        "--list-vulnerabilities",
        action="store_true",
        help=t("cli.h.list_vulnerabilities"),
    )
    policy_group.add_argument(
        "--list-profiles",
        action="store_true",
        help=t("cli.h.list_profiles"),
    )

    output = parser.add_argument_group(t("cli.grp.output"))
    output.add_argument(
        "--format",
        dest="formats",
        action="append",
        default=[],
        metavar=t("cli.mv.fmt"),
        help=t("cli.h.format"),
    )
    output.add_argument(
        "-o",
        "--output",
        metavar=t("cli.mv.path"),
        help=t("cli.h.output"),
    )
    output.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help=t("cli.h.color"),
    )
    output.add_argument(
        "--no-color", action="store_true", help=t("cli.h.no_color")
    )
    output.add_argument(
        "-s",
        "--summary-only",
        action="store_true",
        help=t("cli.h.summary_only"),
    )
    output.add_argument(
        "--notes",
        action="store_true",
        help=t("cli.h.notes"),
    )
    output.add_argument(
        "--no-config-suggestions",
        action="store_true",
        help=t("cli.h.no_config_suggestions"),
    )
    output.add_argument(
        "-q", "--quiet", action="store_true", help=t("cli.h.quiet")
    )
    output.add_argument(
        "-v", "--verbose", action="store_true", help=t("cli.h.verbose")
    )

    behaviour = parser.add_argument_group(t("cli.grp.behaviour"))
    behaviour.add_argument(
        "--history",
        metavar=t("cli.mv.file"),
        type=Path,
        help=t("cli.h.history"),
    )
    behaviour.add_argument(
        "--history-report",
        action="store_true",
        help=t("cli.h.history_report"),
    )
    behaviour.add_argument(
        "--compare",
        metavar=t("cli.mv.file"),
        type=Path,
        help=t("cli.h.compare"),
    )
    behaviour.add_argument(
        "--fail-on-regression",
        action="store_true",
        help=t("cli.h.fail_on_regression"),
    )
    behaviour.add_argument(
        "--profile",
        dest="profiles",
        action="append",
        default=[],
        metavar=t("cli.mv.id"),
        help=t("cli.h.profile"),
    )
    behaviour.add_argument(
        "--require-profile",
        dest="required_profiles",
        action="append",
        default=[],
        metavar=t("cli.mv.id"),
        help=t("cli.h.require_profile"),
    )
    behaviour.add_argument(
        "--fail-on",
        choices=["never", "critical", "high", "medium", "low", "info"],
        default="never",
        help=t("cli.h.fail_on"),
    )

    parser.add_argument(
        "--version", action="version", version=f"{PRODUCT_NAME} {__version__}"
    )
    return parser


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _normalise_formats(values: Sequence[str]) -> List[str]:
    """Expand comma-separated values and remove duplicates, keeping order."""
    formats: List[str] = []
    for value in values:
        for part in value.split(","):
            name = part.strip().lower()
            if name and name not in formats:
                formats.append(name)
    return formats or ["console"]


def _threshold_exceeded(report: ScanReport, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    limit = SEVERITY_ORDER.index(Severity(fail_on))
    for result in report.results:
        worst = result.worst_severity()
        if worst is not None and SEVERITY_ORDER.index(worst) <= limit:
            return True
    return False


def _render_comparison(comparison: Any, options: RenderOptions) -> str:
    """The difference against the baseline, as a block of text."""
    from .reporting.common import Ansi

    t = options.translator
    ansi = Ansi(options.color)
    rule = ("━" if options.unicode else "=") * options.width
    lines = [rule, ansi(t("cli.cmp.header"), "bold")]
    lines.append(
        ansi(
            f"{comparison.baseline_path}"
            + (
                t("cli.cmp.scanned", when=comparison.baseline_finished_at)
                if comparison.baseline_finished_at
                else ""
            ),
            "dim",
        )
    )
    lines.append("")
    # The colour markers come from the same catalog as the templates, so a
    # translated line is still recognised as bad news or good news.
    bad = (t("cmp.mark_new"), t("cmp.mark_host_key"))
    good = (t("cmp.mark_fixed"), t("cmp.mark_improved"))
    for line in summarise_comparison(comparison, t):
        if any(marker in line for marker in bad):
            lines.append(ansi(line, "bright_red", "bold"))
        elif any(marker in line for marker in good):
            lines.append(ansi(line, "green"))
        else:
            lines.append(line)
    return "\n".join(lines)


def _profile_not_met(report: ScanReport, required: Sequence[str]) -> bool:
    """Whether any scanned target fails a profile the caller demanded."""
    if not required:
        return False
    # Asked of the result rather than compared against a status here: what
    # counts as conforming is decided in one place, and it has changed once
    # already -- a profile whose requirements were never tested is not a
    # profile that passed.
    return any(
        not entry.conforms
        for result in report.results
        for entry in result.compliance
        if entry.profile_id in required
    )


#: English translator for helpers that can be called without one (tests do).
_EN = Translator(DEFAULT_LANGUAGE, MESSAGES)

#: What each condition type reads (as a message key), and the flag that makes
#: it available. A listing that says only "version" or "on the wire" hides the
#: fact that some checks need a flag the caller has to pass.
_DETECTION_SOURCES = [
    ("version", "cli.det.version", ""),
    ("protocol", "cli.det.protocol", ""),
    ("present", "cli.det.algorithms", ""),
    ("absent", "cli.det.algorithms", ""),
    ("host_key", "cli.det.host_key", ""),
    ("auth_method", "cli.det.auth_methods", "--auth-methods"),
    ("extension", "cli.det.extensions", "--auth-methods"),
    ("config", "cli.det.config", "--audit-config"),
]


def _condition_keys(condition: dict, found: Optional[set] = None) -> set:
    """Every condition key in a rule, including the nested ones.

    The rule has been through the policy loader, which refuses anything that is
    not an object where an object belongs -- so there is no need to check the
    shape again here, and checking it left a branch nothing could take.
    """
    found = set() if found is None else found
    for key, value in condition.items():
        found.add(key)
        if key in {"all", "any"}:
            for item in value:
                _condition_keys(item, found)
        elif key == "not":
            _condition_keys(value, found)
    return found


def _describe_detection(detection: Optional[dict], t: Optional[Translator] = None) -> str:
    """Say what a rule reads, and what has to be run for it to be answerable."""
    t = t or _EN
    keys = _condition_keys(detection or {})
    sources, flags = [], []
    for key, source_key, flag in _DETECTION_SOURCES:
        source = t(source_key)
        if key in keys and source not in sources:
            sources.append(source)
            if flag and flag not in flags:
                flags.append(flag)
    if not sources:
        return t("cli.det.always")
    text = ", ".join(sources)
    if flags:
        text += t("cli.det.needs", flags=", ".join(flags))
    return text


def _list_plugins(
    plugins: Sequence[Any], problems: Sequence[str], stdout: IO[str],
    t: Optional[Translator] = None,
) -> int:
    """Show what would run, and what would not."""
    t = t or _EN
    counts: Dict[str, int] = {}
    for plugin in plugins:
        counts[plugin.kind] = counts.get(plugin.kind, 0) + 1
    breakdown = ", ".join(f"{count} {kind}" for kind, count in sorted(counts.items()))
    stdout.write(
        t("cli.pl.loaded", n=len(plugins))
        + (f" ({breakdown})\n\n" if breakdown else "\n\n")
    )
    labels = {key: t(key) for key in (
        "cli.pl.lbl_from", "cli.pl.lbl_needs", "cli.pl.lbl_affects", "cli.pl.lbl_references",
    )}
    width = max(len(label) for label in labels.values())

    def row(key: str, value: str) -> str:
        return f"  {labels[key].ljust(width)} : {value}\n"

    for plugin in plugins:
        stdout.write(f"{plugin.id}  [{plugin.severity.value}]  ({plugin.kind})\n")
        stdout.write(f"  {plugin.name}\n")
        stdout.write(row("cli.pl.lbl_from", str(plugin.source)))
        if plugin.needs:
            stdout.write(row("cli.pl.lbl_needs", ", ".join(plugin.needs)))
        if plugin.affects == "client":
            stdout.write(row("cli.pl.lbl_affects", t("cli.pl.affects_client")))
        if plugin.references:
            stdout.write(row("cli.pl.lbl_references", ", ".join(plugin.references)))
        stdout.write("\n")
    if problems:
        stdout.write(t("cli.pl.not_loaded") + "\n")
        for problem in problems:
            stdout.write(f"  {problem}\n")
    return EXIT_OK


def _list_vulnerabilities(
    policy: Policy, stdout: IO[str], t: Optional[Translator] = None
) -> int:
    t = t or _EN
    stdout.write(t("cli.lv.header", n=len(policy.vulnerabilities), source=policy.source) + "\n\n")
    labels = {key: t(key) for key in (
        "cli.lv.lbl_detected", "cli.pl.lbl_affects", "cli.pl.lbl_references",
    )}
    width = max(len(label) for label in labels.values())

    def row(key: str, value: str) -> str:
        return f"  {labels[key].ljust(width)}: {value}\n"

    for vulnerability in policy.vulnerabilities:
        stdout.write(f"{vulnerability.id}  [{vulnerability.severity.value}]\n")
        stdout.write(f"  {vulnerability.name}\n")
        stdout.write(row("cli.lv.lbl_detected", _describe_detection(vulnerability.detection, t)))
        if vulnerability.affects == "client":
            stdout.write(row("cli.pl.lbl_affects", t("cli.pl.affects_client")))
        if vulnerability.references:
            stdout.write(row("cli.pl.lbl_references", ", ".join(vulnerability.references)))
        stdout.write("\n")
    stdout.write(t("cli.lv.footer"))
    return EXIT_OK


def _list_profiles(policy: Policy, stdout: IO[str], t: Optional[Translator] = None) -> int:
    t = t or _EN
    stdout.write(t(
        "cli.lp.header",
        profiles=len(policy.profiles),
        editions=len(policy.profile_editions),
        source=policy.source,
    ))
    labels = {key: t(key) for key in (
        "cli.lp.lbl_authority", "cli.lp.lbl_kind", "cli.lp.lbl_edition",
        "cli.lp.lbl_reference", "cli.lp.lbl_url", "cli.lp.lbl_editions",
        "cli.lp.lbl_minimum", "cli.lp.lbl_summary",
    )}
    width = max(len(label) for label in labels.values())

    def row(key: str, value: object) -> str:
        return f"  {labels[key].ljust(width)} : {value}\n"

    for profile in policy.profiles.values():
        stdout.write(f"{profile.id}  ·  {profile.name}\n")
        stdout.write(row("cli.lp.lbl_authority", profile.authority))
        stdout.write(row("cli.lp.lbl_kind", profile.kind))
        if profile.edition:
            stdout.write(row("cli.lp.lbl_edition", profile.edition))
        stdout.write(row("cli.lp.lbl_reference", profile.reference))
        if profile.url:
            stdout.write(row("cli.lp.lbl_url", profile.url))
        others = [
            selector
            for selector in sorted(policy.profile_editions)
            if selector.startswith(f"{profile.id}@")
        ]
        if others:
            marked = [
                t("cli.lp.in_force", selector=selector)
                if policy.profile_editions[selector].current
                else selector
                for selector in others
            ]
            stdout.write(row("cli.lp.lbl_editions", ", ".join(marked)))
        if profile.minimum_security_strength is not None:
            stdout.write(row(
                "cli.lp.lbl_minimum",
                t("cli.lp.minimum_value", bits=profile.minimum_security_strength),
            ))
        if profile.summary:
            stdout.write(row("cli.lp.lbl_summary", profile.summary))
        stdout.write("\n")
    stdout.write(t("cli.lp.footer"))
    return EXIT_OK


def _write(content: str, destination: Optional[Path], stdout: IO[str]) -> None:
    if destination is None:
        stdout.write(content)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")


def _profiles_to_export(
    profiles: Path, exported: Path, stderr: IO[str], t: Optional[Translator] = None
) -> Optional[List[Tuple[Path, Path]]]:
    """The editions that still have to be written, or None to refuse.

    A second policy exported into a directory that already holds these same
    profiles is somebody keeping two policies side by side, which is exactly
    how the shipped layout works: one directory of standards, and the policy
    beside it. That is allowed, and nothing is rewritten.

    A file that is there and says something different is somebody's edited
    profile, and the export stops before writing anything rather than replace
    it -- half an export is worse than none.
    """
    t = t or _EN
    planned: List[Tuple[Path, Path]] = []
    for path in sorted(profiles.glob("*/*.json")):
        target = exported / path.parent.name / path.name
        if not target.is_file():
            planned.append((path, target))
            continue
        if target.read_text(encoding="utf-8") != path.read_text(encoding="utf-8"):
            stderr.write(t("cli.exp.exists_diff", target=target))
            return None
    return planned


def _export_policy(destination: Path, stderr: IO[str], t: Optional[Translator] = None) -> int:
    t = t or _EN
    source = default_policy_path()
    if destination.exists():
        stderr.write(t("cli.exp.exists", destination=destination))
        return EXIT_USAGE
    # The conformance profiles live in a directory beside the policy, so a copy
    # of the file alone is a policy with no standards in it -- and a scan
    # against no standards looks exactly like a scan against standards that
    # everything passes. They travel together.
    profiles = profile_directory_for(source)
    exported_profiles = destination.parent / PROFILE_DIRECTORY
    planned: List[Tuple[Path, Path]] = []
    if profiles is not None:
        found = _profiles_to_export(profiles, exported_profiles, stderr, t)
        if found is None:
            return EXIT_USAGE
        planned = found
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        for path, target in planned:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    except OSError as exc:
        # Whichever file it was: the standards are written after the policy, so
        # naming the policy here would send somebody to look at the one file
        # that worked.
        stderr.write(t("cli.exp.write_failed", file=exc.filename or destination, exc=exc))
        return EXIT_USAGE
    stderr.write(t("cli.exp.wrote", destination=destination))
    if profiles is not None:
        count = len(list(exported_profiles.glob("*/*.json")))
        stderr.write(t(
            "cli.exp.wrote_profiles",
            directory=exported_profiles, count=count, written=len(planned),
        ))
    stderr.write(t("cli.exp.edit_hint", destination=destination, var=ENV_VAR))
    return EXIT_OK


def _show_policy(policy: Policy, stdout: IO[str], t: Optional[Translator] = None) -> int:
    t = t or _EN
    stdout.write(f"{policy.describe()}\n")
    stdout.write(f"{t('cli.sp.lbl_source')}: {policy.source}\n")
    stdout.write(f"{t('cli.sp.lbl_schema')}: {policy.schema_version}\n\n")

    for key, class_policy in policy.classes.items():
        counts: dict = {}
        for entry in class_policy.entries.values():
            counts[entry.category.value] = counts.get(entry.category.value, 0) + 1
        breakdown = ", ".join(f"{count} {name}" for name, count in sorted(counts.items()))
        stdout.write(
            f"{class_policy.label} ({key}) -> {class_policy.sshd_config_directive or 'n/a'}\n"
            "  " + t("cli.sp.entries", entries=len(class_policy.entries),
                     patterns=len(class_policy.patterns), breakdown=breakdown) + "\n"
            "  " + t("cli.sp.suggested",
                     names=", ".join(class_policy.suggested()) or "-") + "\n"
        )

    stdout.write("\n" + t("cli.sp.weights", weights=policy.class_weights) + "\n")
    stdout.write(t("cli.sp.grades", ladder=" > ".join(policy.grade_ladder)) + "\n")
    stdout.write(t("cli.sp.advisories", n=len(policy.advisories)) + "\n")
    stdout.write("\n" + t("cli.sp.search_order") + "\n")
    for candidate in candidate_policy_paths():
        marker = "*" if candidate == policy.source else " "
        stdout.write(
            f"  {marker} {candidate}{'' if candidate.is_file() else t('cli.sp.missing')}\n"
        )
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def _prescan_language(argv: Sequence[str]) -> Optional[str]:
    """Read --lang off the raw argv, before argparse runs.

    argparse builds the help text (which must already be in the right language)
    before it parses, so the language cannot come from the parsed args. Only the
    explicit flag is read here; an absent flag returns None so the locale decides.
    Accepts both '--lang es' and '--lang=es'.
    """
    for index, token in enumerate(argv):
        if token == "--lang" and index + 1 < len(argv):
            return argv[index + 1]
        if token.startswith("--lang="):
            return token.split("=", 1)[1]
    return None


def main(
    argv: Optional[Sequence[str]] = None,
    stdout: Optional[IO[str]] = None,
    stderr: Optional[IO[str]] = None,
) -> int:
    """Run the command line interface and return the process exit code."""
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr

    argv = list(sys.argv[1:] if argv is None else argv)
    # The help text has to be built in the right language, but the language
    # only becomes known after parsing --lang -- and argparse builds the help
    # before it parses. So --lang is read off the raw argv first, the locale
    # fills in when it is absent, and the parser (and every later message) is
    # built from that translator.
    translator = Translator(resolve_language(_prescan_language(argv)), MESSAGES)
    parser = build_parser(translator)

    # With no arguments, or when any argument is a request for help, show the
    # full help and exit cleanly -- the same "help wins wherever it appears"
    # behaviour argparse gives '-h'. The broken spellings are intercepted
    # before argparse so that '--h' (alone or next to other options, like
    # '--h --lang es') shows help instead of failing with 'ambiguous option'.
    if not argv or any(token in _HELP_REQUESTS for token in argv):
        parser.print_help(stdout)
        return EXIT_OK

    args = parser.parse_args(argv)

    if args.export_policy is not None:
        return _export_policy(args.export_policy, stderr, translator)

    try:
        policy = load_policy(args.config, translator.language)
    except PolicyError as exc:
        stderr.write(translator("cli.err.generic", exc=exc))
        return EXIT_USAGE

    if args.wizard:
        if not sys.stdin.isatty():
            stderr.write(translator("cli.err.wizard_needs_tty"))
            return EXIT_USAGE
        from .wizard import run_wizard

        fmt_options = ["console", *sorted(n for n in FORMATS if n != "console")]
        profile_labels = {
            pid: (
                f"{profile.name} ({profile.authority})"
                + (f", {profile.edition}" if profile.edition else "")
            )
            for pid, profile in policy.profiles.items()
        }
        def emit(line: str) -> None:
            stdout.write(line + "\n")

        built = run_wizard(
            sorted(policy.profiles),
            fmt_options,
            ask=input,
            emit=emit,
            t=translator,
            profile_labels=profile_labels,
        )
        if built is None:
            return EXIT_OK
        return main(built, stdout=stdout, stderr=stderr)

    if args.show_policy:
        return _show_policy(policy, stdout, translator)

    if args.list_profiles:
        return _list_profiles(policy, stdout, translator)

    plugins, plugin_problems = load_plugins(args.plugin_dir)
    for problem in plugin_problems:
        stderr.write(translator("cli.warn.plugin_not_loaded", problem=problem))

    if args.list_plugins:
        return _list_plugins(plugins, plugin_problems, stdout, translator)

    if args.list_vulnerabilities:
        return _list_vulnerabilities(policy, stdout, translator)

    try:
        formats = _normalise_formats(args.formats)
        for name in formats:
            if name not in FORMATS:
                parser.error(translator(
                    "cli.err.unknown_format",
                    name=name, valid=", ".join(sorted(FORMATS)),
                ))
        default_credentials = Credentials(
            username=args.user,
            mode=AuthMode(args.auth),
            identity_file=args.identity,
            password_file=args.password_file,
            password_env=args.password_env,
        )
        targets, target_errors = build_targets(
            args.targets, args.files, args.port, defaults=default_credentials
        )
    except TargetError as exc:
        stderr.write(translator("cli.err.generic", exc=exc))
        return EXIT_USAGE

    for message in target_errors:
        stderr.write(translator("cli.warn.skipping_target", message=message))

    if not targets:
        stderr.write(translator("cli.err.no_target"))
        return EXIT_USAGE

    def _resolve_profiles(values: Sequence[str]) -> List[str]:
        resolved: List[str] = []
        for value in values:
            for part in value.split(","):
                profile_id = part.strip()
                if not profile_id:
                    continue
                if policy.resolve_profile(profile_id) is None:
                    known = ", ".join(policy.profile_selectors())
                    parser.error(translator(
                        "cli.err.unknown_profile", id=profile_id, known=known,
                    ))
                if profile_id not in resolved:
                    resolved.append(profile_id)
        return resolved

    required_profiles = _resolve_profiles(args.required_profiles)
    selected_profiles = _resolve_profiles(args.profiles)
    # Requiring a profile implies evaluating it, so the two flags compose.
    for profile_id in required_profiles:
        if selected_profiles and profile_id not in selected_profiles:
            selected_profiles.append(profile_id)

    if len(formats) > 1 and not args.output:
        parser.error(translator("cli.err.output_required"))

    # One destination per format. Each has its own extension, so a shared base
    # name resolves to distinct files; tests/test_compare_and_formats.py holds
    # the extensions unique, which is what makes that true.
    destinations = [(name, _destination_for(name, formats, args.output)) for name in formats]

    try:
        scan_options = ScanOptions(
            timeout=args.timeout,
            concurrency=args.concurrency,
            retries=args.retries,
            fetch_host_keys=not args.no_host_keys,
            address_family=(
                socket.AF_INET if args.ipv4 else socket.AF_INET6 if args.ipv6 else socket.AF_UNSPEC
            ),
            source_address=args.source_ip,
            skip_certificate_probes=args.no_cert_probes,
            profiles=tuple(selected_profiles) or None,
            probe_auth_methods=args.auth_methods or args.all_checks,
            auth_username=args.user or "sshcryptochecker",
            jump_host=args.jump_host,
            jump_options=tuple(args.jump_option or ()),
            audit_client=args.audit_client or args.all_checks or bool(args.client_config),
            client_config_file=args.client_config,
            plugins=tuple(plugins),
            check_sshfp=args.sshfp or args.all_checks,
            dns_servers=tuple(args.dns_server) if args.dns_server else None,
            audit_config=args.audit_config,
            check_known_hosts=args.known_hosts is not None or args.all_checks,
            known_hosts_paths=(args.known_hosts,) if args.known_hosts else None,
            measure_max_startups=args.max_startups is not None,
            max_startups_probe_limit=args.max_startups or 20,
            measure_login_grace=args.login_grace is not None or args.all_checks,
            login_grace_wait=args.login_grace or 130.0,
        )
    except ValueError as exc:
        parser.error(str(exc))

    progress = _make_progress_callback(args, len(targets), stderr, translator)
    if not args.quiet:
        stderr.write(translator(
            "cli.msg.scan_start", n=len(targets), policy=policy.describe(),
        ))
        if args.verbose:
            # Which account and which key, because an audit that does not say
            # who it ran as cannot be read later: "root can log in directly"
            # means one thing found as root and another found as nobody. It
            # names the source of a password and never its value.
            stderr.write(translator(
                "cli.msg.credentials", desc=default_credentials.describe(),
            ))

    report = scan(
        targets,
        policy,
        scan_options,
        on_finish=progress,
        command_line=" ".join(["ssh-crypto-checker", *argv]),
    )

    if args.history is not None:
        try:
            append_history(args.history, build_json_document(report, policy))
        except HistoryError as exc:
            stderr.write(translator("cli.err.generic", exc=exc))
            return EXIT_USAGE

    comparison = None
    if args.compare is not None:
        try:
            comparison = compare_reports(report, load_baseline(args.compare))
        except BaselineError as exc:
            stderr.write(translator("cli.err.generic", exc=exc))
            return EXIT_USAGE

    color_mode = "never" if args.no_color else args.color
    base_options = RenderOptions.for_stream(
        stdout,
        color_mode=color_mode,
        summary_only=args.summary_only,
        include_config_snippet=not args.no_config_suggestions,
        show_algorithm_notes=args.notes,
        translator=translator,
    )

    written: List[Path] = []
    for name, destination in destinations:
        options = base_options
        if destination is not None:
            # A file is not a terminal: never write escape sequences into it.
            options = RenderOptions(
                color=False,
                unicode=True,
                width=base_options.width,
                summary_only=base_options.summary_only,
                include_config_snippet=base_options.include_config_snippet,
                show_algorithm_notes=base_options.show_algorithm_notes,
                translator=translator,
            )
        try:
            _write(render(name, report, policy, options), destination, stdout)
        except OSError as exc:
            stderr.write(translator("cli.err.could_not_write", destination=destination, exc=exc))
            return EXIT_USAGE
        if destination is not None:
            written.append(destination)

    if comparison is not None:
        stdout.write("\n" + _render_comparison(comparison, base_options) + "\n")

    if args.history is not None and args.history_report:
        # Writing the history and reading it back are two different failures.
        # The write is handled above; this one was not, and a history file the
        # process could append to but not read came out as a stack trace.
        try:
            summary = summarise_history(args.history, t=translator)
        except HistoryError as exc:
            stderr.write(translator("cli.err.generic", exc=exc))
            return EXIT_USAGE
        rule = ("━" if base_options.unicode else "=") * base_options.width
        stdout.write("\n" + rule + "\n" + translator("cli.msg.history_header") + "\n\n")
        stdout.write("\n".join(summary) + "\n")

    if written and not args.quiet:
        for path in written:
            stderr.write(translator("cli.msg.wrote", path=path))

    if comparison is not None and args.fail_on_regression and comparison.regressions:
        return EXIT_FINDINGS
    if _profile_not_met(report, required_profiles):
        return EXIT_FINDINGS
    if _threshold_exceeded(report, args.fail_on):
        return EXIT_FINDINGS
    if report.summary.failed:
        return EXIT_SCAN_ERROR
    return EXIT_OK


def _destination_for(
    output_format: str, formats: Sequence[str], output: Optional[str]
) -> Optional[Path]:
    if not output or output == "-":
        return None
    del formats  # one format or several, the file still gets its extension
    extension = EXTENSIONS[output_format]
    # Append the format's extension unless the path already carries it, so a
    # single '-o informe --format html' writes 'informe.html' rather than a file
    # literally called 'informe', and none of them ever double the suffix.
    if output.lower().endswith(extension.lower()):
        return Path(output)
    return Path(output + extension)


def _make_progress_callback(
    args: argparse.Namespace, total: int, stderr: IO[str],
    t: Optional[Translator] = None,
) -> Optional[Callable[[Any], None]]:
    """Return an ``on_finish`` callback, or ``None`` when output must stay quiet."""
    t = t or _EN
    if args.quiet:
        return None
    if not args.verbose and (total <= 1 or not stderr.isatty()):
        return None

    state = {"done": 0}

    def on_finish(result: Any) -> None:
        state["done"] += 1
        if args.verbose:
            status = result.grade if result.ok else t("cli.msg.unreachable")
            stderr.write(f"[{state['done']}/{total}] {result.target}: {status}\n")
        else:
            stderr.write("\r" + t("cli.msg.scanning", done=state["done"], total=total))
            if state["done"] == total:
                stderr.write("\r" + " " * 32 + "\r")
        stderr.flush()

    return on_finish


if __name__ == "__main__":
    sys.exit(main())
