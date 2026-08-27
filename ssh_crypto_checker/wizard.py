"""Interactive wizard: build a command line by answering questions.

The wizard never scans anything itself. It assembles the exact ``argv`` a normal
invocation would take, prints it back as a copy-pasteable command, and hands it
to :func:`ssh_crypto_checker.cli.main` to run -- so what it shows and what it
runs are the same thing by construction, and the printed command can be saved
and re-run later without the wizard.

``ask`` and ``emit`` are injected so the whole flow is testable without a
terminal: ``ask(prompt)`` returns a line of input, ``emit(line)`` writes a line
of output. ``t`` is a :class:`ssh_crypto_checker.i18n.Translator`, so every
string comes out in the chosen language.
"""

from __future__ import annotations

import shlex
from typing import Callable, List, Optional, Sequence

from .i18n import Translator

Ask = Callable[[str], str]
Emit = Callable[[str], None]

#: The remote checks a wizard can switch on, as (flag, message key).
_REMOTE_CHECKS = [
    ("--auth-methods", "wiz.chk_auth_methods"),
    ("--sshfp", "wiz.chk_sshfp"),
    ("--known-hosts", "wiz.chk_known_hosts"),
    ("--login-grace", "wiz.chk_login_grace"),
    ("--audit-client", "wiz.chk_audit_client"),
    ("--max-startups", "wiz.chk_max_startups"),
    ("--audit-config", "wiz.chk_audit_config"),
]

#: Presentation toggles, as (flag, message key).
_PRESENTATION = [
    ("--summary-only", "wiz.pres_summary_only"),
    ("--notes", "wiz.pres_notes"),
    ("--no-config-suggestions", "wiz.pres_no_config"),
    ("--no-color", "wiz.pres_no_color"),
    ("--verbose", "wiz.pres_verbose"),
    ("--quiet", "wiz.pres_quiet"),
]

#: Accepted inputs, language-independent so either language's user is understood.
_YES = frozenset({"s", "si", "sí", "y", "yes"})
_NO = frozenset({"n", "no"})
_ALL = frozenset({"a", "all", "todas", "*"})
_NONE = frozenset({"n", "none", "ninguna"})


# --------------------------------------------------------------------------- #
# Prompt primitives
# --------------------------------------------------------------------------- #


def _ask_text(ask: Ask, emit: Emit, prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = ask(f"{prompt}{suffix}: ").strip()
    return raw if raw else default


def _ask_yes_no(ask: Ask, emit: Emit, t: Translator, prompt: str, default: bool = False) -> bool:
    hint = t("ui.yes_no_default_yes") if default else t("ui.yes_no_default_no")
    while True:
        raw = ask(f"{prompt} [{hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in _YES:
            return True
        if raw in _NO:
            return False
        emit(t("ui.yes_no_retry"))


def _ask_int(ask: Ask, emit: Emit, t: Translator, prompt: str, default: int) -> int:
    while True:
        raw = ask(f"{prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            emit(t("ui.int_retry"))


def _ask_choice(
    ask: Ask, emit: Emit, t: Translator, prompt: str, options: Sequence[str], default: str
) -> str:
    emit(prompt)
    for i, opt in enumerate(options, 1):
        mark = t("ui.choice_default_mark") if opt == default else ""
        emit(f"  {i}) {opt}{mark}")
    while True:
        raw = ask(t("ui.choice_prompt")).strip()
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        emit(t("ui.choice_out_of_range", n=len(options)))


def _ask_multi(
    ask: Ask,
    emit: Emit,
    t: Translator,
    prompt: str,
    options: Sequence[str],
    *,
    default_all: bool,
) -> List[str]:
    """Multi-select with all/none. Returns the chosen subset (order preserved)."""
    emit(prompt)
    for i, opt in enumerate(options, 1):
        emit(f"  {i}) {opt}")
    default_label = t("ui.default_label_all") if default_all else t("ui.default_label_none")
    emit(t("ui.multi_hint"))
    while True:
        raw = ask(t("ui.multi_prompt", label=default_label)).strip().lower()
        if not raw:
            return list(options) if default_all else []
        if raw in _ALL:
            return list(options)
        if raw in _NONE:
            return []
        picked: List[str] = []
        ok = True
        for tok in raw.replace(" ", "").split(","):
            if tok.isdigit() and 1 <= int(tok) <= len(options):
                choice = options[int(tok) - 1]
                if choice not in picked:
                    picked.append(choice)
            else:
                emit(t("ui.multi_bad_token", token=tok, n=len(options)))
                ok = False
                break
        if ok:
            return picked


# --------------------------------------------------------------------------- #
# The wizard
# --------------------------------------------------------------------------- #


def run_wizard(
    profile_ids: Sequence[str],
    formats: Sequence[str],
    *,
    ask: Ask,
    emit: Emit,
    t: Translator,
    profile_labels: Optional[dict] = None,
) -> Optional[List[str]]:
    """Ask the questions and return the argv to run, or None to just show it.

    ``profile_ids`` are the conformance profile identifiers, ``formats`` the
    available output formats, ``t`` the translator, and ``profile_labels`` maps
    an id to a human-readable description so the menu shows what each normativa
    is; the id is still what the command uses.
    """
    argv: List[str] = []
    labels = profile_labels or {}

    def _option(pid: str) -> str:
        return f"{pid}   {labels[pid]}" if pid in labels else pid

    emit("")
    emit(t("wiz.title"))
    emit(t("wiz.intro"))
    emit(t("wiz.default_hint"))
    emit("")

    # 1. Targets -----------------------------------------------------------
    emit(t("wiz.sec_targets"))
    hosts = _ask_text(ask, emit, t("wiz.target_prompt"), default="")
    targets = hosts.split() if hosts else []
    argv.extend(targets)

    inventory = _ask_text(ask, emit, t("wiz.inventory_prompt"), default="")
    if inventory:
        argv += ["-f", inventory]

    if not targets and not inventory:
        emit(t("wiz.no_target_hint"))
        hosts = _ask_text(ask, emit, t("wiz.target_reprompt"), default="")
        if hosts:
            targets = hosts.split()
            argv[:0] = targets  # positionals go first
        else:
            emit(t("wiz.cancelled_no_target"))
            return None

    port = _ask_int(ask, emit, t, t("wiz.port_prompt"), 22)
    if port != 22:
        argv += ["-p", str(port)]

    user = _ask_text(ask, emit, t("wiz.user_prompt"), default="")
    if user:
        argv += ["--user", user]

    if _ask_yes_no(ask, emit, t, t("wiz.credentials_gate"), default=False):
        emit("")
        emit(t("wiz.sec_credentials"))
        auth = _ask_choice(
            ask, emit, t, t("wiz.auth_mode"), ["any", "none", "key", "password"], default="any",
        )
        if auth != "any":
            argv += ["--auth", auth]
        identity = _ask_text(ask, emit, t("wiz.identity_prompt"), default="")
        if identity:
            argv += ["-i", identity]
        pw_file = _ask_text(ask, emit, t("wiz.password_file_prompt"), default="")
        if pw_file:
            argv += ["--password-file", pw_file]
        pw_env = _ask_text(ask, emit, t("wiz.password_env_prompt"), default="")
        if pw_env:
            argv += ["--password-env", pw_env]

    # 2. Profiles ----------------------------------------------------------
    emit("")
    emit(t("wiz.sec_profiles"))
    emit(t("wiz.profiles_intro1"))
    emit(t("wiz.profiles_intro2"))
    emit(t("wiz.profiles_intro3"))
    emit(t("wiz.profiles_intro4"))
    emit(t("wiz.profiles_intro5"))
    emit(t("wiz.profiles_intro6"))
    emit("")
    emit(t("wiz.evaluate_lead"))
    chosen = _ask_multi(
        ask, emit, t, t("wiz.evaluate_prompt"),
        [_option(pid) for pid in profile_ids], default_all=True,
    )
    chosen_profiles = [option.split()[0] for option in chosen]
    is_subset = bool(chosen_profiles) and len(chosen_profiles) != len(profile_ids)
    if is_subset:
        argv += ["--profile", ",".join(chosen_profiles)]
    requirable = chosen_profiles if is_subset else list(profile_ids)

    emit("")
    emit(t("wiz.require_lead"))
    if _ask_yes_no(ask, emit, t, t("wiz.require_gate"), default=False):
        required = _ask_multi(
            ask, emit, t, t("wiz.require_prompt"),
            [_option(pid) for pid in requirable], default_all=False,
        )
        for option in required:
            argv += ["--require-profile", option.split()[0]]

    # 3. Output ------------------------------------------------------------
    emit("")
    emit(t("wiz.sec_output"))
    chosen_formats = _ask_multi(
        ask, emit, t, t("wiz.format_prompt"), list(formats), default_all=False,
    )
    if chosen_formats and chosen_formats != ["console"]:
        argv += ["--format", ",".join(chosen_formats)]

    needs_file = bool(chosen_formats) and chosen_formats != ["console"]
    if needs_file or _ask_yes_no(ask, emit, t, t("wiz.write_file_gate"), default=needs_file):
        path = _ask_text(ask, emit, t("wiz.output_path_prompt"), default="report")
        argv += ["-o", path]

    fail_on = _ask_choice(
        ask, emit, t, t("wiz.fail_on_prompt"),
        ["never", "critical", "high", "medium", "low", "info"], default="never",
    )
    if fail_on != "never":
        argv += ["--fail-on", fail_on]

    # 4. Advanced ----------------------------------------------------------
    if _ask_yes_no(ask, emit, t, t("wiz.remote_gate"), default=False):
        emit("")
        emit(t("wiz.sec_remote"))
        if _ask_yes_no(ask, emit, t, t("wiz.all_checks_gate"), default=False):
            argv += ["--all-checks"]
        else:
            labels_r = [f"{flag}  ({t(key)})" for flag, key in _REMOTE_CHECKS]
            picked = _ask_multi(ask, emit, t, t("wiz.remote_pick"), labels_r, default_all=False)
            for label in picked:
                argv += [label.split()[0]]

    if _ask_yes_no(ask, emit, t, t("wiz.presentation_gate"), default=False):
        emit("")
        emit(t("wiz.sec_presentation"))
        labels_p = [f"{flag}  ({t(key)})" for flag, key in _PRESENTATION]
        picked = _ask_multi(ask, emit, t, t("wiz.presentation_pick"), labels_p, default_all=False)
        for label in picked:
            argv += [label.split()[0]]

    if _ask_yes_no(ask, emit, t, t("wiz.scanning_gate"), default=False):
        emit("")
        emit(t("wiz.sec_scanning"))
        timeout = _ask_int(ask, emit, t, t("wiz.timeout_prompt"), 5)
        if timeout != 5:
            argv += ["-t", str(timeout)]
        concurrency = _ask_int(ask, emit, t, t("wiz.concurrency_prompt"), 8)
        if concurrency != 8:
            argv += ["-c", str(concurrency)]
        retries = _ask_int(ask, emit, t, t("wiz.retries_prompt"), 1)
        if retries != 1:
            argv += ["-r", str(retries)]
        if _ask_yes_no(ask, emit, t, t("wiz.no_host_keys_gate"), default=False):
            argv += ["--no-host-keys"]
        elif _ask_yes_no(ask, emit, t, t("wiz.no_cert_probes_gate"), default=False):
            argv += ["--no-cert-probes"]

    if _ask_yes_no(ask, emit, t, t("wiz.connection_gate"), default=False):
        emit("")
        emit(t("wiz.sec_connection"))
        jump = _ask_text(ask, emit, t("wiz.jump_prompt"), default="")
        if jump:
            argv += ["-J", jump]
        source_ip = _ask_text(ask, emit, t("wiz.source_ip_prompt"), default="")
        if source_ip:
            argv += ["--source-ip", source_ip]
        family = _ask_choice(
            ask, emit, t, t("wiz.family_prompt"),
            [t("wiz.family_both"), t("wiz.family_ipv4"), t("wiz.family_ipv6")],
            default=t("wiz.family_both"),
        )
        if family == t("wiz.family_ipv4"):
            argv += ["-4"]
        elif family == t("wiz.family_ipv6"):
            argv += ["-6"]

    if _ask_yes_no(ask, emit, t, t("wiz.policy_gate"), default=False):
        emit("")
        emit(t("wiz.sec_policy"))
        config = _ask_text(ask, emit, t("wiz.config_prompt"), default="")
        if config:
            argv += ["--config", config]
        plugin_dir = _ask_text(ask, emit, t("wiz.plugin_dir_prompt"), default="")
        if plugin_dir:
            argv += ["--plugin-dir", plugin_dir]

    if _ask_yes_no(ask, emit, t, t("wiz.history_gate"), default=False):
        emit("")
        emit(t("wiz.sec_history"))
        history = _ask_text(ask, emit, t("wiz.history_prompt"), default="")
        if history:
            argv += ["--history", history]
        compare = _ask_text(ask, emit, t("wiz.compare_prompt"), default="")
        if compare:
            argv += ["--compare", compare]
            if _ask_yes_no(ask, emit, t, t("wiz.regression_gate"), default=False):
                argv += ["--fail-on-regression"]

    # 5. Show and offer to run --------------------------------------------
    # The wizard's language travels into the command it builds: without this,
    # a wizard run with --lang es would assemble a command whose reports come
    # out in whatever the machine's locale says -- here, and on any other
    # machine the copied command is later run on.
    argv += ["--lang", t.language]
    command = "ssh-crypto-checker " + " ".join(shlex.quote(tok) for tok in argv)
    emit("")
    emit(t("wiz.command_header"))
    emit(f"  {command}")
    emit("")
    emit(t("wiz.command_save"))

    if _ask_yes_no(ask, emit, t, t("wiz.launch_gate"), default=True):
        return argv
    emit(t("wiz.declined"))
    return None
