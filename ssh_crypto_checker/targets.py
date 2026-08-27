"""Parsing of the target specifications accepted on the command line.

Supported forms::

    example.com                 # default port
    example.com:2222
    192.0.2.10
    192.0.2.10:22
    [2001:db8::1]:22            # IPv6 with an explicit port
    2001:db8::1                 # bare IPv6, default port
    ssh://example.com:2222
    admin@example.com:2222      # the user part is ignored

Files use one target per line. ``#`` starts a comment. After the target,
``key=value`` tokens set per-server options and anything else accumulates into
a free-form label::

    web01.example.com:22   user=admin auth=key key=~/.ssh/id_ed25519   web frontend
    db01.example.com       user=svc auth=password password-env=DB01_PW
    router.example.com     auth=none   edge router
    192.0.2.10             legacy application server

Recognised options: ``user``, ``auth`` (none, key, password or any), ``key``,
``password-file``, ``password-env``, ``port`` and ``label``. Command line
defaults apply to any target that does not set them.

A password is never written in the file itself: only ``password-file`` and
``password-env`` are accepted, so the inventory can be committed to version
control without leaking a secret.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Dict, List, Optional, TextIO, Tuple

from .models import AuthMode, Credentials, Target

__all__ = [
    "DEFAULT_PORT",
    "OPTION_NAMES",
    "TargetError",
    "build_targets",
    "parse_options",
    "parse_target",
    "read_target_file",
]

#: Options accepted after a target in an inventory file.
OPTION_NAMES = frozenset(
    {"user", "username", "auth", "key", "identity", "password-file", "password_file",
     "password-env", "password_env", "port", "label"}
)

DEFAULT_PORT = 22
_MAX_PORT = 65535


class TargetError(ValueError):
    """Raised when a target specification cannot be understood."""


def parse_options(tokens: Sequence[str], context: str) -> Tuple[Dict[str, str], List[str]]:
    """Split inventory tokens into recognised options and label words.

    A token only counts as an option when its name is one this tool knows, so a
    label such as ``base=datos`` is not silently swallowed.
    """
    options: Dict[str, str] = {}
    words: List[str] = []
    for token in tokens:
        name, separator, value = token.partition("=")
        key = name.strip().lower()
        if separator and key in OPTION_NAMES:
            options[key.replace("_", "-")] = value.strip()
        else:
            words.append(token)
    # Only the names are echoed. A token that looks like an option may well be
    # a secret somebody typed by mistake -- 'password=hunter2' is exactly the
    # case this tool refuses -- and an error message ends up in terminals,
    # tickets and CI logs.
    unknown = [
        t.partition("=")[0].strip()
        for t in words
        if "=" in t and not t.startswith("=")
    ]
    if unknown:
        if "password" in {name.lower() for name in unknown}:
            raise TargetError(
                f"{context}: a literal password is not accepted in an inventory "
                "file; use password-file= or password-env="
            )
        raise TargetError(
            f"{context}: unrecognised option(s) {', '.join(unknown)}; "
            f"valid options are {', '.join(sorted(OPTION_NAMES))}"
        )
    return options, words


def _credentials_from(options: Dict[str, str], defaults: Credentials, context: str) -> Credentials:
    """Build per-target credentials, falling back to the command line defaults."""
    mode = defaults.mode
    if "auth" in options:
        try:
            mode = AuthMode(options["auth"].lower())
        except ValueError:
            valid = ", ".join(m.value for m in AuthMode)
            raise TargetError(
                f"{context}: invalid auth mode '{options['auth']}' (valid: {valid})"
            ) from None

    return Credentials(
        username=options.get("user") or options.get("username") or defaults.username,
        mode=mode,
        identity_file=options.get("key") or options.get("identity") or defaults.identity_file,
        password_file=options.get("password-file") or defaults.password_file,
        password_env=options.get("password-env") or defaults.password_env,
    )


def parse_target(
    spec: str,
    default_port: int = DEFAULT_PORT,
    label: Optional[str] = None,
    source: Optional[str] = None,
    credentials: Optional[Credentials] = None,
) -> Target:
    """Turn one specification string into a :class:`~.models.Target`."""
    text = spec.strip()
    if not text:
        raise TargetError("empty target")

    for scheme in ("ssh://", "sftp://"):
        if text.lower().startswith(scheme):
            text = text[len(scheme) :]
            break
    text = text.rstrip("/")

    if "@" in text:
        _user, _, text = text.rpartition("@")
        if not text:
            raise TargetError(f"missing host name in '{spec}'")

    host, port = _split_host_port(text, spec, default_port)

    if not host:
        raise TargetError(f"missing host name in '{spec}'")
    if any(character.isspace() for character in host):
        raise TargetError(f"host name contains whitespace: '{spec}'")
    if not 1 <= port <= _MAX_PORT:
        raise TargetError(f"port out of range in '{spec}': {port}")

    return Target(
        host=host,
        port=port,
        label=label,
        source=source,
        credentials=credentials or Credentials(),
    )


def _split_host_port(text: str, spec: str, default_port: int) -> Tuple[str, int]:
    """Split a ``host[:port]`` string, coping with IPv6 literals."""
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0:
            raise TargetError(f"unbalanced '[' in '{spec}'")
        host = text[1:closing]
        remainder = text[closing + 1 :]
        if not remainder:
            return host, default_port
        if not remainder.startswith(":"):
            raise TargetError(f"unexpected text after ']' in '{spec}'")
        return host, _parse_port(remainder[1:], spec)

    # More than one colon means a bare IPv6 literal: there is no way to tell a
    # port apart from another group, so the whole string is the address.
    if text.count(":") > 1:
        return text, default_port

    if ":" in text:
        host, _, port_text = text.partition(":")
        return host, _parse_port(port_text, spec)

    return text, default_port


def _parse_port(text: str, spec: str) -> int:
    port_text = text.strip()
    if not port_text:
        raise TargetError(f"missing port number after ':' in '{spec}'")
    # Deliberately not str.isdigit(): that accepts superscripts and other
    # Unicode digits, which either crash int() or silently parse as a
    # different number than the one that was typed.
    if not all(character in "0123456789" for character in port_text):
        raise TargetError(f"invalid port '{port_text}' in '{spec}'")
    return int(port_text)


def read_target_file(
    path: Path,
    default_port: int = DEFAULT_PORT,
    defaults: Optional[Credentials] = None,
) -> Tuple[List[Target], List[str]]:
    """Read a target list file, returning ``(targets, errors)``.

    A single malformed line does not abort the run: the error is collected and
    reported so a long inventory can still be scanned.

    There is no way to hand this an open stream. It had one, and only the tests
    used it -- which meant the tests never opened a file, and the one thing
    that can go wrong with reading an inventory is opening it.
    """
    targets: List[Target] = []
    errors: List[str] = []

    handle: TextIO
    if str(path) == "-":
        handle = sys.stdin
        display_name = "<stdin>"
        close_handle = False
    else:
        try:
            handle = path.open("r", encoding="utf-8")
        except OSError as exc:
            raise TargetError(f"cannot read target file {path}: {exc}") from exc
        display_name = str(path)
        close_handle = True

    try:
        for number, raw_line in enumerate(handle, start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            # Split on any whitespace so tab-aligned inventories work.
            fields = line.split()
            spec = fields[0]
            source = f"{display_name}:{number}"
            try:
                options, words = parse_options(fields[1:], source)
                credentials = _credentials_from(options, defaults or Credentials(), source)
                # An explicit label= is a single token, so any trailing words
                # join it rather than being silently dropped.
                label = " ".join(filter(None, [options.get("label"), " ".join(words)])).strip()
                port = default_port
                if "port" in options:
                    port = _parse_port(options["port"], line)
                targets.append(
                    parse_target(
                        spec, port, label=label or None, source=source, credentials=credentials
                    )
                )
            except TargetError as exc:
                # parse_options and _credentials_from already name the line;
                # parse_target and _parse_port do not, so the prefix is added
                # only when it is not there already.
                message = str(exc)
                errors.append(
                    message if message.startswith(f"{source}:") else f"{source}: {message}"
                )
    finally:
        if close_handle:
            handle.close()

    return targets, errors


def build_targets(
    specs: Sequence[str],
    files: Iterable[Path] = (),
    default_port: int = DEFAULT_PORT,
    defaults: Optional[Credentials] = None,
) -> Tuple[List[Target], List[str]]:
    """Collect targets from command line arguments and files.

    Duplicates (same host and port) are removed, keeping the first occurrence
    so that its label survives.
    """
    targets: List[Target] = []
    errors: List[str] = []

    for spec in specs:
        try:
            targets.append(
                parse_target(spec, default_port, source="command line", credentials=defaults)
            )
        except TargetError as exc:
            errors.append(str(exc))

    for path in files:
        file_targets, file_errors = read_target_file(path, default_port, defaults=defaults)
        targets.extend(file_targets)
        errors.extend(file_errors)

    seen = set()
    unique: List[Target] = []
    for target in targets:
        key = (target.host.lower(), target.port)
        if key in seen:
            continue
        seen.add(key)
        unique.append(target)

    return unique, errors
