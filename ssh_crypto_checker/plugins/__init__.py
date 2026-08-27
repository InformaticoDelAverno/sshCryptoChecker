"""Detections that need code rather than a rule.

Most vulnerabilities are matched declaratively from ``algorithms.json``: a
version window, an algorithm that is offered, a directive that is set. That
covers nearly everything and needs no Python at all, which is why it is the
default and why it should stay the default.

What it cannot express is a check that has to *compute* something -- factor a
modulus, correlate two pieces of evidence, decide from arithmetic rather than
from matching. This is for those. A plugin is one file:

.. code-block:: python

    ID = "EXAMPLE-1"
    NAME = "Something a rule cannot express"
    SEVERITY = "high"
    DESCRIPTION = "What is wrong, and why it matters."
    REMEDIATION = "What to do about it."
    REFERENCES = ["CVE-0000-0000"]

    def check(server):
        if server.offers("cipher", "3des-cbc"):
            return Detected(evidence=["3des-cbc"])
        return None

Drop it in a plugin directory and it runs. Nothing else has to change: the
result becomes an ordinary vulnerability match, so it appears in every output
format, in the fleet summary and in the coverage test, exactly as a rule from
the policy file would.

Three properties matter more than the convenience:

*A broken plugin must not break the scan.* Anything a plugin raises is caught
and reported as a finding naming the plugin, in the same way a malformed rule
in the policy file is. One bad file does not cost an audit.

*A plugin that cannot answer must say so.* Declaring ``NEEDS`` makes the
result undetermined when the scan did not collect that data, rather than
letting the plugin return "not affected" because it had nothing to look at.

*Loading code is loading code.* A plugin runs with the privileges of whoever
runs the scan, which for an audit is frequently root. Directories are
therefore explicit, never the working directory, and one that is writable by
others is refused rather than trusted.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, cast

from ..models import Severity

__all__ = [
    "Detected",
    "FleetView",
    "ForTarget",
    "Plugin",
    "PluginError",
    "ScannedServer",
    "ServerView",
    "Undetermined",
    "builtin_directory",
    "default_plugin_directories",
    "load_plugins",
]


class PluginError(Exception):
    """A plugin could not be loaded."""


# --------------------------------------------------------------------------- #
# What a plugin returns
# --------------------------------------------------------------------------- #


@dataclass
class Detected:
    """Something the plugin found.

    The module's metadata supplies the defaults, so the common case -- one
    plugin, one thing to report -- needs nothing but ``evidence``. A plugin
    that reports several related things overrides what differs and returns a
    list; that keeps one subject in one file instead of scattering six halves
    of the same parser across six.
    """

    evidence: List[str] = field(default_factory=list)
    """What made it match, so the finding is actionable rather than a label."""
    severity: Optional[str] = None
    """Overrides the plugin's declared severity, when the case is worse or milder."""
    note: str = ""
    """Appended to the description, for anything specific to this server."""
    id: str = ""
    """Overrides the plugin's ID, for a plugin that reports more than one thing."""
    name: str = ""
    description: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ForTarget:
    """A fleet finding, and which server it belongs to.

    A fleet check sees everything, so it has to say who each result is about.
    ``target`` is the address as the report prints it -- what ``str(target)``
    gives -- and anything that names a server the scan did not produce is
    dropped rather than invented.
    """

    target: str
    finding: Any


@dataclass
class ScannedServer:
    """One server in a fleet view: what it is called, and what was seen."""

    target: str
    """The address as the report prints it."""
    label: str = ""
    view: ServerView = field(default_factory=lambda: ServerView())
    """Always present, even for a target that could not be reached.

    A server that refused the connection has a view with nothing in it rather
    than no view, so a fleet check that walks the scan sees every target it was
    asked about. The alternative -- dropping the failures -- makes "are all my
    servers on the same version" answer from whichever ones happened to be up.
    """


@dataclass
class FleetView:
    """Every server in the scan, for a check that needs more than one.

    Holds the same observations as a ServerView, one per server, and the same
    boundary applies: no score, no grade, no verdict. A fleet check can see
    that two servers present the same key; it cannot see, or change, what
    either of them was graded.
    """

    servers: List[ScannedServer] = field(default_factory=list)
    policy: Any = None

    def __iter__(self) -> Iterator[ScannedServer]:
        return iter(self.servers)

    def __len__(self) -> int:
        return len(self.servers)

    def with_host_keys(self) -> List[ScannedServer]:
        """The servers whose host keys were actually retrieved."""
        return [server for server in self.servers if server.view.host_keys]


@dataclass
class Undetermined:
    """The plugin could not decide, and says what would settle it."""

    needs: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# What a plugin is given
# --------------------------------------------------------------------------- #


@dataclass
class ServerView:
    """What was observed, and nothing that was concluded.

    Deliberately the scan's *observations* rather than its assessment. A plugin
    can see the algorithms a server offered; it cannot see the score, the grade
    or the verdict, and it cannot change them.

    That boundary is the point. Findings from a plugin are added to the report;
    the number at the top of it comes from the policy file. A plugin that is
    absent, broken or third-party therefore cannot silently move a server's
    grade, which is the one thing an auditor has to be able to rely on.
    """

    banner: Any = None
    kexinit: Any = None
    host_keys: Sequence[Any] = ()
    auth_methods: Any = None
    config: Any = None
    """The server's effective configuration, from --audit-config."""
    client_config: Any = None
    assessments: Sequence[Any] = ()
    """Each algorithm class, classified against the policy.

    A classification is an observation plus the policy's opinion of it, which
    a check may read. The *score* built from those classifications is not here
    and never will be: that is the conclusion, and no plugin gets to see or
    move it.
    """
    strict_kex: bool = False
    post_quantum: Any = None
    dh_group_bits: Optional[int] = None
    sshfp: Any = None
    """SSHFP records compared against the host keys, from --sshfp."""
    known_hosts: Any = None
    """The local known_hosts comparison, from --known-hosts."""
    login_grace_seconds: Optional[float] = None
    max_startups: Optional[int] = None
    max_startups_probe_limit: int = 0
    policy: Any = None

    # -- banner ---------------------------------------------------------- #

    @property
    def product(self) -> str:
        return getattr(self.banner, "product", None) or ""

    @property
    def product_version(self) -> str:
        return getattr(self.banner, "product_version", None) or ""

    @property
    def protocol_version(self) -> str:
        return getattr(self.banner, "protocol_version", "") or ""

    def version_in_range(self, introduced: str, fixed: str) -> bool:
        """Whether the advertised version falls in ``[introduced, fixed)``."""
        from ..analysis import version_in_range

        if not self.product_version:
            return False
        return version_in_range(self.product_version, introduced, fixed)

    # -- algorithms ------------------------------------------------------ #

    @staticmethod
    def _algorithm_class(algorithm_class: str) -> str:
        """Reject a class name no server has, loudly and in one place.

        Every accessor below funnels through here so that a typo is answered
        the same way each time. It used to be answered three different ways --
        a KeyError from algorithms(), an empty list from tags(), None from
        assessment() -- and the empty list is the dangerous one: a check keyed
        on a mistyped class silently never fires, which reads exactly like a
        server with nothing wrong with it.
        """
        from ..models import ALGORITHM_CLASSES

        if algorithm_class not in ALGORITHM_CLASSES:
            raise ValueError(
                f"unknown algorithm class {algorithm_class!r}; "
                f"expected one of {', '.join(ALGORITHM_CLASSES)}"
            )
        return algorithm_class

    def algorithms(self, algorithm_class: str) -> List[str]:
        """Every algorithm the server offers for a class."""
        self._algorithm_class(algorithm_class)
        if self.kexinit is None:
            return []
        return list(self.kexinit.algorithms_for(algorithm_class))

    def offers(self, algorithm_class: str, name: str) -> bool:
        return name in self.algorithms(algorithm_class)

    def requirement(self, name: str, default: Any = None) -> Any:
        """A threshold from the policy, so a plugin does not hard-code one.

        The numbers a check compares against belong in the policy file, where
        they can be changed without touching code. A plugin that carries its
        own copy of "2048" is a second place to update and a second place to
        forget.
        """
        if self.policy is None:
            return default
        return getattr(self.policy, name, default)

    def assessment(self, algorithm_class: str) -> Any:
        """The classification for one algorithm class, or None if not assessed."""
        self._algorithm_class(algorithm_class)
        for entry in self.assessments:
            if getattr(entry, "key", None) == algorithm_class:
                return entry
        return None

    def tags(self, algorithm_class: str, name: str) -> List[str]:
        """The policy's tags for an algorithm, so a plugin can reason by shape.

        An algorithm the policy has never heard of has no tags, which is an
        answer rather than an error -- servers offer names nobody has catalogued
        all the time. A class that does not exist is a different matter, and
        _algorithm_class says so.
        """
        self._algorithm_class(algorithm_class)
        if self.policy is None:
            return []
        return list(self.policy.lookup(algorithm_class, name).tags)

    # -- configuration --------------------------------------------------- #

    def directive(self, name: str) -> Optional[str]:
        """A directive from 'sshd -T', or None when it was not read."""
        if self.config is None or not getattr(self.config, "available", False):
            return None
        return cast(Optional[str], self.config.value(name))

    def client_directive(self, name: str) -> Optional[str]:
        if self.client_config is None or not getattr(self.client_config, "available", False):
            return None
        return cast(Optional[str], self.client_config.value(name))


#: What a plugin may declare it needs, and how to tell whether the scan has it.
_AVAILABILITY = {
    "banner": lambda view: view.banner is not None,
    "kexinit": lambda view: view.kexinit is not None,
    "host_keys": lambda view: bool(view.host_keys),
    "sshfp": lambda view: view.sshfp is not None and getattr(view.sshfp, "queried", False),
    "known_hosts": lambda view: view.known_hosts is not None
    and getattr(view.known_hosts, "checked", False),
    "login_grace": lambda view: view.login_grace_seconds is not None,
    "max_startups": lambda view: view.max_startups is not None,
    "auth_methods": lambda view: view.auth_methods is not None
    and getattr(view.auth_methods, "error", None) is None,
    "config": lambda view: view.config is not None
    and getattr(view.config, "available", False),
    "client_config": lambda view: view.client_config is not None
    and getattr(view.client_config, "available", False),
}

#: What to re-run with, per kind of missing data.
_NEEDS_HINT = {
    "sshfp": "the SSHFP records (--sshfp)",
    "known_hosts": "the known_hosts comparison (--known-hosts)",
    "login_grace": "the login grace measurement (--login-grace)",
    "max_startups": "the max-startups probe (--max-startups)",
    "auth_methods": "the authentication methods (--auth-methods)",
    "config": "the server's configuration (--audit-config)",
    "client_config": "the client configuration (--audit-client)",
    "host_keys": "the host keys (do not pass --no-host-keys)",
    "banner": "the server's identification string",
    "kexinit": "the algorithms the server offers",
}


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


#: What a plugin reports, and when it runs.
#:
#: ``vulnerability``  something somebody published an attack against. Gets the
#:                    ``vuln-`` prefix and its own section in the report.
#: ``check``          this policy's opinion about one server's configuration.
#: ``fleet``          something only visible across the whole scan. Runs once,
#:                    after every target, and attaches its findings to the
#:                    servers they are about.
#:
#: The first two see one server and cannot see each other. The third exists
#: because some problems are not properties of a server at all: a host key is
#: only *shared* relative to another host key, and no amount of looking at one
#: machine reveals it.
KINDS = ("vulnerability", "check", "fleet")


@dataclass
class Plugin:
    """One loaded detection."""

    id: str
    name: str
    severity: Severity
    description: str
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    affects: str = "server"
    kind: str = "vulnerability"
    needs: List[str] = field(default_factory=list)
    source: str = ""
    """The file it came from, so a report can say where a finding originated."""
    check: Any = None

    def missing(self, view: ServerView) -> List[str]:
        """What this plugin asked for that the scan did not collect."""
        absent = []
        for requirement in self.needs:
            probe = _AVAILABILITY.get(requirement)
            if probe is not None and not probe(view):
                absent.append(_NEEDS_HINT.get(requirement, requirement))
        return absent


_BUILTIN_CACHE: Optional[List[Plugin]] = None


def builtin_plugins() -> List[Plugin]:
    """The detections shipped with the tool, loaded once.

    These are not optional extras: they are how the tool performs most of its
    checks. A caller that passes no plugin list gets them, because the
    alternative is a library whose default behaviour silently omits most of
    what it is for.
    """
    global _BUILTIN_CACHE
    if _BUILTIN_CACHE is None:
        loaded, _problems = load_plugins([], include_builtin=True)
        _BUILTIN_CACHE = loaded
    return list(_BUILTIN_CACHE)


def builtin_directory() -> Path:
    """The plugins shipped with this tool."""
    return Path(__file__).resolve().parent / "builtin"


def default_plugin_directories() -> List[Path]:
    """Where plugins are looked for when nothing is specified.

    Deliberately not the working directory. Running a scan inside a directory
    somebody else can write to would otherwise execute their code, and this
    tool is often run with sudo.
    """
    directories = [builtin_directory()]
    configured = os.environ.get("SSHCC_PLUGIN_DIR")
    if configured:
        directories += [Path(part) for part in configured.split(os.pathsep) if part]
    home = Path(os.path.expanduser("~"))
    directories.append(home / ".config" / "sshcryptochecker" / "plugins")
    return directories


def _refuse_if_writable_by_others(path: Path) -> Optional[str]:
    """Why this path must not be loaded, or None if it is safe.

    A plugin directory anybody can write to is a way to run code as whoever
    runs the audit. That is worth refusing outright rather than warning about.
    """
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        return f"cannot be read: {exc}"
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        # The same rule sshd applies to authorized_keys under StrictModes, and
        # for the same reason.
        return (
            "is writable by group or others, so anyone in that group could run code as "
            f"whoever runs the scan; fix it with 'chmod go-w {path}'"
        )
    return None


def load_plugins(
    directories: Optional[Sequence[Path]] = None,
    include_builtin: bool = True,
) -> tuple:
    """Load every plugin found, returning ``(plugins, problems)``.

    Never raises. A directory that does not exist is skipped silently -- most
    people will not have one -- and anything that does exist but cannot be
    loaded is reported, because a plugin somebody wrote and that never ran is
    worse than no plugin at all.
    """
    search: List[Path] = []
    if directories is None:
        search = list(default_plugin_directories())
    else:
        if include_builtin:
            search.append(builtin_directory())
        search += [Path(directory) for directory in directories]

    plugins: List[Plugin] = []
    problems: List[str] = []
    seen_ids: Dict[str, str] = {}

    builtin = builtin_directory()
    for directory in search:
        if not directory.is_dir():
            continue
        # The permission guard applies to directories outside the package. It
        # would be theatre on the shipped one: that sits next to the modules
        # already being executed, so anyone who can write a plugin there can
        # write analysis.py instead. Applying it there would only mean a
        # developer's umask stops the tool loading its own detections.
        external = directory.resolve() != builtin.resolve()
        if external:
            refusal = _refuse_if_writable_by_others(directory)
            if refusal is not None:
                problems.append(f"{directory} {refusal}")
                continue
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            if external:
                refusal = _refuse_if_writable_by_others(path)
                if refusal is not None:
                    problems.append(f"{path} {refusal}")
                    continue
            try:
                plugin = _load_one(path)
            except PluginError as exc:
                problems.append(str(exc))
                continue
            previous = seen_ids.get(plugin.id)
            if previous is not None:
                problems.append(
                    f"{path}: id '{plugin.id}' is already defined by {previous}, so it "
                    "was not loaded; two detections with one identifier cannot both be "
                    "reported"
                )
                continue
            seen_ids[plugin.id] = str(path)
            plugins.append(plugin)
    return plugins, problems


def _load_one(path: Path) -> Plugin:
    """Import one file and turn it into a Plugin, or explain why not."""
    if not path.is_file():
        # glob('*.py') matches directories too. Letting one through produced
        # "failed to import: IsADirectoryError", which sends whoever reads it
        # looking for a mistake inside a file that is not a file.
        raise PluginError(f"{path}: is not a file, so it is not a plugin")

    module_name = f"_sshcc_plugin_{path.stem}_{abs(hash(str(path))) & 0xFFFFFF:x}"
    # A '.py' path that exists always yields a spec with a source loader; there
    # is no None case left to guard once the path is known to be a file.
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(cast(importlib.machinery.ModuleSpec, spec))
    # Made importable under its own name so a plugin can use dataclasses and
    # anything else that looks itself up in sys.modules.
    sys.modules[module_name] = module
    try:
        cast(Any, cast(Any, spec).loader).exec_module(module)
    except Exception as exc:  # any failure is the plugin's, not ours
        sys.modules.pop(module_name, None)
        raise PluginError(f"{path}: failed to import: {exc}") from exc

    missing = [
        field_name
        for field_name in ("ID", "NAME", "SEVERITY", "DESCRIPTION")
        if not getattr(module, field_name, None)
    ]
    if missing:
        raise PluginError(f"{path}: missing {', '.join(missing)}")

    check = getattr(module, "check", None)
    if not callable(check):
        raise PluginError(f"{path}: has no check(server) function")

    try:
        severity = Severity(str(module.SEVERITY).lower())
    except ValueError:
        valid = ", ".join(item.value for item in Severity)
        raise PluginError(
            f"{path}: SEVERITY {module.SEVERITY!r} is not one of {valid}"
        ) from None

    affects = str(getattr(module, "AFFECTS", "server")).lower()
    if affects not in {"server", "client"}:
        raise PluginError(f"{path}: AFFECTS must be 'server' or 'client', not {affects!r}")

    kind = str(getattr(module, "KIND", "vulnerability")).lower()
    if kind not in KINDS:
        raise PluginError(f"{path}: KIND must be one of {', '.join(KINDS)}, not {kind!r}")

    needs = [str(item) for item in getattr(module, "NEEDS", []) or []]
    unknown = [item for item in needs if item not in _AVAILABILITY]
    if unknown:
        raise PluginError(
            f"{path}: NEEDS names {', '.join(unknown)}, which is not collected; "
            f"valid entries are {', '.join(sorted(_AVAILABILITY))}"
        )

    return Plugin(
        id=str(module.ID),
        name=str(module.NAME),
        severity=severity,
        description=str(module.DESCRIPTION),
        remediation=str(getattr(module, "REMEDIATION", "")),
        references=[str(item) for item in getattr(module, "REFERENCES", []) or []],
        affects=affects,
        kind=kind,
        needs=needs,
        source=str(path),
        check=check,
    )
