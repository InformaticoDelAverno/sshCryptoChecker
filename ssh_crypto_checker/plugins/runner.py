"""Running plugins and turning what they return into results.

Kept apart from the plugin API on purpose. ``plugins/__init__.py`` defines what
a plugin *is* -- the metadata, the return types, the view it gets -- and knows
nothing about findings, vulnerabilities or reports. This module is the one that
knows how a plugin's answer becomes something the rest of the tool understands.

The split is what lets a plugin be written against a small, stable surface
while the result types move underneath it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Dict, List, Optional, Tuple

from ..models import Finding, Severity
from . import Detected, FleetView, ForTarget, Plugin, ServerView, Undetermined

__all__ = ["run", "run_fleet"]


def _severity(requested: Optional[str], fallback: Severity, notes: List[str]) -> Severity:
    """Resolve a severity a plugin asked for, saying so when it makes no sense."""
    if not requested:
        return fallback
    try:
        return Severity(str(requested).lower())
    except ValueError:
        notes.append(
            f"(the plugin asked for severity {requested!r}, which is not a severity, "
            "so its declared one was used)"
        )
        return fallback


def _reportable(value: Any) -> str:
    """Text a report can hold, whatever the plugin left in the field.

    Every writer joins these fields into a document of some kind, and each one
    joins a different subset: bytes in ``items`` ended the run in CSV and
    SARIF, bytes in ``references`` in four other formats, and bytes in ``id``
    in four again. Which ``--format`` was asked for decided whether a finished
    scan survived being written down.

    Hex rather than repr, because that is what the JSON writer already does
    with bytes and a fingerprint is what bytes in a finding would be.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if value is None:
        return ""
    return str(value)


def _reportable_list(value: Any) -> List[str]:
    """The same for a field a report iterates over."""
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray)):
        # One string is not a list of one-character strings.
        return [_reportable(value)]
    try:
        return [_reportable(item) for item in value]
    except TypeError:
        return [_reportable(value)]


def _reportable_finding(finding: Finding, plugin: Plugin) -> Finding:
    """Force a plugin-built Finding into the shape a report can hold.

    A plugin's declared SEVERITY is checked when it loads. A Finding built
    inside check() is not: the plugin fills every field itself, at the moment
    it fires, which is when nobody is watching. Anything that is not a
    Severity used to reach the report and take the whole target down with it
    -- sorting findings by severity raised 'x not in list', the scan pool
    caught it, and a reachable server came out UNREACHABLE because of a
    plugin. The text fields do the same thing one step later, in the writer,
    where nothing catches it and the whole scan is lost rather than one target.

    That is the boundary this package draws everywhere else: a plugin reports
    observations and can never decide what a server scores, nor whether the
    report gets written.
    """
    notes: List[str] = []
    if not isinstance(finding.severity, Severity):
        finding.severity = _severity(finding.severity, plugin.severity, notes)
    finding.id = _reportable(finding.id)
    finding.title = _reportable(finding.title)
    finding.description = _reportable(finding.description)
    finding.remediation = _reportable(finding.remediation)
    finding.items = _reportable_list(finding.items) + notes
    finding.references = _reportable_list(finding.references)
    return finding


def _outcomes(returned: Any) -> List[Any]:
    """Normalise what a plugin returned into a list of outcomes."""
    if returned is None or returned is False:
        return []
    if returned is True:
        return [Detected()]
    if isinstance(returned, (list, tuple)):
        return [item for item in returned if item is not None and item is not False]
    return [returned]


def run(
    plugins: Sequence[Plugin], view: ServerView
) -> Tuple[List[Any], List[Finding]]:
    """Run every plugin, returning ``(vulnerability matches, findings)``.

    Nothing a plugin does ends a scan. An exception becomes a result naming the
    plugin, the same way a malformed rule in the policy file does: a detection
    that broke is worth knowing about, and it is not worth an audit.
    """
    from ..vulnerabilities import VulnerabilityMatch

    matches: List[Any] = []
    findings: List[Finding] = []

    for plugin in plugins:
        if plugin.kind == "fleet":
            # Run once at the end, over everything, not once per server.
            continue
        missing = plugin.missing(view)
        if missing:
            matches.append(_undetermined(plugin, missing, VulnerabilityMatch))
            continue

        try:
            returned = plugin.check(view)
        except Exception as exc:  # a plugin must not end a scan
            # Reported where the plugin's own results would have gone, so a
            # check that broke is looked for in the same place as a check that
            # worked rather than turning up among the vulnerabilities.
            if plugin.kind == "check":
                findings.append(_broke_finding(plugin, exc))
            else:
                matches.append(_broke(plugin, exc, VulnerabilityMatch))
            continue

        for outcome in _outcomes(returned):
            # A check may hand back a Finding outright. Detected fills in the
            # module's metadata for the common case; a plugin reporting several
            # unrelated things says all of it itself, and this keeps the two
            # from being different mechanisms.
            if isinstance(outcome, Finding):
                findings.append(_reportable_finding(outcome, plugin))
            elif isinstance(outcome, Undetermined):
                matches.append(
                    _undetermined(
                        plugin,
                        list(outcome.needs) or ["information this scan did not collect"],
                        VulnerabilityMatch,
                    )
                )
            elif plugin.kind == "check":
                findings.append(_finding(plugin, outcome))
            else:
                matches.append(_match(plugin, outcome, VulnerabilityMatch))

    return matches, findings


def _detail(plugin: Plugin, outcome: Any) -> Tuple[str, str, str, str, List[str], List[str]]:
    """The plugin's metadata, with anything the outcome overrode."""
    detected = outcome if isinstance(outcome, Detected) else Detected()
    notes: List[str] = []
    evidence = _reportable_list(detected.evidence)
    description = detected.description or plugin.description
    if detected.note:
        description = f"{_reportable(description)} {_reportable(detected.note)}"
    return (
        _reportable(detected.id or plugin.id),
        _reportable(detected.name or plugin.name),
        _reportable(description),
        _reportable(detected.remediation or plugin.remediation),
        _reportable_list(detected.references) or _reportable_list(plugin.references),
        evidence + notes,
    )


def _match(plugin: Plugin, outcome: Any, cls: Any) -> Any:
    identifier, name, description, remediation, references, evidence = _detail(plugin, outcome)
    notes: List[str] = []
    severity = _severity(
        getattr(outcome, "severity", None) if isinstance(outcome, Detected) else None,
        plugin.severity,
        notes,
    )
    return cls(
        id=identifier,
        name=name,
        severity=severity,
        description=description,
        remediation=remediation,
        references=references,
        affects=plugin.affects,
        source=f"plugin:{plugin.source}",
        evidence=evidence + notes,
    )


def _finding(plugin: Plugin, outcome: Any) -> Finding:
    identifier, name, description, remediation, references, evidence = _detail(plugin, outcome)
    notes: List[str] = []
    severity = _severity(
        getattr(outcome, "severity", None) if isinstance(outcome, Detected) else None,
        plugin.severity,
        notes,
    )
    return Finding(
        id=identifier,
        severity=severity,
        title=name,
        description=description,
        remediation=remediation,
        items=evidence + notes,
        references=references,
    )


_BROKEN_DESCRIPTION = (
    "This detection could not be run because the plugin raised an exception. Nothing is "
    "claimed about the server either way."
)


def _broke_finding(plugin: Plugin, exc: BaseException) -> Finding:
    return Finding(
        id=f"{plugin.id}-plugin-failed",
        severity=Severity.INFO,
        title=f"The '{plugin.id}' check could not be run",
        description=_BROKEN_DESCRIPTION,
        remediation=f"Fix the plugin at {plugin.source}.",
        items=[f"{type(exc).__name__}: {exc}"],
    )


def _undetermined(plugin: Plugin, needs: List[str], cls: Any) -> Any:
    return cls(
        id=plugin.id,
        name=plugin.name,
        severity=Severity.INFO,
        description=plugin.description,
        remediation=plugin.remediation,
        references=list(plugin.references),
        affects=plugin.affects,
        source=f"plugin:{plugin.source}",
        undetermined=True,
        needs=list(needs),
    )


def _broke(plugin: Plugin, exc: BaseException, cls: Any) -> Any:
    return cls(
        id=plugin.id,
        name=plugin.name,
        severity=Severity.INFO,
        description=_BROKEN_DESCRIPTION,
        remediation=f"Fix the plugin at {plugin.source}.",
        references=list(plugin.references),
        affects=plugin.affects,
        source=f"plugin:{plugin.source}",
        evidence=[f"{type(exc).__name__}: {exc}"],
    )


def run_fleet(plugins: Sequence[Plugin], fleet: FleetView) -> Dict[str, List[Finding]]:
    """Run the fleet checks, returning findings keyed by target.

    Separate from ``run`` because it happens at a different time: after every
    server, once, over all of them. Mixing the two would mean either running a
    fleet check per target and discarding all but the last, or holding back
    every per-server check until the scan finished.
    """
    by_target: Dict[str, List[Finding]] = {}
    known = {server.target for server in fleet.servers}

    for plugin in plugins:
        if plugin.kind != "fleet":
            continue
        try:
            returned = plugin.check(fleet)
        except Exception as exc:
            # Nowhere better to put it: the failure is about the scan, not one
            # server, so it goes to the first one rather than being lost.
            if fleet.servers:
                by_target.setdefault(fleet.servers[0].target, []).append(
                    _broke_finding(plugin, exc)
                )
            continue

        for outcome in _outcomes(returned):
            if not isinstance(outcome, ForTarget):
                continue
            if outcome.target not in known:
                # A fleet check naming a server the scan never produced is a
                # bug in the plugin; dropping it beats inventing a target.
                continue
            # The same boundary as the per-server path. It was missing here,
            # and a fleet check that built its own Finding could put anything
            # in it: a severity that is not one reached summarise() as a
            # string and ended the run with an AttributeError, losing every
            # target rather than one.
            finding = (
                _reportable_finding(outcome.finding, plugin)
                if isinstance(outcome.finding, Finding)
                else _finding(plugin, outcome.finding)
            )
            by_target.setdefault(outcome.target, []).append(finding)
    return by_target
