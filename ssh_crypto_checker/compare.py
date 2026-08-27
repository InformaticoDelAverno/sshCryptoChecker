"""Comparison of a scan against an earlier one.

A single report says what a server looks like today. What an operator usually
needs to know is what changed: which findings appeared since the last audit,
which were fixed, and whether anything silently regressed after a package
upgrade or a configuration change nobody announced.

Comparison works on the JSON reports, so a baseline can be an artefact kept
from a previous CI run rather than something this tool has to store.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .i18n import DEFAULT_LANGUAGE, Translator
from .messages import MESSAGES
from .models import ScanReport, Severity, TargetResult

__all__ = ["Baseline", "Comparison", "TargetDrift", "compare", "load_baseline"]

#: English for callers that pass no translator (tests, machine-adjacent code).
_EN = Translator(DEFAULT_LANGUAGE, MESSAGES)


class BaselineError(Exception):
    """The baseline report could not be read."""


@dataclass
class Baseline:
    """An earlier report, reduced to what a comparison needs."""

    path: str
    finished_at: str = ""
    targets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    """Keyed by ``host:port``."""


@dataclass
class TargetDrift:
    """What changed for one server between the two scans."""

    target: str
    label: str = ""
    status: str = "unchanged"
    """``new``, ``gone``, ``changed`` or ``unchanged``."""
    previous_grade: Optional[str] = None
    current_grade: Optional[str] = None
    previous_score: Optional[int] = None
    current_score: Optional[int] = None
    new_findings: List[Tuple[str, str, str]] = field(default_factory=list)
    """``(id, severity, title)`` for findings that were not there before."""
    resolved_findings: List[Tuple[str, str, str]] = field(default_factory=list)
    algorithms_added: List[str] = field(default_factory=list)
    algorithms_removed: List[str] = field(default_factory=list)
    host_keys_changed: List[str] = field(default_factory=list)

    @property
    def improved(self) -> bool:
        if self.previous_score is None or self.current_score is None:
            return False
        return self.current_score > self.previous_score

    @property
    def regressed(self) -> bool:
        if self.previous_score is None or self.current_score is None:
            return bool(self.new_findings)
        return self.current_score < self.previous_score


@dataclass
class Comparison:
    """The full difference between a baseline and the current scan."""

    baseline_path: str = ""
    baseline_finished_at: str = ""
    drifts: List[TargetDrift] = field(default_factory=list)

    @property
    def changed(self) -> List[TargetDrift]:
        return [drift for drift in self.drifts if drift.status != "unchanged"]

    @property
    def regressions(self) -> List[TargetDrift]:
        return [drift for drift in self.drifts if drift.regressed]

    @property
    def has_changes(self) -> bool:
        return bool(self.changed)


def load_baseline(path: Path) -> Baseline:
    """Read a previous JSON report."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot read the baseline {path}: {exc}") from exc

    try:
        document = json.loads(text)
    except json.JSONDecodeError as first_error:
        # A history file holds one report per line, so its most recent entry is
        # the natural baseline and --compare should accept it without a flag.
        # Asked of the history module rather than parsed again here: what
        # counts as a recorded report is decided in one place.
        from .history import latest as latest_recorded  # local: history imports nothing here

        document = latest_recorded(Path(path))
        if document is None:
            raise BaselineError(f"{path} is not valid JSON: {first_error}") from first_error

    if not isinstance(document, dict) or "results" not in document:
        raise BaselineError(f"{path} does not look like a report from this tool")

    baseline = Baseline(
        path=str(path), finished_at=str(document.get("scan", {}).get("finished_at", ""))
    )
    for result in document.get("results") or []:
        target = result.get("target") or {}
        address = target.get("address") or f"{target.get('host')}:{target.get('port')}"
        baseline.targets[address] = result
    return baseline


def _findings_of(result: Any) -> Dict[str, Tuple[str, str, str]]:
    """Findings keyed by id, from either a live result or a baseline record."""
    findings = (
        result.findings if isinstance(result, TargetResult)
        else (result.get("findings") or [])
    )
    keyed = {}
    for finding in findings:
        if isinstance(finding, dict):
            identifier = str(finding.get("id", ""))
            severity = str(finding.get("severity", ""))
            title = str(finding.get("title", ""))
        else:
            identifier, severity, title = finding.id, finding.severity.value, finding.title
        if identifier:
            keyed[identifier] = (identifier, severity, title)
    return keyed


def _algorithms_of(result: Any) -> Dict[str, set]:
    """Offered algorithms per class, from either representation."""
    if isinstance(result, TargetResult):
        return {
            assessment.key: {a.name for a in assessment.algorithms}
            for assessment in result.assessments
        }
    return {
        assessment.get("key", ""): {a.get("name", "") for a in assessment.get("algorithms") or []}
        for assessment in result.get("assessments") or []
    }


def _host_keys_of(result: Any) -> Dict[str, str]:
    """Fingerprint per host key algorithm."""
    keys = result.host_keys if isinstance(result, TargetResult) else (result.get("host_keys") or [])
    mapping = {}
    for key in keys:
        if isinstance(key, dict):
            algorithm, fingerprint, error = (
                key.get("algorithm", ""),
                key.get("fingerprint_sha256", ""),
                key.get("error"),
            )
        else:
            algorithm, fingerprint, error = key.algorithm, key.fingerprint_sha256, key.error
        if error is None and fingerprint:
            mapping[algorithm] = fingerprint
    return mapping


def _grade_of(result: Any) -> Tuple[Optional[str], Optional[int]]:
    if isinstance(result, TargetResult):
        return result.grade, result.score
    return result.get("grade"), result.get("score")


def compare(report: ScanReport, baseline: Baseline) -> Comparison:
    """Difference the current scan against a baseline."""
    comparison = Comparison(
        baseline_path=baseline.path, baseline_finished_at=baseline.finished_at
    )
    seen = set()

    for result in report.results:
        address = f"{result.target.host}:{result.target.port}"
        seen.add(address)
        previous = baseline.targets.get(address)
        drift = TargetDrift(target=address, label=result.target.label or "")

        if previous is None:
            drift.status = "new"
            drift.current_grade, drift.current_score = _grade_of(result)
            comparison.drifts.append(drift)
            continue

        drift.previous_grade, drift.previous_score = _grade_of(previous)
        drift.current_grade, drift.current_score = _grade_of(result)

        before, after = _findings_of(previous), _findings_of(result)
        drift.new_findings = [after[k] for k in after.keys() - before.keys()]
        drift.resolved_findings = [before[k] for k in before.keys() - after.keys()]

        before_algorithms, after_algorithms = _algorithms_of(previous), _algorithms_of(result)
        for class_key in sorted(set(before_algorithms) | set(after_algorithms)):
            old = before_algorithms.get(class_key, set())
            new = after_algorithms.get(class_key, set())
            drift.algorithms_added += [f"{class_key}: {name}" for name in sorted(new - old)]
            drift.algorithms_removed += [f"{class_key}: {name}" for name in sorted(old - new)]

        before_keys, after_keys = _host_keys_of(previous), _host_keys_of(result)
        for algorithm, fingerprint in after_keys.items():
            recorded = before_keys.get(algorithm)
            if recorded is not None and recorded != fingerprint:
                drift.host_keys_changed.append(
                    f"{algorithm}: {recorded} -> {fingerprint}"
                )

        if any(
            (
                drift.new_findings,
                drift.resolved_findings,
                drift.algorithms_added,
                drift.algorithms_removed,
                drift.host_keys_changed,
                drift.previous_grade != drift.current_grade,
            )
        ):
            drift.status = "changed"
        comparison.drifts.append(drift)

    for address, previous in baseline.targets.items():
        if address in seen:
            continue
        drift = TargetDrift(target=address, status="gone")
        drift.previous_grade, drift.previous_score = _grade_of(previous)
        comparison.drifts.append(drift)

    # Sort so the interesting rows come first.
    order = {"changed": 0, "new": 1, "gone": 2, "unchanged": 3}
    comparison.drifts.sort(key=lambda d: (order[d.status], d.target))
    return comparison


def severity_rank(severity: str) -> int:
    try:
        return [s.value for s in Severity].index(severity)
    except ValueError:
        return len(Severity)


def summarise(comparison: Comparison, t: Optional[Translator] = None) -> List[str]:
    """Human-readable lines describing what changed.

    ``t`` picks the language; left out, the lines are English, which is what
    every existing caller (and test) without an opinion gets.
    """
    t = t or _EN
    if not comparison.has_changes:
        return [t("cmp.nothing")]

    lines = []
    for drift in comparison.changed:
        name = drift.label or drift.target
        if drift.status == "new":
            lines.append(t("cmp.new_target", name=name, grade=drift.current_grade or "-"))
            continue
        if drift.status == "gone":
            lines.append(t("cmp.gone", name=name))
            continue

        if drift.previous_grade != drift.current_grade:
            key = "cmp.grade_improved" if drift.improved else "cmp.grade_regressed"
            lines.append(t(key, name=name, a=drift.previous_grade, b=drift.current_grade))
        for _identifier, severity, title in sorted(
            drift.new_findings, key=lambda f: severity_rank(f[1])
        ):
            lines.append(t("cmp.new_finding", name=name, severity=severity, title=title))
        for _identifier, severity, title in sorted(
            drift.resolved_findings, key=lambda f: severity_rank(f[1])
        ):
            lines.append(t("cmp.fixed_finding", name=name, severity=severity, title=title))
        for change in drift.host_keys_changed:
            lines.append(t("cmp.host_key_changed", name=name, change=change))
        for item in drift.algorithms_added:
            lines.append(t("cmp.now_offers", name=name, item=item))
        for item in drift.algorithms_removed:
            lines.append(t("cmp.no_longer_offers", name=name, item=item))
    return lines
