"""An append-only record of past scans.

``--compare`` answers "what changed since that report". What it cannot answer
is "when did this start", because a single baseline file is a single point.
Keeping every scan in one file turns the same data into a series, without
running a service to hold it: a scan appends one line, and the line is a
complete report, so any of them can serve as a baseline later.

JSON Lines rather than a JSON array, because appending to an array means
rewriting the file, and a scan interrupted half way through that leaves no
history at all.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .i18n import DEFAULT_LANGUAGE, Translator
from .messages import MESSAGES

__all__ = ["Entry", "HistoryError", "append", "latest", "read", "summarise"]

#: English for callers that pass no translator.
_EN = Translator(DEFAULT_LANGUAGE, MESSAGES)


class HistoryError(Exception):
    """The history file could not be read or written."""


@dataclass
class Entry:
    """One recorded scan, reduced to what a trend needs."""

    finished_at: str
    targets: int
    reachable: int
    average_score: Optional[float]
    grades: Dict[str, int]
    vulnerable: int
    by_severity: Dict[str, int]

    @property
    def worst_grade(self) -> str:
        return sorted(self.grades)[-1] if self.grades else "-"


def append(path: Path, document: Dict[str, Any]) -> None:
    """Add one report to the history.

    Opened in append mode so that two scans finishing at once interleave
    whole lines rather than corrupting each other, which is what a
    read-modify-write would do.
    """
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n")
    except OSError as exc:
        raise HistoryError(f"cannot write the history file {path}: {exc}") from exc


def read(path: Path) -> List[Dict[str, Any]]:
    """Every report in the file, oldest first.

    A line that will not parse is skipped rather than fatal: a history is
    written over months, and one truncated write should not make the rest
    unreadable.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise HistoryError(f"cannot read the history file {path}: {exc}") from exc

    documents = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(document, dict) and "results" in document:
            documents.append(document)
    return documents


def latest(path: Path) -> Optional[Dict[str, Any]]:
    """The most recent report in the file."""
    documents = read(path)
    return documents[-1] if documents else None


def _entry(document: Dict[str, Any]) -> Entry:
    scan = document.get("scan") or {}
    summary = document.get("summary") or {}
    return Entry(
        finished_at=str(scan.get("finished_at", "")),
        targets=int(summary.get("total", 0)),
        reachable=int(summary.get("succeeded", 0)),
        average_score=summary.get("average_score"),
        grades=dict(summary.get("by_grade") or {}),
        vulnerable=int(summary.get("vulnerable", 0)),
        by_severity=dict(summary.get("by_severity") or {}),
    )


def summarise(path: Path, limit: int = 10, t: Optional[Translator] = None) -> List[str]:
    """A short table of how the estate has moved, most recent last.

    ``t`` picks the language of the header and footer; the rows are numbers.
    """
    t = t or _EN
    documents = read(path)
    if not documents:
        return [t("his.empty")]

    entries = [_entry(document) for document in documents][-limit:]
    lines = [
        f"{t('his.hdr_scanned'):<26} {t('his.hdr_hosts'):>6} {t('his.hdr_avg'):>6} "
        f"{t('his.hdr_worst'):>6} "
        f"{t('his.hdr_vuln'):>5} {t('his.hdr_crit'):>5} {t('his.hdr_high'):>5}",
    ]
    for entry in entries:
        average = "-" if entry.average_score is None else f"{entry.average_score:.1f}"
        lines.append(
            f"{entry.finished_at[:25]:<26} "
            f"{entry.reachable}/{entry.targets:<4} "
            f"{average:>6} "
            # The average hides the one server that is bad: an estate can drift
            # from a fleet of B's to mostly A's and one F without the mean
            # moving much, and the F is the whole story.
            f"{entry.worst_grade:>6} "
            f"{entry.vulnerable:>5} "
            f"{entry.by_severity.get('critical', 0):>5} "
            f"{entry.by_severity.get('high', 0):>5}"
        )
    if len(documents) > limit:
        lines.append(t("his.more", n=len(documents), limit=limit))
    return lines
