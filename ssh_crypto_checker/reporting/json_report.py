"""Machine readable renderer.

The output is a stable, versioned document meant to be consumed by other tools:
dashboards, CI gates, configuration management, trend analysis. Every value the
scanner observed is present, including the raw algorithm lists, so a consumer
never has to re-scan to answer a follow-up question.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from ..models import ScanReport, to_jsonable
from ..policy import Policy
from .common import RenderOptions

__all__ = ["SCHEMA_VERSION", "build_document", "render"]

#: Bump the minor version for additive changes, the major for breaking ones.
SCHEMA_VERSION = "1.0"


def build_document(report: ScanReport, policy: Optional[Policy] = None) -> Dict[str, Any]:
    """Build the JSON document as plain Python objects.

    ``policy`` is accepted for interface symmetry with the other renderers; the
    policy metadata already travels inside ``report``.
    """
    del policy
    document: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": report.tool,
            "version": report.version,
            "command_line": report.command_line,
        },
        "scan": {
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "duration_ms": report.duration_ms,
        },
        "policy": to_jsonable(report.policy),
        "summary": to_jsonable(report.summary),
        "results": [_build_result(result) for result in report.results],
    }
    return document


def _build_result(result: Any) -> Dict[str, Any]:
    # to_jsonable devuelve Any porque su entrada es cualquier cosa; aqui la
    # entrada es un TargetResult y la salida es siempre un objeto.
    document: Dict[str, Any] = to_jsonable(result)
    # `target` is nested; flatten the parts a consumer filters on most often.
    target = document.get("target", {})
    document["target"] = {
        **target,
        "address": f"{target.get('host')}:{target.get('port')}",
    }
    return document


def render(report: ScanReport, policy: Policy, options: RenderOptions) -> str:
    """Serialise the report as indented JSON."""
    del options
    return json.dumps(
        build_document(report, policy), indent=2, ensure_ascii=False, sort_keys=False
    ) + "\n"
