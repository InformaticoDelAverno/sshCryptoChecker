"""Report renderers.

Every renderer exposes ``render(report, policy, options) -> str`` so the CLI can
treat all output formats identically.
"""

from __future__ import annotations

from typing import Callable, Dict

from ..models import ScanReport
from ..policy import Policy
from .common import RenderOptions
from .console import render as render_console
from .csv_report import render as render_csv
from .html import render as render_html
from .inventory import render as render_inventory
from .json_report import render as render_json
from .openmetrics import render as render_openmetrics
from .sarif import render as render_sarif
from .text import render as render_text

__all__ = ["EXTENSIONS", "FORMATS", "RenderOptions", "render"]

Renderer = Callable[[ScanReport, Policy, RenderOptions], str]

#: Supported ``--format`` values.
FORMATS: Dict[str, Renderer] = {
    "console": render_console,
    "json": render_json,
    "txt": render_text,
    "html": render_html,
    "csv": render_csv,
    "sarif": render_sarif,
    "inventory": render_inventory,
    "openmetrics": render_openmetrics,
}

#: File extension used when several formats are written at once.
EXTENSIONS: Dict[str, str] = {
    "console": ".console.txt",
    "json": ".json",
    "txt": ".txt",
    "html": ".html",
    "csv": ".csv",
    "sarif": ".sarif.json",
    "inventory": ".inventory.md",
    "openmetrics": ".prom",
}


def render(
    output_format: str, report: ScanReport, policy: Policy, options: RenderOptions
) -> str:
    """Render ``report`` in the requested format."""
    try:
        renderer = FORMATS[output_format]
    except KeyError:
        valid = ", ".join(sorted(FORMATS))
        raise ValueError(f"unknown output format '{output_format}' (valid: {valid})") from None
    return renderer(report, policy, options)
