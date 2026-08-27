"""SARIF 2.1.0 output, for tools that already consume static analysis results.

SARIF is what GitHub code scanning, Azure DevOps and several dashboards ingest,
so emitting it means a fleet audit lands in the same place as the rest of an
organisation's findings instead of needing its own viewer.

The mapping is deliberate. SARIF describes findings in files, and this tool
finds them on servers, so each scanned target becomes an artifact with an
``ssh://`` URI and each finding a result against it. Finding identifiers become
rule identifiers, which is what makes a result stable enough for a dashboard to
track across runs.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .. import PRODUCT_NAME
from ..models import ComplianceStatus, ScanReport, Severity
from ..policy import Policy
from .common import RenderOptions

__all__ = ["SARIF_VERSION", "build_document", "render"]

SARIF_VERSION = "2.1.0"
_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

#: SARIF has three levels plus "none"; this tool has five severities.
_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: A 0-1 score, so a consumer can rank within a level.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.5",
}


def _artifact_uri(result: Any) -> str:
    return f"ssh://{result.target.host}:{result.target.port}"


def build_document(report: ScanReport, policy: Policy) -> Dict[str, Any]:
    """Build the SARIF log as plain Python objects."""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    artifacts: List[Dict[str, Any]] = []

    for target_result in report.results:
        uri = _artifact_uri(target_result)
        artifacts.append(
            {
                "location": {"uri": uri},
                "description": {
                    "text": target_result.target.label
                    or (target_result.banner.software if target_result.banner else "SSH server")
                },
            }
        )

        for finding in target_result.findings:
            if finding.id not in rules:
                rules[finding.id] = {
                    "id": finding.id,
                    "name": finding.id.replace("-", " ").title().replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description or finding.title},
                    "help": {
                        "text": finding.remediation or "No remediation recorded.",
                        "markdown": f"**Fix:** {finding.remediation}"
                        if finding.remediation
                        else "No remediation recorded.",
                    },
                    "defaultConfiguration": {"level": _LEVELS[finding.severity]},
                    "properties": {
                        "security-severity": _SECURITY_SEVERITY[finding.severity],
                        "tags": ["security", "ssh"],
                    },
                }
                if finding.references:
                    rules[finding.id]["helpUri"] = next(
                        (r for r in finding.references if r.startswith("http")),
                        "",
                    ) or rules[finding.id].pop("helpUri", "")
                    if not rules[finding.id].get("helpUri"):
                        rules[finding.id].pop("helpUri", None)

            message = finding.title
            if finding.items:
                message += ": " + ", ".join(finding.items[:5])
            results.append(
                {
                    "ruleId": finding.id,
                    "level": _LEVELS[finding.severity],
                    "message": {"text": message},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                    ],
                    "partialFingerprints": {
                        # Stable across runs, so a dashboard can tell a
                        # recurring finding from a new one.
                        "sshCryptoChecker/v1": f"{uri}#{finding.id}"
                    },
                }
            )

        # Non-conformance as results, one rule per normativa, so a SARIF viewer
        # groups 'which servers fail ISO?' by ruleId natively.
        for entry in target_result.compliance:
            if entry.status is not ComplianceStatus.FAIL:
                continue
            rule_id = f"conformance/{entry.profile_id}"
            offenders = [v.subject for v in entry.violations]
            fixes = []
            for v in entry.violations:
                if v.remediation and v.remediation not in fixes:
                    fixes.append(v.remediation)
            if rule_id not in rules:
                help_text = (
                    "To comply: " + " ".join(fixes)
                    if fixes
                    else f"Bring the server's SSH cryptography into line with {entry.name}."
                )
                rules[rule_id] = {
                    "id": rule_id,
                    "name": entry.profile_id.replace("-", " ").title().replace(" ", ""),
                    "shortDescription": {"text": f"Conformance: {entry.name}"},
                    "fullDescription": {"text": entry.summary or entry.name},
                    "help": {"text": help_text},
                    "defaultConfiguration": {"level": "warning"},
                    "properties": {"tags": ["conformance", "ssh", entry.authority]},
                }
                if entry.url:
                    rules[rule_id]["helpUri"] = entry.url
            message = f"Does not conform to {entry.name}."
            if offenders:
                message += " Offending: " + ", ".join(offenders[:6]) + "."
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "warning",
                    "message": {"text": message},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                    ],
                    "partialFingerprints": {"sshCryptoChecker/v1": f"{uri}#{rule_id}"},
                }
            )

    return {
        "$schema": _SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": PRODUCT_NAME,
                        "version": report.version,
                        "informationUri": "https://github.com/CHANGEME/sshCryptoChecker",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": report.command_line,
                        "startTimeUtc": report.started_at,
                        "endTimeUtc": report.finished_at,
                    }
                ],
                "artifacts": artifacts,
                "results": results,
                "properties": {
                    "policy": report.policy.get("name", ""),
                    "policyVersion": report.policy.get("version", ""),
                    "targetsScanned": report.summary.total,
                    "targetsUnreachable": report.summary.failed,
                },
            }
        ],
    }


def render(report: ScanReport, policy: Policy, options: RenderOptions) -> str:
    """Serialise the report as a SARIF log."""
    del options
    return json.dumps(build_document(report, policy), indent=2, ensure_ascii=False) + "\n"
