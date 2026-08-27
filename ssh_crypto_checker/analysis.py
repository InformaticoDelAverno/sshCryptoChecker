"""The orchestrator: what runs, in what order, and what is done with it.

This module decides nothing about a server. It builds the assessment, runs the
detections, collects what they said and asks the model for a grade. Every
judgement lives elsewhere:

* ``assessment.py``  classifies algorithms, measures strength, computes the
  score, the grade and the verdict. Not pluggable, deliberately.
* ``data/algorithms.json``  the algorithms, the thresholds, the vulnerability
  rules and the configuration expectations.
* ``plugins/builtin/``  the checks, one subject per file.

Order matters and is the one thing this file really enforces: the assessment
is built in full before any detection runs, because several of them read the
classification, the strict-kex flag or the post-quantum status. That is a
single, stated dependency -- "after the assessment" -- rather than a graph
between plugins, and it is why there is no dependency system to configure.

What is still emitted here is the vulnerability engine's own output: the
matches and the summary of what could not be settled. Those
are results of an engine, not judgements about a server, and there is nowhere
better for them to live.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Dict, List, Optional

from .assessment import (
    GradeCapFacts,
    _apply_grade_caps,
    _assess_class,
    _build_recommendations,
    _compute_score,
    _detect_strict_kex,
    _post_quantum_status,
    _verdict_for,
    compression_status,
    host_key_flags,
    parse_version,
    version_in_range,
)
from .compliance import compute_security_strength, evaluate_profiles
from .models import (
    ALGORITHM_CLASSES,
    CATEGORY_ORDER,
    SEVERITY_ORDER,
    Finding,
    PostQuantumStatus,
    Severity,
    TargetResult,
    Verdict,
)
from .plugins import ServerView as PluginView
from .plugins import builtin_plugins
from .plugins.runner import run as run_plugins
from .policy import Policy
from .vulnerabilities import evaluate as evaluate_vulnerabilities

__all__ = ["analyse", "parse_version", "version_in_range"]




# --------------------------------------------------------------------------- #
# Version handling
# --------------------------------------------------------------------------- #


def _apply_changelog(result: TargetResult) -> None:
    """Mark version-based matches the installed package says it fixed.

    A distribution changelog documents its own package's history, so a CVE
    named in it was dealt with in this revision or an earlier one. That is the
    answer to the caveat every version-based finding carries.

    Only version-based matches are touched, and deliberately so. A changelog
    cannot un-offer a CBC cipher: anything observed on the wire is what the
    server actually does, whatever the package notes say about it.
    """
    config = result.effective_config
    package = config.package if config is not None else None
    if package is None or not package.changelog_cves:
        return
    named = {identifier.upper() for identifier in package.changelog_cves}
    for match in result.vulnerabilities:
        if not match.version_based or match.undetermined:
            continue
        if match.id.upper() in named:
            match.distribution_patched = True
            match.changelog_source = package.changelog_source


def _vulnerability_findings(result: TargetResult) -> List[Finding]:
    """One finding per known vulnerability the server matches.

    The ones that could not be evaluated are gathered into a single finding
    rather than one each: a scan without --auth-methods and --audit-config
    cannot settle a good number of them, and a wall of identical notices would
    bury the ones that did match.
    """
    findings = []
    undetermined = [match for match in result.vulnerabilities if match.undetermined]
    for match in result.vulnerabilities:
        if match.undetermined:
            continue
        description = match.description
        if match.affects == "client":
            description += " This affects SSH clients rather than the server."
        if match.version_based and not match.distribution_patched:
            description += (
                " This was matched on the version string the server advertises; distributions "
                "routinely backport fixes without changing it, so confirm against the package "
                "changelog before acting."
            )
        severity = match.severity
        if match.distribution_patched:
            severity = Severity.INFO
            description += (
                f" The installed package's changelog ({match.changelog_source}) names this "
                "CVE, so the distribution states it addressed it in this revision or an "
                "earlier one. That is the distribution's claim rather than a verification of "
                "the running binary, but it is the same evidence a human would check, so the "
                "finding is recorded at informational severity instead of "
                f"{match.severity.value}."
            )
        findings.append(
            Finding(
                id=f"vuln-{match.id.lower()}",
                severity=severity,
                title=f"{match.id}: {match.name}",
                description=description,
                remediation=match.remediation,
                items=list(match.evidence),
                references=list(match.references),
            )
        )

    if undetermined:
        needed = sorted({item for match in undetermined for item in match.needs})
        findings.append(
            Finding(
                id="vulnerabilities-undetermined",
                severity=Severity.INFO,
                title=f"{len(undetermined)} vulnerability check(s) could not be completed",
                description=(
                    "These checks depend on information this scan did not collect, so the "
                    "server is neither confirmed affected nor confirmed clear. They are "
                    "listed because a check that was never run must not be mistaken for one "
                    "that came back clean."
                ),
                remediation="Re-run with: " + ", ".join(needed),
                items=[f"{match.id}: {match.name}" for match in undetermined],
            )
        )
    return findings






# --------------------------------------------------------------------------- #
# Recommendations
# --------------------------------------------------------------------------- #


def _implicated_algorithms(result: TargetResult) -> Dict[str, List[str]]:
    """Que algoritmo nombra cada hallazgo confirmado como evidencia.

    Una linea sugerida de sshd_config que sigue conteniendo uno de ellos no
    cierra ese hallazgo, y quien la aplique creera que si. La evidencia de una
    coincidencia es texto libre -- a veces "aes128-cbc", a veces
    "aes128-cbc (server-to-client)" -- asi que se busca el nombre dentro.
    """
    implicated: Dict[str, List[str]] = {}
    offered = {
        name
        for assessment in result.assessments
        for name in (algorithm.name for algorithm in assessment.algorithms)
    }
    for match in result.vulnerabilities:
        if match.undetermined:
            continue
        for item in match.evidence:
            for name in offered:
                if name in item:
                    implicated.setdefault(name, []).append(match.id)
    return implicated


def analyse(
    result: TargetResult,
    policy: Policy,
    now: Optional[float] = None,
    profiles: Optional[Sequence[str]] = None,
    plugins: Optional[Sequence[Any]] = None,
) -> TargetResult:
    """Fill in the assessment fields of a scanned target, in place."""
    kexinit = result.kexinit
    if not result.ok or kexinit is None:
        result.verdict = Verdict.ERROR
        return result

    result.assessments = [_assess_class(policy, key, kexinit) for key in ALGORITHM_CLASSES]

    result.security_strength = compute_security_strength(
        policy, result.assessments, result.host_keys
    )
    result.strict_kex = _detect_strict_kex(kexinit)
    result.compression = compression_status(policy, result.assessment("compression"))

    # Vulnerability detection is entirely policy-driven, including Terrapin:
    # adding a new one is editing algorithms.json, not this file.
    result.vulnerabilities = evaluate_vulnerabilities(
        policy,
        kexinit,
        result.banner,
        result.host_keys,
        auth_methods=result.auth_methods,
        effective_config=result.effective_config,
    )
    _apply_changelog(result)

    kex_assessment = result.assessment("kex")
    result.post_quantum, _pq_algorithms = _post_quantum_status(kex_assessment)

    # Plugins run once the model is complete. Several of them read the
    # classification, the strict-kex flag or the post-quantum status, and a
    # check that ran before those were computed would quietly see nothing.
    # This is the orchestrator's job: there is no dependency graph because
    # there is only one dependency, and it is "after the assessment".
    # Cleared first: analysing a result twice must give the same answer as
    # analysing it once, and leaving the previous run's plugin findings in
    # place would quietly add them again.
    result.plugin_findings = []

    # None means "the tool's own detections"; an explicit empty list means
    # none, which is what a test isolating one plugin wants.
    if plugins is None:
        plugins = builtin_plugins()
    if plugins:
        matches, plugin_findings = run_plugins(
            plugins,
            PluginView(
                banner=result.banner,
                kexinit=kexinit,
                host_keys=result.host_keys,
                auth_methods=result.auth_methods,
                config=result.effective_config,
                client_config=result.client_config,
                assessments=result.assessments,
                strict_kex=result.strict_kex,
                post_quantum=result.post_quantum,
                dh_group_bits=next(
                    (k.dh_group_bits for k in result.host_keys if k.dh_group_bits), None
                ),
                sshfp=result.sshfp,
                known_hosts=result.known_hosts,
                login_grace_seconds=result.login_grace_seconds,
                max_startups=result.max_startups,
                max_startups_probe_limit=result.max_startups_probe_limit or 0,
                policy=policy,
            ),
        )
        result.vulnerabilities.extend(matches)
        result.plugin_findings = plugin_findings

    result.compliance = evaluate_profiles(
        policy,
        result.assessments,
        kexinit,
        result.host_keys,
        result.security_strength,
        result.strict_kex,
        result.post_quantum,
        profiles,
    )

    below_minimum, below_recommended, weak_dh = host_key_flags(policy, result.host_keys)

    # Terrapin no lleva un hallazgo escrito a mano. Lo llevaba, y salia dos
    # veces: este y el de CVE-2023-48795 que produce la politica, con la misma
    # severidad y la misma evidencia. Un servidor con un problema parecia
    # tener dos, y ninguna otra vulnerabilidad recibia ese trato. La
    # deteccion, la descripcion y la remediacion viven en el fichero de
    # politica como las otras sesenta y cuatro.
    findings: List[Finding] = []
    findings.extend(_vulnerability_findings(result))
    findings.extend(result.plugin_findings)

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    result.findings = findings

    flags = {
        "missing_strict_kex": not result.strict_kex and policy.require_strict_kex,
        "no_post_quantum_kex": result.post_quantum is PostQuantumStatus.NOT_READY,
        "host_key_below_minimum": below_minimum,
        "host_key_below_recommended": below_recommended,
        "dh_group_below_minimum": weak_dh,
    }
    breakdown = _compute_score(policy, result.assessments, flags)
    result.score_breakdown = breakdown

    if not breakdown.total_weight:
        # Nothing at all could be classified. Publishing a grade here would be
        # an invention: "F" would read as insecure, "A" as safe, and neither is
        # supported by evidence.
        result.score = None
        result.grade = None
        result.verdict = Verdict.UNKNOWN
        result.recommendations = _build_recommendations(
            policy, kexinit, result.assessments, _implicated_algorithms(result)
        )
        return result

    scored_categories = [a.worst_category for a in result.assessments if a.worst_category]
    worst_category = (
        max(scored_categories, key=CATEGORY_ORDER.index) if scored_categories else None
    )

    # "Host keys are fine" must mean at least one was actually inspected. When
    # retrieval was skipped or failed, the requirement is unmet rather than
    # vacuously true, so the top grade cannot be awarded on an unrun check.
    verified_keys = [key for key in result.host_keys if key.error is None and key.bits]
    capabilities = {
        "strict_kex": result.strict_kex,
        "post_quantum": result.post_quantum
        in {PostQuantumStatus.READY, PostQuantumStatus.ENFORCED},
        "host_keys_ok": bool(verified_keys) and not below_minimum and not below_recommended,
    }
    grade = policy.grade_for(breakdown.final_score, capabilities)
    grade, applied_caps = _apply_grade_caps(
        policy,
        grade,
        GradeCapFacts(
            worst_category=worst_category,
            host_key_below_minimum=below_minimum,
            vulnerabilities=result.vulnerabilities,
            changelog_read=bool(
                result.effective_config is not None
                and result.effective_config.package is not None
                and result.effective_config.package.changelog_read
            ),
        ),
    )
    breakdown.applied_caps = applied_caps

    result.score = breakdown.final_score
    result.grade = grade
    # A vulnerability the report is listing counts towards the word at the top
    # of it. Undetermined ones do not: "we could not tell" is not a finding.
    serious = any(
        match.severity in {Severity.CRITICAL, Severity.HIGH} and not match.undetermined
        for match in result.vulnerabilities
    )
    result.verdict = _verdict_for(
        worst_category,
        result.strict_kex,
        policy,
        undersized_key_material=below_minimum or weak_dh,
        key_material_below_recommended=below_recommended,
        serious_vulnerability=serious,
    )
    result.recommendations = _build_recommendations(
        policy, kexinit, result.assessments, _implicated_algorithms(result)
    )
    return result
