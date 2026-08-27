"""The assessment: what the observations mean under a policy.

Kept apart from the checks on purpose. Everything here turns what was seen
into what it is worth -- each algorithm classified, the security strength, the
score, the grade, the verdict -- and none of it is pluggable.

That is the boundary the whole plugin system rests on. Checks report; this
decides. A plugin that is absent, broken or written by somebody else adds or
removes findings from a report, and cannot move the number at the top of it.
Reproducing an audit therefore needs the policy file and nothing else.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    CATEGORY_ORDER,
    AlgorithmAssessment,
    Category,
    ClassAssessment,
    CompressionStatus,
    HostKeyInfo,
    KexInit,
    PostQuantumStatus,
    Recommendation,
    ScoreBreakdown,
    Severity,
    Verdict,
)
from .policy import Policy
from .ssh_protocol import STRICT_KEX_SERVER

__all__ = ["parse_version", "version_in_range"]

TAG_POST_QUANTUM = "post-quantum"
TAG_AEAD = "aead"
TAG_ETM = "etm"
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:p(\d+))?")

def parse_version(text: Optional[str]) -> Optional[Tuple[int, int, int, int]]:
    """Parse a version such as ``9.6p1`` into ``(major, minor, micro, portable)``."""
    if not text:
        return None
    match = _VERSION_RE.match(text.strip())
    if not match:
        return None
    major, minor, micro, portable = match.groups()
    return (int(major), int(minor), int(micro or 0), int(portable or 0))


def _version_lt(observed: Tuple[int, int, int, int], bound: Tuple[int, int, int, int]) -> bool:
    """``observed < bound``, treating an absent portable suffix as "same release".

    ``OpenSSH_9.8`` (the OpenBSD release) carries the same fixes as
    ``OpenSSH_9.8p1`` (the portable release), so it must not be reported as
    older than it.
    """
    if observed[:3] != bound[:3]:
        return observed[:3] < bound[:3]
    if observed[3] == 0 or bound[3] == 0:
        return False
    return observed[3] < bound[3]


def version_in_range(
    version: Optional[str], introduced: str, fixed: str
) -> bool:
    """Whether ``version`` falls in ``[introduced, fixed)``."""
    observed = parse_version(version)
    if observed is None:
        return False
    lower = parse_version(introduced) or (0, 0, 0, 0)
    if _version_lt(observed, lower):
        return False
    upper = parse_version(fixed)
    if upper is None:
        return True
    return _version_lt(observed, upper)




# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def _assess_class(policy: Policy, class_key: str, kexinit: KexInit) -> ClassAssessment:
    class_policy = policy.classes[class_key]
    assessment = ClassAssessment(
        key=class_key,
        label=class_policy.label,
        directions_differ=kexinit.directions_differ(class_key),
    )

    directions = _direction_map(kexinit, class_key)
    for name in kexinit.algorithms_for(class_key):
        entry = class_policy.lookup(name)
        assessment.algorithms.append(
            AlgorithmAssessment(
                name=name,
                category=entry.category,
                tags=list(entry.tags),
                notes=entry.notes,
                score=policy.category_score(entry.category),
                matched_by=entry.matched_by,
                directions=directions.get(name, []),
            )
        )

    # Negotiation picks the client's first choice that the server also has, so
    # a permissive client ends up with whatever the server listed first.
    offered = kexinit.algorithms_for(class_key)
    assessment.preferred = next(
        (name for name in offered if class_policy.lookup(name).category.is_scored), None
    )

    scored = [a for a in assessment.algorithms if a.category.is_scored and a.score is not None]
    if scored:
        assessment.score = min(int(a.score) for a in scored if a.score is not None)
        assessment.worst_category = max(
            (a.category for a in scored), key=CATEGORY_ORDER.index
        )
    return assessment


def _direction_map(kexinit: KexInit, class_key: str) -> Dict[str, List[str]]:
    """Which directions each algorithm was advertised in."""
    pairs = {
        "cipher": (kexinit.encryption_c2s, kexinit.encryption_s2c),
        "mac": (kexinit.mac_c2s, kexinit.mac_s2c),
        "compression": (kexinit.compression_c2s, kexinit.compression_s2c),
    }
    if class_key not in pairs:
        return {}
    c2s, s2c = pairs[class_key]
    mapping: Dict[str, List[str]] = {}
    for name in set(c2s) | set(s2c):
        directions = []
        if name in c2s:
            directions.append("client-to-server")
        if name in s2c:
            directions.append("server-to-client")
        mapping[name] = directions
    return mapping


# --------------------------------------------------------------------------- #
# Protocol-level checks
# --------------------------------------------------------------------------- #


def _detect_strict_kex(kexinit: KexInit) -> bool:
    return STRICT_KEX_SERVER in kexinit.kex_algorithms


def _post_quantum_status(
    kex_assessment: Optional[ClassAssessment],
) -> Tuple[PostQuantumStatus, List[str]]:
    if kex_assessment is None:
        return PostQuantumStatus.UNKNOWN, []
    scored = [a for a in kex_assessment.algorithms if a.category.is_scored]
    if not scored:
        return PostQuantumStatus.UNKNOWN, []
    post_quantum = [a.name for a in scored if TAG_POST_QUANTUM in a.tags]
    if not post_quantum:
        return PostQuantumStatus.NOT_READY, []
    if len(post_quantum) == len(scored):
        return PostQuantumStatus.ENFORCED, post_quantum
    return PostQuantumStatus.READY, post_quantum


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _compute_score(
    policy: Policy, assessments: Sequence[ClassAssessment], flags: Dict[str, bool]
) -> ScoreBreakdown:
    breakdown = ScoreBreakdown()
    weighted_total = 0.0
    total_weight = 0

    for assessment in assessments:
        weight = policy.class_weights.get(assessment.key, 0)
        breakdown.class_scores[assessment.key] = assessment.score
        breakdown.class_weights[assessment.key] = weight
        if assessment.score is None or weight <= 0:
            continue
        weighted_total += assessment.score * weight
        total_weight += weight

    breakdown.total_weight = total_weight
    if not total_weight:
        # Nothing the policy recognises: leave the score at zero but let the
        # caller detect this and refuse to publish a grade.
        breakdown.base_score = 0
        breakdown.final_score = 0
        return breakdown

    breakdown.base_score = round(weighted_total / total_weight)

    score = float(breakdown.base_score)
    for modifier_id, active in flags.items():
        if not active:
            continue
        modifier = policy.modifier(modifier_id)
        if modifier is None:
            continue
        score += modifier["points"]
        breakdown.modifiers.append(dict(modifier))

    breakdown.final_score = int(max(0, min(100, round(score))))
    return breakdown


@dataclass
class GradeCapFacts:
    """Everything a grade cap in the policy file is allowed to be keyed on."""

    worst_category: Optional[Category] = None
    host_key_below_minimum: bool = False
    vulnerabilities: Sequence[Any] = field(default_factory=tuple)
    changelog_read: bool = False
    """Whether the installed package's own changelog could be read.

    It is what turns a version match from a reason to go and look into a fact
    about this server. A changelog that was read and does not name a CVE is
    the package saying it never fixed it -- ``_apply_changelog`` has already
    downgraded the ones it does name.
    """


def _confirmed(facts: GradeCapFacts, *severities: Severity, measured_only: bool = False) -> bool:
    """Whether any vulnerability of these severities was actually established.

    ``measured_only`` leaves out the ones matched on the advertised version.
    Distributions patch without changing that string, so a version match is a
    reason to go and look rather than a fact about this server -- which is
    exactly why a policy might want to cap on one kind and not the other.

    One taken out of every count: a match the installed package's changelog
    names. The report already records those at informational severity with
    the changelog quoted, because the distribution says it dealt with them --
    and a match reported as informational must not be capping a grade as
    critical. The match keeps its own severity, which is what it would be
    without the changelog; this is the one place that difference matters.
    """
    return any(
        match.severity in severities
        and not match.undetermined
        and not match.distribution_patched
        and not (measured_only and match.version_based)
        for match in facts.vulnerabilities
    )


#: What a grade cap can be keyed on. There is one table, and the loader checks
#: a policy file against its keys when the file is read -- so a cap whose
#: condition is misspelled is refused there instead of quietly never firing,
#: which is a safety limit disappearing without a word.
_CAP_CONDITIONS = {
    "any_insecure_algorithm": lambda f: f.worst_category is Category.INSECURE,
    "any_weak_algorithm": lambda f: f.worst_category in {Category.WEAK, Category.INSECURE},
    "host_key_below_minimum": lambda f: f.host_key_below_minimum,
    "any_critical_vulnerability": lambda f: _confirmed(f, Severity.CRITICAL),
    "any_high_vulnerability": lambda f: _confirmed(f, Severity.CRITICAL, Severity.HIGH),
    "any_measured_critical_vulnerability": lambda f: _confirmed(
        f, Severity.CRITICAL, measured_only=True
    ),
    # The version match that stopped being only a version match. Every
    # version-based finding carries the caveat that distributions patch
    # without changing the number they advertise; the package's own changelog
    # is what settles it, and the ones it names have already been downgraded
    # out of this list. So a critical still standing after a changelog was
    # read is one the package does not claim to have fixed.
    #
    # Without --audit-config there is no changelog and no cap, which is not an
    # inconsistency: it is the tool declining to mark a server down on
    # evidence it calls inconclusive, and doing so when the evidence stops
    # being inconclusive.
    "any_critical_vulnerability_the_changelog_did_not_clear": lambda f: (
        f.changelog_read and _confirmed(f, Severity.CRITICAL)
    ),
}

#: The names a policy file may use. Read by the loader; see _CAP_CONDITIONS.
GRADE_CAP_CONDITIONS = frozenset(_CAP_CONDITIONS)


def _apply_grade_caps(
    policy: Policy, grade: str, facts: GradeCapFacts
) -> Tuple[str, List[str]]:
    applied: List[str] = []
    for cap in policy.grade_caps:
        # The name is checked when the policy is read, so it is in the table.
        if _CAP_CONDITIONS[cap["when"]](facts):
            capped = policy.cap_grade(grade, cap["max_grade"])
            if capped != grade:
                applied.append(f"{cap['when']} caps the grade at {cap['max_grade']}")
                grade = capped
    return grade, applied


def _verdict_for(
    worst_category: Optional[Category],
    strict_kex: bool,
    policy: Policy,
    undersized_key_material: bool = False,
    key_material_below_recommended: bool = False,
    serious_vulnerability: bool = False,
) -> Verdict:
    """Combine the algorithm categories with the facts measured on the wire.

    Key sizes are as much a part of the verdict as algorithm names: a perfect
    algorithm list in front of a 1024-bit host key still lets an attacker
    impersonate the server.

    So is a vulnerability the report itself is listing. Terrapin used to be
    the only one that counted here, named in this signature and nowhere else,
    and the result was that a server carrying a confirmed critical CVE could
    be summed up in the word "secure" -- while the page underneath it said
    otherwise. One special case became the rule it was an instance of, and
    then the special case went: Terrapin is a high-severity match, it arrives
    here as serious_vulnerability like every other one, and how much it weighs
    follows from its severity rather than from its name.
    """
    if worst_category is Category.INSECURE:
        return Verdict.INSECURE
    if (
        worst_category is Category.WEAK
        or undersized_key_material
        or serious_vulnerability
    ):
        return Verdict.WEAK
    if (
        worst_category is Category.RECOMMENDED
        and not key_material_below_recommended
        and (strict_kex or not policy.require_strict_kex)
    ):
        return Verdict.SECURE
    return Verdict.ACCEPTABLE


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def _build_recommendations(
    policy: Policy,
    kexinit: KexInit,
    assessments: Sequence[ClassAssessment],
    implicated: Optional[Dict[str, List[str]]] = None,
) -> List[Recommendation]:
    """Generate sshd_config directives that keep the server reachable.

    The suggested list is the policy's recommended algorithms intersected with
    what the server actually supports, so applying it cannot lock anyone out by
    naming an algorithm the build does not have.

    ``implicated`` maps an algorithm this server offers to the findings that
    name it as evidence. A suggested line that still contains one of those
    does not close that finding, and says so -- otherwise the tool hands
    somebody a block of configuration that looks like the fix and is not.

    This used to be written for Terrapin and only for Terrapin, keyed on a
    boolean with its name on it. The situation it describes is not special:
    any suggestion can carry an algorithm some finding names.
    """
    recommendations: List[Recommendation] = []

    for assessment in assessments:
        class_policy = policy.classes[assessment.key]
        directive = class_policy.sshd_config_directive
        if not directive or assessment.key == "compression":
            continue

        scored = [a for a in assessment.algorithms if a.category.is_scored]
        if not scored:
            continue
        if all(a.category is Category.RECOMMENDED for a in scored):
            continue

        offered = set(kexinit.algorithms_for(assessment.key))
        wanted = class_policy.suggested()
        preferred = [name for name in wanted if name in offered]

        if preferred:
            dropped = [a.name for a in scored if a.name not in preferred]
            comment = "Safe to apply now: every algorithm below is already supported here."
            if dropped:
                comment += (
                    " This removes " + ", ".join(dropped) + " -- check that no client still "
                    "depends on them."
                )
            missing = [name for name in wanted if name not in offered]
            if missing:
                comment += (
                    " Also recommended but not available on this server: "
                    + ", ".join(missing)
                    + "."
                )
        elif wanted:
            preferred = wanted
            comment = (
                "The server supports none of the recommended algorithms, so this line cannot be "
                "applied until it is upgraded. Applying it as-is would make the server "
                "unreachable."
            )
        else:
            continue

        still_named = sorted(
            {
                name: sorted(set(implicated[name]))
                for name in preferred
                if implicated and name in implicated
            }.items()
        )
        if still_named:
            citados = ", ".join(
                f"{name} ({', '.join(ids)})" for name, ids in still_named
            )
            comment += (
                " This line does not close every finding on this server: "
                + citados
                + ". Read those findings for what does -- usually an upgrade -- and"
                " drop the algorithm here only as a stop-gap."
            )

        recommendations.append(
            Recommendation(directive=directive, value=",".join(preferred), comment=comment)
        )

    compression = set(kexinit.compression_c2s) | set(kexinit.compression_s2c)
    if "zlib" in compression:
        recommendations.append(
            Recommendation(
                directive="Compression",
                value="no",
                comment=(
                    "The server accepts pre-authentication compression (zlib), which exposes the "
                    "decompressor to unauthenticated input. Use 'no', or 'delayed' if clients "
                    "need compression."
                ),
            )
        )

    host_key_recommendation = next(
        (r for r in recommendations if r.directive == "HostKeyAlgorithms"), None
    )
    if host_key_recommendation is not None:
        recommendations.append(
            Recommendation(
                directive="PubkeyAcceptedAlgorithms",
                value=host_key_recommendation.value,
                comment="Apply the same restriction to client public key authentication.",
            )
        )

    return recommendations


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #


def host_key_flags(
    policy: Policy, host_keys: Sequence[HostKeyInfo]
) -> Tuple[bool, bool, bool]:
    """Whether the key material is below minimum, below recommended, or the
    negotiated Diffie-Hellman group is too small.

    Pure arithmetic against the policy, and deliberately separate from the
    findings that report the same facts. The grade reads this; a plugin writes
    the report. Neither can move the other.
    """
    below_minimum = below_recommended = weak_dh = False
    for key in host_keys:
        if key.error is not None:
            continue
        requirement = policy.size_requirement(key.key_family)
        if requirement is not None and key.bits is not None:
            if key.bits < requirement.minimum_bits:
                below_minimum = True
            elif key.bits < requirement.recommended_bits:
                below_recommended = True
        if (
            key.dh_group_bits is not None
            and key.dh_group_bits < policy.dh_requirement.minimum_bits
        ):
            weak_dh = True
    return below_minimum, below_recommended, weak_dh


#: The tag the policy puts on a method that waits for authentication. Nothing
#: here knows the name of a single algorithm: adding a delayed method is
#: tagging it in algorithms.json, and an untagged one is treated as starting
#: early, because "it waits" is the claim that needs evidence.
_DELAYED_TAG = "post-auth"

#: The one name that is not an algorithm. Every class list carries it and it
#: means the same thing everywhere.
_NO_COMPRESSION = "none"


def compression_status(
    policy: Policy, assessment: Optional[ClassAssessment]
) -> CompressionStatus:
    """Whether the server will compress, and whether it can before login.

    The interesting question is not on or off. Compression that begins before
    authentication hands the decompressor to anyone who can open a connection;
    the same algorithm started afterwards does not, which is why OpenSSH
    replaced one with the other in 7.4.
    """
    if assessment is None or not assessment.algorithms:
        return CompressionStatus.UNKNOWN

    compressing = {a.name for a in assessment.algorithms} - {_NO_COMPRESSION}
    if not compressing:
        return CompressionStatus.DISABLED
    if any(_DELAYED_TAG not in policy.lookup("compression", n).tags for n in compressing):
        # One method that starts early is enough: the client gets to choose.
        return CompressionStatus.PRE_AUTH
    return CompressionStatus.POST_AUTH
