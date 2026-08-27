"""Evaluation against published cryptographic standards.

Two distinct questions are answered here, and they must not be confused:

**How strong is this server?** Expressed as an effective security strength in
bits, per NIST SP 800-57 Part 1 Rev. 5. It is the weakest algorithm on offer,
because that is what an attacker can negotiate. The bands (high / moderate /
legacy / inadequate) are NIST security-strength bands. They are *not* FIPS 199
impact levels: FIPS 199 categorises a system by the consequences of its
compromise, which no network scan can determine.

**Does it conform to standard X?** Answered per profile, independently of this
tool's own opinion. A server can fail the local policy while passing a
baseline standard (NIST SP 800-131A still accepts HMAC-SHA-1, which this policy
rates weak) or pass the local policy while failing a stricter one (CNSA 2.0
rejects AES-128 outright).

On ISO: ISO/IEC 27001:2022 does not specify algorithms or strength levels.
Control A.8.24 requires that rules for the use of cryptography are defined and
implemented, so the ISO profile checks the server against the loaded policy
file, which *is* those documented rules. It reports enforcement evidence, not a
strength level and not a certification.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Sequence
from typing import Any, Dict, List, Optional

from .i18n import DEFAULT_LANGUAGE, Translator
from .messages import MESSAGES
from .models import (
    ALGORITHM_CLASSES,
    Category,
    ClassAssessment,
    ComplianceResult,
    ComplianceStatus,
    ComplianceViolation,
    HostKeyInfo,
    KexInit,
    PostQuantumStatus,
    SecurityStrength,
)
from .policy import ClassRule, Policy, Profile

__all__ = ["compute_security_strength", "evaluate_profiles"]

#: Violations are built during the scan, before the report language is known.
#: The English strings are rendered here so the machine formats (and any code
#: reading ``.reason``) keep working unchanged; the key+args travel alongside so
#: a human report can re-render them in its own language.
_EN = Translator(DEFAULT_LANGUAGE, MESSAGES)


def _violation(
    algorithm_class: str,
    subject: str,
    reason_key: str,
    reason_args: Dict[str, Any],
    remediation_key: str = "",
    remediation_args: Optional[Dict[str, Any]] = None,
    reason_override: str = "",
) -> ComplianceViolation:
    """Build a violation from message keys, rendering the English eagerly.

    ``reason_override`` is a profile's own free-text reason: it wins over the
    key, and no key is stored (a human report leaves that text as authored --
    profile prose is translated, if at all, through the policy overlay).
    """
    remediation_args = remediation_args or {}
    return ComplianceViolation(
        algorithm_class=algorithm_class,
        subject=subject,
        reason=reason_override or _EN(reason_key, **reason_args),
        remediation=_EN(remediation_key, **remediation_args) if remediation_key else "",
        reason_key="" if reason_override else reason_key,
        reason_args={} if reason_override else reason_args,
        remediation_key=remediation_key,
        remediation_args=remediation_args,
    )


def _matches_any(name: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


# --------------------------------------------------------------------------- #
# Security strength
# --------------------------------------------------------------------------- #


def _key_strength(policy: Policy, key: HostKeyInfo) -> Optional[int]:
    """Security strength of a retrieved host key.

    For RSA and DSA this follows from the modulus size; for the fixed-size
    algorithms the policy entry already carries the answer.
    """
    if key.error is not None or not key.bits:
        return None
    if key.key_family in {"rsa", "dsa"}:
        return policy.strength_for_modulus(key.bits)
    entry = policy.lookup("host_key", key.algorithm)
    if entry.security_strength_bits is not None:
        return entry.security_strength_bits
    return policy.strength_for_modulus(key.bits)


def compute_security_strength(
    policy: Policy,
    assessments: Sequence[ClassAssessment],
    host_keys: Sequence[HostKeyInfo],
) -> SecurityStrength:
    """Effective security strength of a server, and what holds it down."""
    strength = SecurityStrength(reference=policy.strength_reference)
    per_class: Dict[str, Optional[int]] = {}
    limiting: List[str] = []

    for assessment in assessments:
        rated = []
        for algorithm in assessment.algorithms:
            if not algorithm.category.is_scored:
                continue
            entry = policy.lookup(assessment.key, algorithm.name)
            if entry.security_strength_bits is not None:
                rated.append((entry.security_strength_bits, algorithm.name))
        per_class[assessment.key] = min(bits for bits, _ in rated) if rated else None

    # Host key algorithms whose strength depends on the key size are resolved
    # from the keys actually retrieved.
    key_strengths = [
        (bits, f"{key.algorithm} ({key.bits}-bit {key.key_family.upper()})")
        for key in host_keys
        for bits in (_key_strength(policy, key),)
        if bits is not None
    ]
    if key_strengths:
        weakest_key = min(bits for bits, _ in key_strengths)
        existing = per_class.get("host_key")
        per_class["host_key"] = (
            weakest_key if existing is None else min(existing, weakest_key)
        )

    # diffie-hellman-group-exchange-* has no fixed strength: it depends on the
    # modulus the server chooses. Use the size actually negotiated during the
    # host key probe when we have it.
    group_strengths = [
        (bits, f"{key.kex_used} ({key.dh_group_bits}-bit group)")
        for key in host_keys
        if key.dh_group_bits
        for bits in (policy.strength_for_modulus(key.dh_group_bits),)
        if bits is not None
    ]
    if group_strengths:
        weakest_group = min(bits for bits, _ in group_strengths)
        existing = per_class.get("kex")
        per_class["kex"] = (
            weakest_group if existing is None else min(existing, weakest_group)
        )

    strength.per_class = {key: per_class.get(key) for key in ALGORITHM_CLASSES}
    rated_classes = [bits for bits in per_class.values() if bits is not None]
    if not rated_classes:
        strength.level_id = "unknown"
        strength.level_label = "Unknown"
        strength.level_description = (
            "No offered algorithm has a security strength recorded in the policy."
        )
        return strength

    effective = min(rated_classes)
    strength.effective_bits = effective

    # Name everything sitting at the effective strength, so the number is
    # actionable rather than just a verdict.
    for assessment in assessments:
        for algorithm in assessment.algorithms:
            if not algorithm.category.is_scored:
                continue
            entry = policy.lookup(assessment.key, algorithm.name)
            if entry.security_strength_bits == effective:
                limiting.append(f"{algorithm.name} ({assessment.label.lower()})")
    limiting.extend(label for bits, label in key_strengths if bits == effective)
    limiting.extend(label for bits, label in group_strengths if bits == effective)
    strength.limiting = limiting

    level = policy.strength_level(effective)
    if level is not None:
        strength.level_id = level.id
        strength.level_label = level.label
        strength.level_description = level.description
    return strength


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #


#: The policy's mark for a name that is announced in an algorithm list but is
#: not an algorithm: ext-info-s, the strict-kex flags, kexguess2. A profile has
#: nothing to say about them, and reading the tag rather than a list of names
#: means a new one is a JSON edit.
_MARKER_TAG = "protocol-marker"


def _check_class_rules(
    policy: Policy, profile: Profile, kexinit: KexInit, strict_kex: bool
) -> List[ComplianceViolation]:
    violations: List[ComplianceViolation] = []
    for class_key, rule in profile.rules.items():
        label = policy.classes[class_key].label
        for name in kexinit.algorithms_for(class_key):
            if _MARKER_TAG in policy.lookup(class_key, name).tags:
                continue  # a signalling flag; nothing is negotiated with it
            violations.extend(_check_algorithm(class_key, label, name, rule, strict_kex))
    return violations


def _check_algorithm(
    class_key: str, label: str, name: str, rule: ClassRule, strict_kex: bool
) -> List[ComplianceViolation]:
    if (
        not strict_kex
        and rule.disallow_unless_strict_kex
        and _matches_any(name, rule.disallow_unless_strict_kex)
    ):
        # Why a baseline draws that line is the baseline's to say, so the profile's
        # own reason is what gets printed. This used to name one CVE in the code,
        # which put words in the mouth of every profile using the mechanism -- and
        # the only one that does gives a different reason entirely.
        detail = rule.reason or _EN("comp.reason.exclusion_lifts")
        return [
            _violation(
                class_key, name,
                "comp.reason.excluded_no_strict_kex", {"name": name, "detail": detail},
                "comp.remedy.excluded_no_strict_kex", {"name": name, "label": label.lower()},
            )
        ]
    if rule.disallow and _matches_any(name, rule.disallow):
        return [
            _violation(
                class_key, name,
                "comp.reason.disallowed", {"name": name, "label": label.lower()},
                "comp.remedy.disallowed", {"name": name, "label": label.lower()},
                reason_override=rule.reason,
            )
        ]
    if rule.allow and not _matches_any(name, rule.allow):
        return [
            _violation(
                class_key, name,
                "comp.reason.not_allowlisted", {"name": name, "label": label.lower()},
                "comp.remedy.not_allowlisted",
                {"label": label.lower(), "allowed": ", ".join(rule.allow)},
                reason_override=rule.reason,
            )
        ]
    return []


def _check_strength(
    policy: Policy, profile: Profile, strength: SecurityStrength
) -> List[ComplianceViolation]:
    minimum = profile.minimum_security_strength
    if minimum is None or strength.effective_bits is None:
        return []
    if strength.effective_bits >= minimum:
        return []
    subject = f"{strength.effective_bits}-bit effective security strength"
    if strength.limiting:
        limiting = ", ".join(strength.limiting[:4])
        return [
            _violation(
                "", subject,
                "comp.reason.strength_limited", {"minimum": minimum, "limiting": limiting},
                "comp.remedy.strength_limited", {"minimum": minimum, "limiting": limiting},
            )
        ]
    return [
        _violation(
            "", subject,
            "comp.reason.strength", {"minimum": minimum},
            "comp.remedy.strength", {"minimum": minimum},
        )
    ]


def _check_key_sizes(
    policy: Policy, profile: Profile, host_keys: Sequence[HostKeyInfo]
) -> List[ComplianceViolation]:
    violations = []
    for key in host_keys:
        if key.error is not None or not key.bits or not key.key_family:
            continue
        minimum = profile.minimum_key_bits.get(key.key_family.lower())
        if minimum is not None and key.bits < minimum:
            family = key.key_family.upper()
            violations.append(
                _violation(
                    "host_key",
                    f"{key.algorithm} ({family} {key.bits} bits)",
                    "comp.reason.key_size", {"minimum": minimum, "family": family},
                    "comp.remedy.key_size", {"minimum": minimum, "family": family},
                )
            )
    return violations


def _check_properties(
    profile: Profile, strict_kex: bool, post_quantum: PostQuantumStatus
) -> List[ComplianceViolation]:
    violations = []
    if profile.require_strict_kex and not strict_kex:
        violations.append(
            _violation(
                "kex", "strict key exchange",
                "comp.reason.strict_kex", {},
                "comp.remedy.strict_kex", {},
            )
        )
    if profile.require_post_quantum and post_quantum is PostQuantumStatus.NOT_READY:
        violations.append(
            _violation(
                "kex", "post-quantum key establishment",
                "comp.reason.post_quantum", {},
                "comp.remedy.post_quantum", {},
            )
        )
    return violations


def _check_local_policy(
    profile: Profile, assessments: Sequence[ClassAssessment]
) -> List[ComplianceViolation]:
    """Policy-conformance profiles measure against this file's own categories."""
    violations = []
    forbidden = set(profile.forbid_local_categories)
    for assessment in assessments:
        for algorithm in assessment.algorithms:
            if algorithm.category in forbidden:
                violations.append(
                    _violation(
                        assessment.key, algorithm.name,
                        "comp.reason.local_policy", {"category": algorithm.category.value},
                    )
                )
    return violations


def _unverified(
    policy: Policy,
    profile: Profile,
    kexinit: KexInit,
    host_keys: Sequence[HostKeyInfo],
    assessments: Sequence[ClassAssessment],
    strength: SecurityStrength,
    post_quantum: PostQuantumStatus,
) -> List[str]:
    """Requirements this profile makes that the scan could not actually test.

    Each one is a question the profile asks and this scan did not answer. They
    are kept apart from violations because they are not evidence of anything:
    the server may well conform. What they rule out is calling it a pass, and
    that is the whole point -- an unrun check that reads as conformance is
    worse than no check at all, because somebody acts on it.
    """
    reasons: List[str] = []

    if profile.minimum_key_bits and not any(
        key.error is None and key.bits for key in host_keys
    ):
        reasons.append(
            "requires host keys of a minimum size and no host key could be inspected"
        )

    if profile.minimum_security_strength is not None and strength.effective_bits is None:
        reasons.append(
            f"requires at least {profile.minimum_security_strength}-bit security strength "
            "and the strength of what this server offers could not be established"
        )

    if profile.require_post_quantum and post_quantum is PostQuantumStatus.UNKNOWN:
        reasons.append(
            "requires quantum-resistant key establishment and the key exchange offer "
            "could not be judged"
        )

    # An algorithm the policy has never seen is judged fine against an
    # allow-list -- not being on a closed list is provable from the name alone.
    # A disallow-list is the other way round: the name gives no way to tell
    # whether the vendor's own label is the forbidden algorithm underneath.
    for class_key, rule in profile.rules.items():
        if rule.allow or not (rule.disallow or rule.disallow_unless_strict_kex):
            continue
        unrecognised = [
            name
            for name in kexinit.algorithms_for(class_key)
            if policy.lookup(class_key, name).category is Category.UNKNOWN
        ]
        if unrecognised:
            reasons.append(
                f"forbids certain {policy.classes[class_key].label.lower()} algorithms and "
                f"the policy does not recognise {', '.join(sorted(unrecognised)[:3])}"
                + ("..." if len(unrecognised) > 3 else "")
            )

    # A policy-conformance profile asks whether anything falls in a forbidden
    # category. An algorithm with no category cannot answer that either way.
    if profile.kind == "policy-conformance":
        unknown = sorted(
            {
                algorithm.name
                for assessment in assessments
                for algorithm in assessment.algorithms
                if algorithm.category is Category.UNKNOWN
            }
        )
        if unknown:
            reasons.append(
                "measures against this policy's own categories and "
                f"{', '.join(unknown[:3])}"
                + ("..." if len(unknown) > 3 else "")
                + " has none"
            )

    return reasons


def evaluate_profiles(
    policy: Policy,
    assessments: Sequence[ClassAssessment],
    kexinit: KexInit,
    host_keys: Sequence[HostKeyInfo],
    strength: SecurityStrength,
    strict_kex: bool,
    post_quantum: PostQuantumStatus,
    only: Optional[Sequence[str]] = None,
) -> List[ComplianceResult]:
    """Evaluate the policy's profiles against one scanned server.

    ``only`` restricts the evaluation to the named profiles; the default is
    every profile the policy defines.
    """
    results = []
    # Without a selection, what is in force. With one, exactly what was asked
    # for -- which may name an edition that is not in force, and may name two
    # editions of the same standard, so the results are keyed by the selector
    # rather than by the standard.
    if only:
        # Resuelto una vez por selector: llamar dos veces al mismo resolutor
        # -- una para filtrar y otra para el valor -- dejaba el tipo como
        # "puede ser None" aunque el filtro dijese lo contrario.
        resolved = ((selector, policy.resolve_profile(selector)) for selector in only)
        chosen = {
            selector: profile for selector, profile in resolved if profile is not None
        }
        # Ordered by the policy, not by the flags. The report reads the same
        # however somebody wrote the command, and an edition sorts with the
        # standard it belongs to rather than wherever it was typed.
        order = list(policy.profiles)
        wanted = sorted(
            chosen.items(),
            key=lambda pair: (
                order.index(pair[1].id) if pair[1].id in order else len(order),
                pair[0],
            ),
        )
    else:
        wanted = [(profile_id, p) for profile_id, p in policy.profiles.items()]

    for selector, profile in wanted:
        result = ComplianceResult(
            profile_id=selector,
            name=profile.name,
            authority=profile.authority,
            reference=profile.reference,
            edition=profile.edition,
            url=profile.url,
            summary=profile.summary,
            notes=profile.notes,
            kind=profile.kind,
        )

        if profile.kind == "policy-conformance":
            result.violations = _check_local_policy(profile, assessments)
        else:
            result.violations = (
                _check_class_rules(policy, profile, kexinit, strict_kex)
                + _check_strength(policy, profile, strength)
                + _check_key_sizes(policy, profile, host_keys)
                + _check_properties(profile, strict_kex, post_quantum)
            )

        result.unverified = _unverified(
            policy, profile, kexinit, host_keys, assessments, strength, post_quantum
        )
        result.caveats = [profile.notes] if profile.notes else []

        # A violation is proof, so it outranks everything: finding one settles
        # the question even if something else could not be checked. Without a
        # violation the profile is only a pass when every requirement it makes
        # was actually tested -- a requirement nobody managed to check has not
        # been met, it has been skipped, and reporting the two the same way is
        # how a scanner ends up certifying a server it never understood.
        if result.violations:
            result.status = ComplianceStatus.FAIL
        elif result.unverified:
            result.status = ComplianceStatus.NOT_ASSESSED
        else:
            result.status = ComplianceStatus.PASS
        results.append(result)
    return results
