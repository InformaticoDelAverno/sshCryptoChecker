"""Detection of known SSH vulnerabilities, driven entirely by the policy file.

A new vulnerability must be addable by editing JSON, never by editing Python.
So a vulnerability declares *what makes a server affected* as a small condition
tree, and this module evaluates it:

.. code-block:: json

    {
      "id": "CVE-2023-48795",
      "name": "Terrapin",
      "severity": "high",
      "detection": {
        "all": [
          { "absent": { "class": "kex", "algorithms": ["kex-strict-s-v00@openssh.com"] } },
          { "any": [
              { "present": { "class": "cipher", "tags": ["terrapin-vector"] } },
              { "all": [
                  { "present": { "class": "cipher", "tags": ["cbc"] } },
                  { "present": { "class": "mac", "tags": ["etm"] } }
              ]}
          ]}
        ]
      }
    }

Conditions
----------

``present`` / ``absent``
    Match algorithms the server offers, by exact name or by policy tag. Naming
    a tag rather than an algorithm is preferred: it keeps working when a new
    cipher of the same shape appears.
``version``
    The advertised software falls in a ``[introduced, fixed)`` window.
``host_key``
    A retrieved host key matches a family and is below a size.
``protocol``
    The protocol version in the banner, which is how a server that still
    speaks SSH-1 announces itself.
``auth_method``
    An authentication method the server offers. Needs ``--auth-methods``.
``extension``
    An RFC 8308 extension the server advertises. Needs ``--auth-methods``.
``config``
    A directive from the server's own configuration. Needs ``--audit-config``.
``all`` / ``any`` / ``not``
    Combine the above.

Every match records the evidence that produced it, so a report can say which
algorithm or version made the server affected rather than only naming a CVE.

Not looking is not the same as looking and finding nothing. A rule that needs
data the scan did not collect -- authentication methods, the effective
configuration -- does not quietly evaluate to false; it marks the
vulnerability *undetermined*, and the report says which flag would settle it.
Silently reporting a server as unaffected because nobody asked the question is
the one failure mode this module must not have.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, cast

from .models import ALGORITHM_CLASSES, BannerInfo, HostKeyInfo, KexInit, Severity

__all__ = ["DetectionError", "Vulnerability", "VulnerabilityMatch", "evaluate", "parse_condition"]

#: Condition keys that take a list of sub-conditions.
_COMBINATORS = {"all", "any"}
#: Every key a condition may use, so a typo is an error rather than a silent
#: condition that never matches. Filled in from _EVALUATORS below, which is
#: defined after the functions it names.
_CONDITION_KEYS: frozenset = frozenset()


class DetectionError(Exception):
    """A vulnerability's detection rule is malformed."""


@dataclass(frozen=True)
class Vulnerability:
    """One known vulnerability and how to recognise it."""

    id: str
    name: str
    severity: Severity
    description: str
    remediation: str = ""
    references: Tuple[str, ...] = ()
    detection: Optional[Dict[str, Any]] = None
    affects: str = "server"
    """``server`` or ``client``; client-side issues are reported for awareness."""


@dataclass
class VulnerabilityMatch:
    """A vulnerability the scanned server appears to be affected by."""

    id: str
    name: str
    severity: Severity
    description: str
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    affects: str = "server"
    evidence: List[str] = field(default_factory=list)
    """What made the server match, so the finding is actionable."""
    version_based: bool = False
    """Matched on the advertised version, which distributions patch silently."""
    undetermined: bool = False
    """The rule needed data this scan did not collect, so the answer is unknown."""
    source: str = "policy"
    """Where the detection came from: ``policy`` or ``plugin:<path>``."""
    distribution_patched: bool = False
    """The installed package's changelog names this CVE.

    Only ever set for a version-based match. Something observed on the wire is
    what it is: a changelog cannot un-offer a CBC cipher.
    """
    changelog_source: str = ""
    needs: List[str] = field(default_factory=list)
    """What would have to be collected to settle an undetermined result."""


# --------------------------------------------------------------------------- #
# Evaluation context
# --------------------------------------------------------------------------- #


@dataclass
class _Context:
    """Everything a condition can be evaluated against."""

    policy: Any
    kexinit: KexInit
    banner: Optional[BannerInfo]
    host_keys: Sequence[HostKeyInfo]
    auth_methods: Optional[Any] = None
    effective_config: Optional[Any] = None
    evidence: List[str] = field(default_factory=list)
    used_version: bool = False
    missing: List[str] = field(default_factory=list)
    """Data a condition asked for that this scan did not collect."""

    def unavailable(self, what: str) -> None:
        if what not in self.missing:
            self.missing.append(what)

    def offered(self, algorithm_class: str) -> List[str]:
        # No backstop here any more. The class name is checked against
        # ALGORITHM_CLASSES by _algorithm_selector, which is the same list
        # algorithms_for dispatches on and is called before this -- by the
        # loader when the file is read, and again on the way past. A third
        # copy of that check could only ever be wrong in a different way.
        return self.kexinit.algorithms_for(algorithm_class)

    def tags_of(self, algorithm_class: str, name: str) -> Tuple[str, ...]:
        return cast(Tuple[str, ...], self.policy.lookup(algorithm_class, name).tags)

    def direction_note(self, algorithm_class: str, name: str) -> str:
        """Note the direction when an algorithm is offered in only one.

        Ciphers and MACs are negotiated per direction, and a server offering a
        weak one in a single direction is still affected; saying which helps
        whoever has to reproduce it.
        """
        pairs = {
            "cipher": (self.kexinit.encryption_c2s, self.kexinit.encryption_s2c),
            "mac": (self.kexinit.mac_c2s, self.kexinit.mac_s2c),
            "compression": (self.kexinit.compression_c2s, self.kexinit.compression_s2c),
        }
        if algorithm_class not in pairs:
            return ""
        c2s, s2c = pairs[algorithm_class]
        if name in c2s and name not in s2c:
            return " (client-to-server)"
        if name in s2c and name not in c2s:
            return " (server-to-client)"
        return ""


def _algorithm_selector(rule: Dict[str, Any], where: str = "") -> tuple:
    """What a present/absent condition selects: (class, names, tags).

    Written once and called twice: the loader calls it to refuse a rule when
    the file is read, and the evaluator calls it on the way past. Two copies of
    "what a valid rule looks like" is how the two drift, and the copy that runs
    per server is the one nobody would notice going wrong.
    """
    prefix = f"{where}: " if where else ""
    algorithm_class = rule.get("class") if isinstance(rule, dict) else None
    if algorithm_class is None:
        raise DetectionError(f"{prefix}a present/absent condition needs a 'class'")
    if algorithm_class not in ALGORITHM_CLASSES:
        # Caught when the file is read on purpose. A class name that does not
        # exist is a typo in a file somebody edited, and the place to say so is
        # once, not once per server -- and certainly not by failing the scan of
        # a server the rule is about.
        raise DetectionError(
            f"{prefix}a present/absent condition names the algorithm class "
            f"'{algorithm_class}', which does not exist; the classes are "
            + ", ".join(ALGORITHM_CLASSES)
        )
    names = set(rule.get("algorithms") or [])
    tags = set(rule.get("tags") or [])
    if not names and not tags:
        raise DetectionError(
            f"{prefix}a present/absent condition needs 'algorithms' or 'tags'"
        )
    return algorithm_class, names, tags


def _required_list(rule: Any, key: str, condition: str, where: str = "") -> set:
    """The values a condition names, refused when it names none."""
    prefix = f"{where}: " if where else ""
    values = {str(item) for item in (rule.get(key) or [])} if isinstance(rule, dict) else set()
    if not values:
        raise DetectionError(f"{prefix}a {condition} condition needs '{key}'")
    return values


def _config_directive(rule: Any, where: str = "") -> str:
    """The directive a config condition names, refused when it names none."""
    prefix = f"{where}: " if where else ""
    directive = str(rule.get("directive", "")).lower() if isinstance(rule, dict) else ""
    if not directive:
        raise DetectionError(f"{prefix}a config condition needs a 'directive'")
    return directive


def _config_comparison(rule: Any, where: str = "") -> str:
    """Which comparison a config condition asks for.

    Shared with the loader for the same reason as the rest: the evaluator must
    not be able to accept a rule the loader would have refused, or the other
    way round.
    """
    prefix = f"{where}: " if where else ""
    for kind in ("equals", "in", "not_in", "present", "absent"):
        if isinstance(rule, dict) and kind in rule:
            return kind
    raise DetectionError(
        f"{prefix}a config condition needs 'equals', 'in', 'not_in', 'present' or 'absent'"
    )


def _matching_algorithms(context: _Context, rule: Dict[str, Any]) -> List[str]:
    """Algorithms the server offers that a present/absent rule selects."""
    algorithm_class, names, tags = _algorithm_selector(rule)

    matched = []
    for name in context.offered(algorithm_class):
        if name in names or (tags and tags & set(context.tags_of(algorithm_class, name))):
            matched.append(name + context.direction_note(algorithm_class, name))
    return matched


def _version_matches(context: _Context, rule: Dict[str, Any]) -> bool:
    from .analysis import version_in_range  # local: analysis imports this module

    banner = context.banner
    if banner is None or not banner.product or not banner.product_version:
        return False
    if str(rule.get("product", "")).lower() != banner.product.lower():
        return False
    windows = rule.get("affected") or [
        {"introduced": rule.get("introduced", "0"), "fixed": rule.get("fixed", "")}
    ]
    for window in windows:
        if version_in_range(
            banner.product_version, str(window.get("introduced", "0")), str(window.get("fixed", ""))
        ):
            context.evidence.append(f"{banner.product} {banner.product_version}")
            context.used_version = True
            return True
    return False


def _host_key_matches(context: _Context, rule: Dict[str, Any]) -> bool:
    family = str(rule.get("family", "")).lower()
    below = rule.get("below_bits")
    for key in context.host_keys:
        if key.error is not None or not key.bits:
            continue
        if family and key.key_family.lower() != family:
            continue
        if below is not None and key.bits >= int(below):
            continue
        context.evidence.append(f"{key.algorithm} ({key.bits}-bit {key.key_family.upper()})")
        return True
    return False


def _protocol_matches(context: _Context, rule: Dict[str, Any]) -> bool:
    """The protocol version in the identification string.

    A server that answers ``SSH-1.99`` speaks both protocol versions, and one
    that answers ``SSH-1.x`` speaks only the old one. Either way it is exposed
    to everything wrong with SSH-1, which no amount of algorithm configuration
    can fix.
    """
    banner = context.banner
    if banner is None or not banner.protocol_version:
        context.unavailable("the server's identification string")
        return False
    versions = _required_list(rule, "versions", "protocol")
    if banner.protocol_version in versions:
        context.evidence.append(f"protocol version {banner.protocol_version}")
        return True
    return False


def _auth_method_matches(context: _Context, rule: Dict[str, Any]) -> bool:
    """An authentication method the server offers."""
    auth = context.auth_methods
    if auth is None or getattr(auth, "error", None) or not getattr(auth, "methods", None):
        context.unavailable("the authentication methods (--auth-methods)")
        return False
    wanted = {name.lower() for name in _required_list(rule, "methods", "auth_method")}
    offered = {str(m).lower() for m in auth.methods}
    matched = sorted(wanted & offered)
    if matched:
        context.evidence.extend(f"offers {name} authentication" for name in matched)
        return True
    return False


def _extension_matches(context: _Context, rule: Dict[str, Any]) -> bool:
    """An RFC 8308 extension the server advertises."""
    auth = context.auth_methods
    extensions = getattr(auth, "extensions", None) if auth is not None else None
    if auth is None or getattr(auth, "error", None) or extensions is None:
        context.unavailable("the server's extensions (--auth-methods)")
        return False
    wanted = _required_list(rule, "names", "extension")
    matched = sorted(wanted & set(extensions))
    if matched:
        context.evidence.extend(f"advertises {name}" for name in matched)
        return True
    return False


def _config_matches(context: _Context, rule: Dict[str, Any]) -> bool:
    """A directive from the server's own configuration."""
    config = context.effective_config
    if config is None or not getattr(config, "available", False):
        context.unavailable("the server's configuration (--audit-config)")
        return False
    directive = _config_directive(rule)
    value = config.value(directive)
    if value is None:
        # sshd -T resolves defaults, so a directive with no value here is one
        # this sshd does not have at all -- not one nobody configured.
        return bool(rule.get("absent", False))
    # The comparison is chosen once, by the same function the loader used, so
    # there is no "none of the above" branch left to be unable to reach.
    lowered = str(value).lower()
    kind = _config_comparison(rule)
    if kind == "equals":
        matched = lowered == str(rule["equals"]).lower()
    elif kind == "in":
        matched = lowered in {str(v).lower() for v in rule["in"]}
    elif kind == "not_in":
        matched = lowered not in {str(v).lower() for v in rule["not_in"]}
    else:
        # 'present' and 'absent': the directive has a value, so present holds
        # and absent does not.
        matched = kind == "present"
    if matched:
        context.evidence.append(f"{directive} {value}")
    return matched


def _one_condition(condition: Any, where: str = "") -> tuple:
    """The single key and value a condition node carries.

    Shared by the loader and the evaluator, like the rest of the shape checks:
    a condition the loader accepted is one the evaluator can read.
    """
    prefix = f"{where}: " if where else ""
    if not isinstance(condition, dict):
        raise DetectionError(f"{prefix}a detection rule must be an object")
    if len(condition) != 1:
        raise DetectionError(
            f"{prefix}a condition must have exactly one key, one of: "
            + ", ".join(sorted(_CONDITION_KEYS))
        )
    (key, value), = condition.items()
    if key not in _CONDITION_KEYS:
        raise DetectionError(
            f"{prefix}unknown condition '{key}'; valid keys are "
            + ", ".join(sorted(_CONDITION_KEYS))
        )
    return key, value


def _evaluate(context: _Context, condition: Dict[str, Any]) -> bool:
    """Evaluate one condition node."""
    key, value = _one_condition(condition)

    return _EVALUATORS[key](context, value)


def _negated(context: _Context, value: Any) -> bool:
    # Evidence gathered inside a negation describes what is absent, which would
    # read as a cause; discard it.
    depth = len(context.evidence)
    result = not _evaluate(context, value)
    del context.evidence[depth:]
    return result


def _present(context: _Context, value: Any) -> bool:
    matched = _matching_algorithms(context, value)
    context.evidence.extend(matched)
    return bool(matched)


#: What each condition key does. _CONDITION_KEYS is this table's keys, so a
#: key cannot be recognised and unimplemented: there is one list, and it is
#: the one that does the work.
_EVALUATORS = {
    "always": lambda context, value: bool(value),
    "all": lambda context, value: all(_evaluate(context, cast(Dict[str, Any], item))
                                     for item in value),
    "any": lambda context, value: any(_evaluate(context, cast(Dict[str, Any], item))
                                     for item in value),
    "not": _negated,
    "present": _present,
    "absent": lambda context, value: not _matching_algorithms(context, value),
    "version": _version_matches,
    "host_key": _host_key_matches,
    "protocol": _protocol_matches,
    "auth_method": _auth_method_matches,
    "extension": _extension_matches,
    "config": _config_matches,
}

_CONDITION_KEYS = frozenset(_EVALUATORS)


def parse_condition(condition: Any, context_name: str) -> Dict[str, Any]:
    """Validate a detection tree at load time, so errors surface early."""
    key, value = _one_condition(condition, context_name)
    if key in _COMBINATORS:
        if not isinstance(value, list) or not value:
            raise DetectionError(f"{context_name}: '{key}' takes a non-empty list of conditions")
        for item in value:
            parse_condition(item, context_name)
    elif key == "not":
        parse_condition(value, context_name)
    elif key in {"present", "absent"}:
        # The same function the evaluator calls, so a rule that loads is a rule
        # that can be evaluated.
        _algorithm_selector(value if isinstance(value, dict) else {}, context_name)
    elif key == "version" and (not isinstance(value, dict) or "product" not in value):
        raise DetectionError(f"{context_name}: 'version' needs an object with a 'product'")
    elif key == "protocol":
        _required_list(value, "versions", "protocol", context_name)
    elif key == "auth_method":
        _required_list(value, "methods", "auth_method", context_name)
    elif key == "extension":
        _required_list(value, "names", "extension", context_name)
    elif key == "config":
        _config_directive(value, context_name)
        _config_comparison(value, context_name)
        for comparison in ("in", "not_in"):
            if comparison in value and not isinstance(value[comparison], (list, tuple)):
                # Same reason as the algorithm class above: a value that is not
                # a list is a mistake in a file somebody edited. Left to
                # evaluation it raises TypeError, which is not a DetectionError
                # and so is not contained -- the scan of the server the rule is
                # about fails, and the report blames the server.
                raise DetectionError(
                    f"{context_name}: 'config.{comparison}' takes a list of values, got "
                    f"{type(value[comparison]).__name__}"
                )
    return cast(Dict[str, Any], condition)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def evaluate(
    policy: Any,
    kexinit: KexInit,
    banner: Optional[BannerInfo],
    host_keys: Sequence[HostKeyInfo],
    auth_methods: Optional[Any] = None,
    effective_config: Optional[Any] = None,
) -> List[VulnerabilityMatch]:
    """Return every vulnerability in the policy that this server matches.

    A rule that came out negative only because the scan never collected what
    it asked for is returned too, marked ``undetermined``. Leaving it out
    would read as "checked, and fine".
    """
    matches: List[VulnerabilityMatch] = []
    for vulnerability in policy.vulnerabilities:
        if vulnerability.detection is None:
            continue
        context = _Context(
            policy=policy,
            kexinit=kexinit,
            banner=banner,
            host_keys=host_keys,
            auth_methods=auth_methods,
            effective_config=effective_config,
        )
        try:
            affected = _evaluate(context, vulnerability.detection)
        except Exception as exc:  # a rule is data somebody wrote
            # A broken rule must not silently pass or silently fail: surface it
            # as its own finding via an evidence note.
            #
            # Every shape the loader knows about is refused when the file is
            # read. This catches everything else, and it catches Exception
            # rather than DetectionError because the failure of a rule is not
            # the failure of the server it was pointed at: 'in: 4' raised
            # TypeError here, escaped, and turned a reachable server into an
            # unscannable one in the report.
            matches.append(
                VulnerabilityMatch(
                    id=vulnerability.id,
                    name=vulnerability.name,
                    severity=Severity.INFO,
                    description=(
                        "This vulnerability could not be evaluated because its detection rule "
                        "in the policy file is malformed."
                    ),
                    remediation=f"Fix the rule: {exc}",
                    references=list(vulnerability.references),
                    affects=vulnerability.affects,
                    evidence=[str(exc)],
                )
            )
            continue
        if not affected:
            if context.missing:
                matches.append(
                    VulnerabilityMatch(
                        id=vulnerability.id,
                        name=vulnerability.name,
                        severity=Severity.INFO,
                        description=vulnerability.description,
                        remediation=vulnerability.remediation,
                        references=list(vulnerability.references),
                        affects=vulnerability.affects,
                        undetermined=True,
                        needs=list(context.missing),
                    )
                )
            continue
        matches.append(
            VulnerabilityMatch(
                id=vulnerability.id,
                name=vulnerability.name,
                severity=vulnerability.severity,
                description=vulnerability.description,
                remediation=vulnerability.remediation,
                references=list(vulnerability.references),
                affects=vulnerability.affects,
                evidence=_dedupe(context.evidence),
                version_based=context.used_version,
            )
        )
    return matches


def _dedupe(items: Sequence[str]) -> List[str]:
    seen = set()
    unique = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique
