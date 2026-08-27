"""Loading and querying of the algorithm policy file.

The policy is the single place where "this algorithm is safe" is decided. It
lives outside the code on purpose: cryptography ages, and updating a JSON file
must not require touching Python.

Search order used by :func:`load_policy` when no explicit path is given:

1. ``$SSH_CRYPTO_CHECKER_CONFIG``
2. ``./ssh-crypto-checker.json`` in the current directory
3. ``~/.config/ssh-crypto-checker/algorithms.json``
4. ``/etc/ssh-crypto-checker/algorithms.json``
5. the copy bundled with the package
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .i18n import DEFAULT_LANGUAGE
from .models import ALGORITHM_CLASSES, Category, Severity
from .vulnerabilities import DetectionError, Vulnerability, parse_condition

__all__ = [
    "AlgorithmEntry",
    "Policy",
    "PolicyError",
    "SoftwareAdvisory",
    "candidate_policy_paths",
    "default_policy_path",
    "load_policy",
]

ENV_VAR = "SSH_CRYPTO_CHECKER_CONFIG"


class PolicyError(Exception):
    """Raised when a policy file is missing, malformed or inconsistent."""


# --------------------------------------------------------------------------- #
# Entries
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AlgorithmEntry:
    """Classification of one algorithm."""

    name: str
    category: Category
    tags: Tuple[str, ...] = ()
    notes: str = ""
    references: Tuple[str, ...] = ()
    suggest: bool = False
    matched_by: str = "exact"
    security_strength_bits: Optional[int] = None
    """Security strength per NIST SP 800-57. ``None`` when it depends on the
    key size rather than on the algorithm, as with ``rsa-sha2-*``."""


@dataclass(frozen=True)
class CategoryInfo:
    key: str
    label: str
    short: str
    score: Optional[int]
    severity: Severity
    description: str


@dataclass(frozen=True)
class SoftwareAdvisory:
    """A version-based advisory for a specific SSH implementation."""

    id: str
    product: str
    severity: Severity
    title: str
    description: str
    remediation: str = ""
    references: Tuple[str, ...] = ()
    affected: Tuple[Tuple[str, str], ...] = ()
    """Pairs of (introduced, fixed) version strings; ``fixed`` is exclusive."""


@dataclass(frozen=True)
class SizeRequirement:
    minimum_bits: int
    recommended_bits: int


@dataclass(frozen=True)
class ConfigCheck:
    """One expectation about the effective sshd configuration."""

    id: str
    directive: str
    severity: Severity
    expect: Dict[str, Any]
    title: str
    description: str = ""
    remediation: str = ""
    reference: str = ""
    """Where the recommendation comes from: a CIS/STIG rule for server
    directives, or the OpenSSH ssh_config(5)/sshd_config(5) manual for the
    client-side ones the CIS/STIG server benchmarks do not cover."""
    alternatives: Tuple[str, ...] = ()
    """Other directives that satisfy the same requirement."""


@dataclass(frozen=True)
class ClassRule:
    """Per-class algorithm rules inside a conformance profile."""

    allow: Tuple[str, ...] = ()
    """Allowlist of fnmatch globs. When non-empty, anything else violates."""
    disallow: Tuple[str, ...] = ()
    disallow_unless_strict_kex: Tuple[str, ...] = ()
    """Forbidden only while the server does not negotiate strict key exchange.

    Some baselines exclude algorithms only until that countermeasure is in
    place and say so. Which threat they had in mind is theirs to state in
    ``reason``; this field only carries the condition.
    """
    reason: str = ""


@dataclass(frozen=True)
class StrengthLevel:
    """A NIST security-strength band."""

    id: str
    minimum_bits: int
    label: str
    description: str


@dataclass(frozen=True)
class Profile:
    """A published standard the server can be measured against."""

    id: str
    name: str
    authority: str
    kind: str
    reference: str
    edition: str = ""
    """Which published edition of the standard these rules encode, in prose."""
    edition_id: str = ""
    """The short name that edition answers to: --profile <id>@<edition_id>.

    It is the file the edition lives in and nothing else, so there is one
    definition of it and it cannot drift from the prose beside it.
    """
    current: bool = True
    """Whether this is the edition in force, which a bare --profile <id> gets."""
    url: str = ""
    summary: str = ""
    notes: str = ""
    minimum_security_strength: Optional[int] = None
    minimum_key_bits: Dict[str, int] = field(default_factory=dict)
    require_strict_kex: bool = False
    require_post_quantum: bool = False
    rules: Dict[str, ClassRule] = field(default_factory=dict)
    forbid_local_categories: Tuple[Category, ...] = ()
    """For policy-conformance profiles: local categories that constitute a breach."""


@dataclass
class AlgorithmClassPolicy:
    """The policy for one algorithm class (kex, cipher, ...)."""

    key: str
    label: str
    sshd_config_directive: str
    entries: Dict[str, AlgorithmEntry] = field(default_factory=dict)
    patterns: List[Tuple[str, AlgorithmEntry]] = field(default_factory=list)

    def lookup(self, name: str) -> AlgorithmEntry:
        """Classify ``name``, falling back to patterns and then to unknown."""
        entry = self.entries.get(name)
        if entry is not None:
            return entry
        for pattern, template in self.patterns:
            if fnmatch.fnmatchcase(name, pattern):
                return AlgorithmEntry(
                    name=name,
                    category=template.category,
                    tags=template.tags,
                    notes=template.notes,
                    references=template.references,
                    suggest=False,
                    matched_by=f"pattern:{pattern}",
                )
        return AlgorithmEntry(
            name=name,
            category=Category.UNKNOWN,
            notes="Not present in the policy file. Review the algorithm and add an entry.",
            matched_by="unknown",
        )

    def suggested(self) -> List[str]:
        """Algorithms flagged for inclusion in a generated hardened config."""
        return [name for name, entry in self.entries.items() if entry.suggest]


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #


@dataclass
class Policy:
    """A fully validated policy file."""

    source: Path
    schema_version: str
    metadata: Dict[str, Any]
    categories: Dict[Category, CategoryInfo]
    classes: Dict[str, AlgorithmClassPolicy]
    class_weights: Dict[str, int]
    modifiers: Dict[str, Dict[str, Any]]
    grades: List[Dict[str, Any]]
    grade_caps: List[Dict[str, str]]
    version_advisories_affect_score: bool
    host_key_requirements: Dict[str, SizeRequirement]
    dh_requirement: SizeRequirement
    require_strict_kex: bool
    require_post_quantum: bool
    require_aead_cipher: bool
    require_etm_mac: bool
    certificate_expiry_warning_days: int
    advisories: List[SoftwareAdvisory]
    tag_labels: Dict[str, str]
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    config_checks: List[ConfigCheck] = field(default_factory=list)
    client_checks: List[ConfigCheck] = field(default_factory=list)
    """Expectations about the client's own ssh_config, read with 'ssh -G'."""
    profiles: Dict[str, Profile] = field(default_factory=dict)
    """One entry per standard: the edition in force. What a scan evaluates."""
    profile_editions: Dict[str, Profile] = field(default_factory=dict)
    """Every edition of every standard, keyed 'id@edition'.

    Kept apart from ``profiles`` on purpose. A scan that evaluated both
    mappings would measure each standard twice, and a report that listed both
    would say the same thing twice; asking for an edition by name is a
    different act from evaluating what is in force.
    """
    strength_levels: List[StrengthLevel] = field(default_factory=list)
    modulus_strength: List[Tuple[int, int]] = field(default_factory=list)
    """(modulus bits, security strength bits) pairs, largest first."""
    strength_reference: str = ""

    # -- queries ---------------------------------------------------------- #

    def strength_for_modulus(self, bits: Optional[int]) -> Optional[int]:
        """Security strength of an RSA/DSA/DH modulus of ``bits`` bits."""
        if bits is None:
            return None
        for modulus_bits, strength in self.modulus_strength:
            if bits >= modulus_bits:
                return strength
        # Reached by a policy whose table does not end at zero, which is a
        # file a user can write, so it is a file a test writes too.
        return 0

    def strength_level(self, bits: Optional[int]) -> Optional[StrengthLevel]:
        """The NIST security-strength band ``bits`` falls into."""
        if bits is None:
            return None
        for level in self.strength_levels:
            if bits >= level.minimum_bits:
                return level
        # Same: a policy that defines no bands at all is a policy somebody
        # could write, so it is one the tests write.
        return self.strength_levels[-1] if self.strength_levels else None

    def resolve_profile(self, selector: str) -> Optional[Profile]:
        """The profile a --profile argument names, edition and all.

        A bare id means the edition in force, which is what somebody asking
        "does this pass BSI" means. An id@edition means that one, which is
        what somebody asking "does this pass the edition we were audited
        under" means. They are different questions and both get asked.
        """
        if selector in self.profile_editions:
            return self.profile_editions[selector]
        return self.profiles.get(selector)

    def profile_selectors(self) -> List[str]:
        """Every name --profile accepts, in the order --list-profiles shows."""
        names = []
        for profile_id in self.profiles:
            names.append(profile_id)
            names.extend(
                selector
                for selector in sorted(self.profile_editions)
                if selector.startswith(f"{profile_id}@")
            )
        return names

    def lookup(self, algorithm_class: str, name: str) -> AlgorithmEntry:
        klass = self.classes.get(algorithm_class)
        if klass is None:
            raise PolicyError(f"unknown algorithm class: {algorithm_class}")
        return klass.lookup(name)

    def category_score(self, category: Category) -> Optional[int]:
        info = self.categories.get(category)
        return info.score if info else None

    def category_label(self, category: Category) -> str:
        info = self.categories.get(category)
        return info.label if info else category.value

    def category_short(self, category: Category) -> str:
        info = self.categories.get(category)
        return info.short if info else category.value.upper()

    def modifier(self, modifier_id: str) -> Optional[Dict[str, Any]]:
        return self.modifiers.get(modifier_id)

    def grade_for(self, score: int, capabilities: Dict[str, bool]) -> str:
        """Map a numeric score to a letter grade, honouring extra requirements."""
        for rule in self.grades:
            if score >= int(rule["min_score"]):
                requirements = rule.get("requires") or []
                if all(capabilities.get(req, False) for req in requirements):
                    return str(rule["grade"])
        return str(self.grades[-1]["grade"]) if self.grades else "F"

    @property
    def grade_ladder(self) -> List[str]:
        """Grades from best to worst."""
        return [str(rule["grade"]) for rule in self.grades]

    def cap_grade(self, grade: str, cap: str) -> str:
        """Return the worse of ``grade`` and ``cap``."""
        ladder = self.grade_ladder
        try:
            return grade if ladder.index(grade) >= ladder.index(cap) else cap
        except ValueError:
            return grade

    def size_requirement(self, family: str) -> Optional[SizeRequirement]:
        return self.host_key_requirements.get(family.lower())

    def describe(self) -> str:
        """One-line human description of the loaded policy."""
        name = self.metadata.get("name", "policy")
        version = self.metadata.get("version", "?")
        updated = self.metadata.get("updated", "?")
        return f"{name} v{version} (updated {updated})"

    def algorithm_count(self) -> int:
        return sum(len(k.entries) for k in self.classes.values())


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #


def _require(mapping: Dict[str, Any], key: str, context: str) -> Any:
    if key not in mapping:
        raise PolicyError(f"missing required key '{key}' in {context}")
    return mapping[key]


def _as_tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    raise PolicyError(f"expected a list of strings, got {type(value).__name__}")


def _parse_category(value: Any, context: str) -> Category:
    try:
        return Category(str(value))
    except ValueError as exc:
        valid = ", ".join(c.value for c in Category)
        raise PolicyError(f"invalid category '{value}' in {context} (valid: {valid})") from exc


def _parse_severity(value: Any, context: str) -> Severity:
    try:
        return Severity(str(value))
    except ValueError as exc:
        valid = ", ".join(s.value for s in Severity)
        raise PolicyError(f"invalid severity '{value}' in {context} (valid: {valid})") from exc


def _parse_entry(name: str, raw: Dict[str, Any], context: str) -> AlgorithmEntry:
    if not isinstance(raw, dict):
        raise PolicyError(f"entry '{name}' in {context} must be an object")
    category = _parse_category(_require(raw, "category", f"{context}.{name}"), f"{context}.{name}")
    suggest = raw.get("suggest")
    if suggest is None:
        suggest = category is Category.RECOMMENDED
    strength = raw.get("security_strength_bits")
    return AlgorithmEntry(
        name=name,
        category=category,
        tags=_as_tuple(raw.get("tags")),
        notes=str(raw.get("notes", "")),
        references=_as_tuple(raw.get("references")),
        suggest=bool(suggest),
        security_strength_bits=None if strength is None else int(strength),
    )


def _parse_size_requirement(raw: Any, context: str) -> SizeRequirement:
    if not isinstance(raw, dict):
        raise PolicyError(f"{context} must be an object with minimum_bits/recommended_bits")
    minimum = int(raw.get("minimum_bits", 0))
    recommended = int(raw.get("recommended_bits", minimum))
    return SizeRequirement(minimum_bits=minimum, recommended_bits=max(minimum, recommended))


def _parse_advisory(raw: Dict[str, Any], index: int) -> SoftwareAdvisory:
    context = f"software_advisories[{index}]"
    affected: List[Tuple[str, str]] = []
    for window in raw.get("affected") or []:
        if not isinstance(window, dict):
            raise PolicyError(f"{context}.affected entries must be objects")
        affected.append((str(window.get("introduced", "0")), str(window.get("fixed", ""))))
    return SoftwareAdvisory(
        id=str(_require(raw, "id", context)),
        product=str(_require(raw, "product", context)),
        severity=_parse_severity(raw.get("severity", "medium"), context),
        title=str(raw.get("title", "")),
        description=str(raw.get("description", "")),
        remediation=str(raw.get("remediation", "")),
        references=_as_tuple(raw.get("references")),
        affected=tuple(affected),
    )


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


def _read_structured(path: Path) -> Dict[str, Any]:
    """Read JSON, TOML or YAML depending on the file extension.

    JSON always works. TOML needs Python 3.11+ and YAML needs PyYAML; both are
    optional conveniences, the shipped policy is JSON.
    """
    suffix = path.suffix.lower()
    try:
        if suffix in {".toml"}:
            try:
                import tomllib  # type: ignore[import-not-found,unused-ignore]
            except ImportError as exc:
                raise PolicyError(
                    f"{path}: TOML policies require Python 3.11 or newer"
                ) from exc
            with path.open("rb") as handle:
                return dict(tomllib.load(handle))
        if suffix in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-untyped]
            except ImportError as exc:
                raise PolicyError(
                    f"{path}: YAML policies require the optional PyYAML package"
                ) from exc
            with path.open("r", encoding="utf-8") as handle:
                return dict(yaml.safe_load(handle) or {})
        with path.open("r", encoding="utf-8") as handle:
            return dict(json.load(handle))
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(
            f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def default_policy_path() -> Path:
    """Path of the policy file bundled with the package.

    The data directory sits beside this module and is installed with it, so
    the path follows from __file__. This used to ask importlib.resources first
    and fall back here, which added two branches nothing could ever take: the
    answer was the same either way, and code no test can reach is code nobody
    can vouch for.
    """
    return Path(__file__).resolve().parent / "data" / "algorithms.json"


def candidate_policy_paths() -> List[Path]:
    """All locations searched for a policy file, in priority order."""
    candidates: List[Path] = []
    env_value = os.environ.get(ENV_VAR)
    if env_value:
        candidates.append(Path(env_value).expanduser())
    candidates.append(Path.cwd() / "ssh-crypto-checker.json")
    candidates.append(Path.home() / ".config" / "ssh-crypto-checker" / "algorithms.json")
    candidates.append(Path("/etc/ssh-crypto-checker/algorithms.json"))
    candidates.append(default_policy_path())
    return candidates


def _language_overlay(language: str) -> Optional[Dict[str, Any]]:
    """The prose overlay for ``language`` (Spanish etc.), or None for English.

    Lives beside the bundled policy at ``data/i18n/algorithms.<language>.json``
    and is keyed by stable identifiers (algorithm name, category, tag, level id,
    vulnerability id, check id, profile id). It is applied to whatever policy is
    loaded and skips anything it has no translation for, so an English string is
    always the fallback and a partial overlay is valid. The file is named after
    the policy it overlays (``algorithms.json``).
    """
    if language == DEFAULT_LANGUAGE:
        return None
    path = default_policy_path().parent / "i18n" / f"algorithms.{language}.json"
    if not path.is_file():
        return None
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _overlay_fields(entry: Dict[str, Any], translation: Any, fields: Sequence[str]) -> None:
    if isinstance(translation, dict):
        for name in fields:
            if translation.get(name):
                entry[name] = translation[name]


def _overlay_by_id(entries: Any, translations: Any, fields: Sequence[str]) -> None:
    if not isinstance(entries, list) or not isinstance(translations, dict):
        return
    for entry in entries:
        if isinstance(entry, dict):
            _overlay_fields(entry, translations.get(entry.get("id")), fields)


def _apply_overlay_to_raw(raw: Dict[str, Any], overlay: Dict[str, Any]) -> None:
    """Swap the translatable prose in the raw policy for the overlay's, in place."""
    categories = overlay.get("categories") or {}
    for key, value in (raw.get("categories") or {}).items():
        if isinstance(value, dict):
            _overlay_fields(value, categories.get(key), ("label", "description"))

    tags = overlay.get("tag_labels") or {}
    raw_tags = raw.get("tag_labels")
    if isinstance(raw_tags, dict):
        for key, text in tags.items():
            if key in raw_tags and text:
                raw_tags[key] = text

    levels = overlay.get("security_strength_levels") or {}
    for level in ((raw.get("security_strength") or {}).get("levels") or []):
        if isinstance(level, dict):
            _overlay_fields(level, levels.get(level.get("id")), ("label", "description"))

    notes = overlay.get("algorithms") or {}
    for algorithm_class in (raw.get("algorithms") or {}).values():
        if not isinstance(algorithm_class, dict):
            continue
        for name, entry in (algorithm_class.get("entries") or {}).items():
            if isinstance(entry, dict) and notes.get(name):
                entry["notes"] = notes[name]

    _overlay_by_id(raw.get("vulnerabilities"), overlay.get("vulnerabilities"),
                   ("name", "description", "remediation"))
    _overlay_by_id(raw.get("sshd_config_checks"), overlay.get("sshd_config_checks"),
                   ("title", "description", "remediation"))
    _overlay_by_id(raw.get("ssh_config_checks"), overlay.get("ssh_config_checks"),
                   ("title", "description", "remediation"))


def _apply_overlay_to_profiles(policy: Policy, profile_overlay: Dict[str, Any]) -> None:
    """Translate profile prose in place. Profiles are frozen, so each is rebuilt
    with ``replace``; the dicts holding them are mutable."""
    if not profile_overlay:
        return

    def translated(profile: Profile, profile_id: str) -> Profile:
        translation = profile_overlay.get(profile_id)
        if not isinstance(translation, dict):
            return profile
        changes = {f: translation[f] for f in ("name", "summary", "notes") if translation.get(f)}
        return replace(profile, **changes) if changes else profile

    for profile_id in list(policy.profiles):
        policy.profiles[profile_id] = translated(policy.profiles[profile_id], profile_id)
    for selector in list(policy.profile_editions):
        base = selector.split("@", 1)[0]
        policy.profile_editions[selector] = translated(policy.profile_editions[selector], base)


def load_policy(path: Optional[Path] = None, language: str = DEFAULT_LANGUAGE) -> Policy:
    """Load and validate a policy file.

    Args:
        path: explicit policy file. When ``None`` the search order documented
            in the module docstring is used.
        language: report language. When it is not English and a matching prose
            overlay exists, the algorithm notes, category and level descriptions,
            tag labels, vulnerability and check text, and profile summaries are
            translated. Everything else -- and everything the overlay omits --
            stays as written in the policy file.

    Raises:
        PolicyError: if no policy can be found, or the file is invalid.
    """
    if path is not None:
        resolved = Path(path).expanduser()
        if not resolved.is_file():
            raise PolicyError(f"policy file not found: {resolved}")
    else:
        resolved = next((p for p in candidate_policy_paths() if p.is_file()), None)  # type: ignore[assignment]
        if resolved is None:
            raise PolicyError(
                "no policy file found; reinstall the package or pass --config"
            )

    raw = _read_structured(resolved)
    overlay = _language_overlay(language)
    if overlay is not None:
        _apply_overlay_to_raw(raw, overlay)
    try:
        policy = _build_policy(raw, resolved)
    except PolicyError as exc:
        # Every message below says where in the document the problem is --
        # 'vulnerabilities[0] must be an object' -- but not which document.
        # Anyone running with --config has at least two, usually one per
        # environment, and "which file?" is the first thing they need.
        if str(resolved) in str(exc):
            raise
        raise PolicyError(f"{resolved}: {exc}") from exc
    if overlay is not None:
        _apply_overlay_to_profiles(policy, overlay.get("profiles") or {})
    return policy


def _build_policy(raw: Dict[str, Any], source: Path) -> Policy:
    schema_version = str(raw.get("schema_version", "1.0"))
    if not schema_version.startswith("1."):
        raise PolicyError(
            f"{source}: unsupported schema_version '{schema_version}' (this build understands 1.x)"
        )

    # Categories -------------------------------------------------------- #
    categories: Dict[Category, CategoryInfo] = {}
    for key, value in (raw.get("categories") or {}).items():
        category = _parse_category(key, "categories")
        if not isinstance(value, dict):
            raise PolicyError(f"categories.{key} must be an object")
        score = value.get("score")
        categories[category] = CategoryInfo(
            key=category.value,
            label=str(value.get("label", category.value.title())),
            short=str(value.get("short", category.value.upper())),
            score=None if score is None else int(score),
            severity=_parse_severity(value.get("severity", "info"), f"categories.{key}"),
            description=str(value.get("description", "")),
        )
    for category in Category:
        if category not in categories:
            raise PolicyError(f"{source}: categories is missing '{category.value}'")

    # Algorithm classes -------------------------------------------------- #
    classes: Dict[str, AlgorithmClassPolicy] = {}
    raw_classes = raw.get("algorithms") or {}
    for class_key in ALGORITHM_CLASSES:
        if class_key not in raw_classes:
            raise PolicyError(f"{source}: algorithms is missing the '{class_key}' class")
        raw_class = raw_classes[class_key]
        if not isinstance(raw_class, dict):
            raise PolicyError(f"algorithms.{class_key} must be an object")
        raw_entries = raw_class.get("entries") or {}
        if not isinstance(raw_entries, dict):
            raise PolicyError(
                f"algorithms.{class_key}.entries must be an object mapping each "
                f"algorithm name to its classification, got {type(raw_entries).__name__}"
            )
        entries = {
            name: _parse_entry(name, value, f"algorithms.{class_key}.entries")
            for name, value in raw_entries.items()
        }
        raw_patterns = raw_class.get("patterns") or []
        if not isinstance(raw_patterns, list):
            raise PolicyError(
                f"algorithms.{class_key}.patterns must be a list of "
                f"objects with a 'match' key, got {type(raw_patterns).__name__}"
            )
        patterns: List[Tuple[str, AlgorithmEntry]] = []
        for index, pattern in enumerate(raw_patterns):
            if not isinstance(pattern, dict) or "match" not in pattern:
                raise PolicyError(
                    f"algorithms.{class_key}.patterns[{index}] must be an object with a 'match' key"
                )
            glob = str(pattern["match"])
            patterns.append(
                (glob, _parse_entry(glob, pattern, f"algorithms.{class_key}.patterns"))
            )
        classes[class_key] = AlgorithmClassPolicy(
            key=class_key,
            label=str(raw_class.get("label", class_key.replace("_", " ").title())),
            sshd_config_directive=str(raw_class.get("sshd_config_directive", "")),
            entries=entries,
            patterns=patterns,
        )

    # Scoring ------------------------------------------------------------ #
    scoring = raw.get("scoring") or {}
    class_weights = {
        key: int(value) for key, value in (scoring.get("class_weights") or {}).items()
    }
    for class_key in ALGORITHM_CLASSES:
        class_weights.setdefault(class_key, 0)
    if sum(class_weights.values()) <= 0:
        raise PolicyError(
            f"{source}: scoring.class_weights must contain at least one positive weight"
        )

    modifiers: Dict[str, Dict[str, Any]] = {}
    for modifier in scoring.get("modifiers") or []:
        if not isinstance(modifier, dict) or "id" not in modifier:
            raise PolicyError("scoring.modifiers entries need an 'id' key")
        modifiers[str(modifier["id"])] = {
            "id": str(modifier["id"]),
            "points": int(modifier.get("points", 0)),
            "description": str(modifier.get("description", "")),
        }

    grades = list(scoring.get("grades") or [])
    if not grades:
        raise PolicyError(f"{source}: scoring.grades must not be empty")
    for rule in grades:
        if "grade" not in rule or "min_score" not in rule:
            raise PolicyError("scoring.grades entries need 'grade' and 'min_score'")
    grades.sort(key=lambda rule: int(rule["min_score"]), reverse=True)

    grade_names = {str(rule["grade"]) for rule in grades}
    grade_caps: List[Dict[str, str]] = []
    for cap in scoring.get("grade_caps") or []:
        if not isinstance(cap, dict) or "when" not in cap or "max_grade" not in cap:
            raise PolicyError("scoring.grade_caps entries need 'when' and 'max_grade'")
        if str(cap["max_grade"]) not in grade_names:
            raise PolicyError(
                f"scoring.grade_caps refers to unknown grade '{cap['max_grade']}'"
            )
        # Local: assessment imports this module. Checked here rather than left
        # to the evaluator, because a cap whose condition does not exist does
        # nothing at all -- a safety limit removed by a typo, in a file where
        # every other kind of typo is refused on sight.
        from .assessment import GRADE_CAP_CONDITIONS

        if str(cap["when"]) not in GRADE_CAP_CONDITIONS:
            raise PolicyError(
                f"scoring.grade_caps refers to unknown condition '{cap['when']}'; "
                f"the ones that exist are {', '.join(sorted(GRADE_CAP_CONDITIONS))}"
            )
        grade_caps.append({"when": str(cap["when"]), "max_grade": str(cap["max_grade"])})

    # Requirements ------------------------------------------------------- #
    requirements = raw.get("requirements") or {}
    host_key_requirements = {
        str(family).lower(): _parse_size_requirement(value, f"requirements.host_keys.{family}")
        for family, value in (requirements.get("host_keys") or {}).items()
    }
    dh_requirement = _parse_size_requirement(
        requirements.get("diffie_hellman") or {"minimum_bits": 2048, "recommended_bits": 3072},
        "requirements.diffie_hellman",
    )

    advisories = [
        _parse_advisory(advisory, index)
        for index, advisory in enumerate(raw.get("software_advisories") or [])
    ]

    config_checks = [
        _parse_config_check(entry, index)
        for index, entry in enumerate(raw.get("sshd_config_checks") or [])
    ]
    client_checks = [
        _parse_config_check(entry, index, "ssh_config_checks")
        for index, entry in enumerate(raw.get("ssh_config_checks") or [])
    ]

    vulnerabilities = [
        _parse_vulnerability(entry, index)
        for index, entry in enumerate(raw.get("vulnerabilities") or [])
    ]
    # A policy written for an older schema only has software_advisories; carry
    # those forward as version-only vulnerabilities so it keeps working.
    known = {vulnerability.id for vulnerability in vulnerabilities}
    for advisory in advisories:
        if advisory.id in known:
            continue
        vulnerabilities.append(
            Vulnerability(
                id=advisory.id,
                name=advisory.title or advisory.id,
                severity=advisory.severity,
                description=advisory.description,
                remediation=advisory.remediation,
                references=advisory.references,
                detection={
                    "version": {
                        "product": advisory.product,
                        "affected": [
                            {"introduced": low, "fixed": high} for low, high in advisory.affected
                        ],
                    }
                },
            )
        )

    # Security strength bands and modulus table ------------------------- #
    strength = raw.get("security_strength") or {}
    strength_levels = [
        StrengthLevel(
            id=str(level.get("id", f"level{index}")),
            minimum_bits=int(level.get("minimum_bits", 0)),
            label=str(level.get("label", "")),
            description=str(level.get("description", "")),
        )
        for index, level in enumerate(strength.get("levels") or [])
    ]
    strength_levels.sort(key=lambda level: level.minimum_bits, reverse=True)
    modulus_strength = sorted(
        ((int(pair[0]), int(pair[1])) for pair in strength.get("modulus_strength") or []),
        key=lambda pair: pair[0],
        reverse=True,
    )

    profiles, profile_editions = _load_profile_directory(source)
    # A policy file may still carry profiles inline. Somebody writing one for
    # their own estate should not have to lay out a directory to add a rule,
    # and an inline profile wins so it can override a shipped one.
    for profile_id, value in (raw.get("profiles") or {}).items():
        profile = _parse_profile(profile_id, value)
        profiles[profile_id] = profile
        profile_editions.setdefault(profile_id, profile)

    return Policy(
        source=source,
        schema_version=schema_version,
        metadata=dict(raw.get("metadata") or {}),
        categories=categories,
        classes=classes,
        class_weights=class_weights,
        modifiers=modifiers,
        grades=grades,
        grade_caps=grade_caps,
        version_advisories_affect_score=bool(scoring.get("version_advisories_affect_score", False)),
        host_key_requirements=host_key_requirements,
        dh_requirement=dh_requirement,
        require_strict_kex=bool(requirements.get("require_strict_kex", True)),
        require_post_quantum=bool(requirements.get("require_post_quantum", False)),
        require_aead_cipher=bool(requirements.get("require_aead_cipher", False)),
        require_etm_mac=bool(requirements.get("require_etm_mac", True)),
        certificate_expiry_warning_days=int(
            requirements.get("certificate_expiry_warning_days", 30)
        ),
        advisories=advisories,
        tag_labels={str(k): str(v) for k, v in (raw.get("tag_labels") or {}).items()},
        vulnerabilities=vulnerabilities,
        config_checks=config_checks,
        client_checks=client_checks,
        profiles=profiles,
        profile_editions=profile_editions,
        strength_levels=strength_levels,
        modulus_strength=modulus_strength,
        strength_reference=str(strength.get("reference", "")),
    )


_EXPECTATIONS = {"equals", "in", "not_in", "at_most", "at_least", "required"}


def _parse_config_check(raw: Any, index: int, section: str = "sshd_config_checks") -> ConfigCheck:
    context = f"{section}[{index}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{context} must be an object")
    expect = raw.get("expect")
    if not isinstance(expect, dict) or len(expect) != 1:
        raise PolicyError(
            f"{context}: 'expect' must be an object with exactly one of "
            f"{', '.join(sorted(_EXPECTATIONS))}"
        )
    (kind, _value), = expect.items()
    if kind not in _EXPECTATIONS:
        raise PolicyError(
            f"{context}: unknown expectation '{kind}'; valid are "
            f"{', '.join(sorted(_EXPECTATIONS))}"
        )
    return ConfigCheck(
        id=str(_require(raw, "id", context)),
        directive=str(_require(raw, "directive", context)).lower(),
        severity=_parse_severity(raw.get("severity", "medium"), context),
        expect=dict(expect),
        title=str(_require(raw, "title", context)),
        description=str(raw.get("description", "")),
        remediation=str(raw.get("remediation", "")),
        reference=str(raw.get("reference", "")),
        alternatives=tuple(str(a).lower() for a in raw.get("alternatives") or []),
    )


def _parse_vulnerability(raw: Any, index: int) -> Vulnerability:
    context = f"vulnerabilities[{index}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{context} must be an object")
    identifier = str(_require(raw, "id", context))
    detection = raw.get("detection")
    if detection is not None:
        try:
            detection = parse_condition(detection, f"{context} ({identifier})")
        except DetectionError as exc:
            raise PolicyError(str(exc)) from exc
    return Vulnerability(
        id=identifier,
        name=str(raw.get("name", identifier)),
        severity=_parse_severity(raw.get("severity", "medium"), context),
        description=str(raw.get("description", "")),
        remediation=str(raw.get("remediation", "")),
        references=_as_tuple(raw.get("references")),
        detection=detection,
        affects=str(raw.get("affects", "server")),
    )


PROFILE_DIRECTORY = "profiles"
#: What an edition may be called: the file name is the selector, so it has to
#: be typeable and stable rather than a slug of somebody's prose.
_EDITION_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]*$")


def profile_directory_for(source: Path) -> Optional[Path]:
    """Where the profiles of a given policy file live: beside it.

    So a policy written for one estate carries its own, and the shipped one
    carries the published standards, without either having to know about the
    other. None means there is no such directory, which is a policy that
    names no standards -- ordinary for one somebody wrote for their estate.
    """
    directory = Path(source).resolve().parent / PROFILE_DIRECTORY
    return directory if directory.is_dir() else None


def _load_profile_directory(
    source: Path,
) -> Tuple[Dict[str, Profile], Dict[str, Profile]]:
    """One profile per file, one directory per profile, one file per edition.

    A standard is a document somebody else revises on their own calendar, so
    an edition is a file that can be added, kept and asked for by name rather
    than a paragraph edited in place. What was in force in 2024 is still there
    to be measured against in 2027.
    """
    directory = profile_directory_for(source)
    if directory is None:
        return {}, {}

    profiles: Dict[str, Profile] = {}
    all_editions: Dict[str, Profile] = {}
    for folder in sorted(p for p in directory.iterdir() if p.is_dir()):
        profile_id = folder.name
        editions: Dict[str, Profile] = {}
        for path in sorted(folder.glob("*.json")):
            edition_id = path.stem
            where = f"{PROFILE_DIRECTORY}/{profile_id}/{path.name}"
            if not _EDITION_NAME.match(edition_id):
                raise PolicyError(
                    f"{where}: an edition is named by its file, so the name has to be "
                    "lower case letters, digits, dots and dashes"
                )
            document = _read_structured(path)
            editions[edition_id] = _parse_profile(
                profile_id, document, edition_id=edition_id
            )
        if not editions:
            continue
        _mark_the_edition_in_force(profile_id, editions, directory)
        for edition_id, profile in editions.items():
            all_editions[f"{profile_id}@{edition_id}"] = profile
            if profile.current:
                profiles[profile_id] = profile
    return profiles, all_editions


def _mark_the_edition_in_force(
    profile_id: str, editions: Dict[str, Profile], directory: Path
) -> None:
    """Decide which edition a bare ``--profile <id>`` means.

    With one edition there is nothing to decide. With more than one, the file
    has to say -- because which edition is in force is exactly the thing a
    compliance tool must not guess, and the day a second one arrives is the
    day somebody has to think about it.
    """
    declared = [p for p in editions.values() if p.current]
    if len(editions) == 1:
        only = next(iter(editions))
        editions[only] = replace(editions[only], current=True)
        return
    if not declared:
        raise PolicyError(
            f"{directory.name}/{profile_id} has {len(editions)} editions "
            f"({', '.join(sorted(editions))}) and none of them says \"current\": true, "
            "so there is nothing for a bare --profile to mean"
        )
    if len(declared) > 1:
        names = ", ".join(sorted(p.edition_id for p in declared))
        raise PolicyError(
            f"{directory.name}/{profile_id} has more than one edition claiming to be "
            f"current ({names}); only one can be in force"
        )


def _parse_profile(profile_id: str, raw: Any, edition_id: str = "") -> Profile:
    context = f"profiles.{profile_id}"
    if not isinstance(raw, dict):
        raise PolicyError(f"{context} must be an object")

    rules: Dict[str, ClassRule] = {}
    for class_key, value in (raw.get("algorithms") or {}).items():
        if class_key not in ALGORITHM_CLASSES:
            raise PolicyError(
                f"{context}.algorithms refers to unknown class '{class_key}'"
            )
        if not isinstance(value, dict):
            raise PolicyError(f"{context}.algorithms.{class_key} must be an object")
        rules[class_key] = ClassRule(
            allow=_as_tuple(value.get("allow")),
            disallow=_as_tuple(value.get("disallow")),
            disallow_unless_strict_kex=_as_tuple(value.get("disallow_unless_strict_kex")),
            reason=str(value.get("reason", "")),
        )

    forbidden = tuple(
        _parse_category(name, f"{context}.forbid_local_categories")
        for name in raw.get("forbid_local_categories") or []
    )
    minimum_strength = raw.get("minimum_security_strength")

    return Profile(
        id=profile_id,
        name=str(_require(raw, "name", context)),
        authority=str(raw.get("authority", "")),
        kind=str(raw.get("kind", "algorithm-strength")),
        reference=str(raw.get("reference", "")),
        edition=str(raw.get("edition", "")),
        url=str(raw.get("url", "")),
        summary=str(raw.get("summary", "")),
        notes=str(raw.get("notes", "")),
        minimum_security_strength=None if minimum_strength is None else int(minimum_strength),
        minimum_key_bits={
            str(family).lower(): int(bits)
            for family, bits in (raw.get("minimum_key_bits") or {}).items()
        },
        require_strict_kex=bool(raw.get("require_strict_kex", False)),
        require_post_quantum=bool(raw.get("require_post_quantum", False)),
        rules=rules,
        forbid_local_categories=forbidden,
        edition_id=edition_id,
        current=bool(raw.get("current", not edition_id)),
    )


def check_expectation(expect: Dict[str, Any], value: Optional[str]) -> bool:
    """Whether a directive's value meets one expectation from the policy."""
    (kind, expected), = expect.items()
    if kind == "required":
        return (value is not None) == bool(expected)
    if value is None:
        # sshd -T prints every directive it has a value for, so an absent one
        # genuinely has none; that cannot satisfy a value comparison.
        return False
    lowered = value.strip().lower()
    if kind == "equals":
        return lowered == str(expected).lower()
    if kind == "in":
        return lowered in {str(item).lower() for item in expected}
    if kind == "not_in":
        return lowered not in {str(item).lower() for item in expected}
    if kind in {"at_most", "at_least"}:
        try:
            number = int(lowered)
        except ValueError:
            return False
        return number <= int(expected) if kind == "at_most" else number >= int(expected)
    return True
