"""Data structures shared by the scanner, the analyser and the reporters.

Everything here is a plain dataclass so that a scan result can be converted to
JSON with :func:`to_jsonable` without any custom serialisation logic scattered
around the code base.
"""

from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class Category(str, Enum):
    """Security classification of a single algorithm."""

    RECOMMENDED = "recommended"
    ACCEPTABLE = "acceptable"
    WEAK = "weak"
    INSECURE = "insecure"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"

    @property
    def is_scored(self) -> bool:
        """Whether the category contributes to the numeric score."""
        return self in _SCORED_CATEGORIES


_SCORED_CATEGORIES = frozenset(
    {Category.RECOMMENDED, Category.ACCEPTABLE, Category.WEAK, Category.INSECURE}
)

#: Ordering from best to worst, used to compute "the worst thing on offer".
CATEGORY_ORDER: List[Category] = [
    Category.RECOMMENDED,
    Category.ACCEPTABLE,
    Category.WEAK,
    Category.INSECURE,
]


class Severity(str, Enum):
    """Severity of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: List[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class Verdict(str, Enum):
    """Overall judgement for a scanned server."""

    SECURE = "secure"
    ACCEPTABLE = "acceptable"
    WEAK = "weak"
    INSECURE = "insecure"

    UNKNOWN = "unknown"
    """Reached the server, but the policy could not classify anything it offers.

    Never guess in this case: an unjudgeable server must not be reported as
    either safe or broken.
    """

    ERROR = "error"


class PostQuantumStatus(str, Enum):
    """Post-quantum readiness of the key exchange offer."""

    ENFORCED = "enforced"
    """Every key exchange method offered is a post-quantum hybrid."""

    READY = "ready"
    """At least one post-quantum hybrid method is offered."""

    NOT_READY = "not-ready"
    """No post-quantum key exchange is offered."""

    UNKNOWN = "unknown"
    """The key exchange offer could not be retrieved."""


class CompressionStatus(str, Enum):
    """Whether the server will compress, and when it starts.

    The distinction that matters is not on/off but *when*. Compression that
    begins before authentication puts the decompressor at the disposal of
    anyone who can open a connection; the same algorithm started afterwards
    does not.
    """

    DISABLED = "disabled"
    """Only 'none' is offered: no compression is possible."""
    POST_AUTH = "after-authentication"
    """Only zlib@openssh.com: compression starts once the user is authenticated."""
    PRE_AUTH = "before-authentication"
    """Plain zlib is offered, so a client can have it running before it logs in."""
    UNKNOWN = "unknown"


class ScanStatus(str, Enum):
    """Outcome of the network part of the scan."""

    OK = "ok"
    ERROR = "error"


#: Algorithm classes, in report order.
#: Where each algorithm class lives on a KexInit: the client-to-server field
#: and, for the classes negotiated per direction, the server-to-client one.
#: ALGORITHM_CLASSES is this table's keys, in this order, so the two cannot
#: disagree about which classes exist.
_ALGORITHM_FIELDS = {
    "kex": ("kex_algorithms", None),
    "host_key": ("host_key_algorithms", None),
    "cipher": ("encryption_c2s", "encryption_s2c"),
    "mac": ("mac_c2s", "mac_s2c"),
    "compression": ("compression_c2s", "compression_s2c"),
}

ALGORITHM_CLASSES: List[str] = list(_ALGORITHM_FIELDS)


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #


class AuthMode(str, Enum):
    """How the scanner should authenticate to a target, when it needs to."""

    NONE = "none"
    """Anonymous: no credentials, only what can be seen before authenticating."""
    KEY = "key"
    PASSWORD = "password"
    ANY = "any"
    """Let the SSH client pick; the default."""


@dataclass(frozen=True)
class Credentials:
    """Per-target authentication settings.

    A password is never stored here. Only where to find it is, so a secret
    cannot leak into a JSON report or a traceback by accident: call
    :meth:`resolve_password` at the moment it is needed.
    """

    username: Optional[str] = None
    mode: AuthMode = AuthMode.ANY
    identity_file: Optional[str] = None
    password_file: Optional[str] = None
    password_env: Optional[str] = None

    @property
    def has_password_source(self) -> bool:
        return bool(self.password_file or self.password_env)

    def describe(self) -> str:
        """A one-line summary safe to print, naming no secret."""
        parts = [f"user={self.username}"] if self.username else []
        parts.append(f"auth={self.mode.value}")
        if self.identity_file:
            parts.append(f"key={self.identity_file}")
        if self.password_file:
            parts.append(f"password-file={self.password_file}")
        if self.password_env:
            parts.append(f"password-env=${self.password_env}")
        return " ".join(parts)

    def resolve_password(self) -> Optional[str]:
        """Read the password from its configured source, at the point of use."""
        import os

        if self.password_env:
            value = os.environ.get(self.password_env)
            if value is None:
                raise ValueError(
                    f"environment variable {self.password_env} is not set"
                )
            return value
        if self.password_file:
            try:
                with open(self.password_file, encoding="utf-8") as handle:
                    return handle.readline().rstrip("\n")
            except OSError as exc:
                raise ValueError(f"cannot read {self.password_file}: {exc}") from exc
        return None


@dataclass(frozen=True)
class Target:
    """A server to scan."""

    host: str
    port: int = 22
    label: Optional[str] = None
    source: Optional[str] = None
    """Where the target came from, e.g. a file name and line number."""
    credentials: Credentials = field(default_factory=Credentials)

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    @property
    def display_name(self) -> str:
        return self.label or str(self)


# --------------------------------------------------------------------------- #
# Raw protocol data
# --------------------------------------------------------------------------- #


@dataclass
class BannerInfo:
    """The SSH identification string sent by the server (RFC 4253 section 4.2)."""

    raw: str = ""
    """The identification string as it will be shown, with the characters a
    terminal would act on replaced by their escapes."""
    exact: str = ""
    """Byte for byte what the server sent.

    The exchange hash is computed over this, so one character's difference
    makes every signature fail to verify. It is kept out of every report: it is
    the string a hostile peer has the most control over, and a report is read
    on somebody's terminal.
    """
    protocol_version: str = ""
    software: str = ""
    comments: str = ""
    product: Optional[str] = None
    """Normalised product name, e.g. ``OpenSSH`` or ``Dropbear``."""
    product_version: Optional[str] = None
    pre_banner_lines: List[str] = field(default_factory=list)
    """Lines the server sent before its identification string (a legal banner)."""


@dataclass
class KexInit:
    """Contents of the server's SSH_MSG_KEXINIT packet."""

    kex_algorithms: List[str] = field(default_factory=list)
    host_key_algorithms: List[str] = field(default_factory=list)
    encryption_c2s: List[str] = field(default_factory=list)
    encryption_s2c: List[str] = field(default_factory=list)
    mac_c2s: List[str] = field(default_factory=list)
    mac_s2c: List[str] = field(default_factory=list)
    compression_c2s: List[str] = field(default_factory=list)
    compression_s2c: List[str] = field(default_factory=list)
    languages_c2s: List[str] = field(default_factory=list)
    languages_s2c: List[str] = field(default_factory=list)
    first_kex_packet_follows: bool = False
    cookie: str = ""
    """Hex encoded 16 byte cookie."""

    def algorithms_for(self, algorithm_class: str) -> List[str]:
        """Return the offered algorithms for one of :data:`ALGORITHM_CLASSES`.

        Client-to-server and server-to-client lists are merged, preserving
        order, because a server is only as strong as the weakest algorithm it
        accepts in either direction.

        Dispatched through _ALGORITHM_FIELDS, which is where ALGORITHM_CLASSES
        comes from: a class cannot be in the list of classes without a way to
        read it, and there is no "unknown class" arm here to be unable to
        reach.
        """
        c2s, s2c = _ALGORITHM_FIELDS[algorithm_class]
        if s2c is None:
            return list(getattr(self, c2s))
        return _merge(getattr(self, c2s), getattr(self, s2c))

    def directions_differ(self, algorithm_class: str) -> bool:
        """Whether the two directions advertise different algorithms."""
        pairs = {
            "cipher": (self.encryption_c2s, self.encryption_s2c),
            "mac": (self.mac_c2s, self.mac_s2c),
            "compression": (self.compression_c2s, self.compression_s2c),
        }
        if algorithm_class not in pairs:
            return False
        c2s, s2c = pairs[algorithm_class]
        return c2s != s2c


def _merge(first: List[str], second: List[str]) -> List[str]:
    """Union of two ordered lists, keeping first-seen order."""
    merged = list(first)
    seen = set(first)
    for item in second:
        if item not in seen:
            merged.append(item)
            seen.add(item)
    return merged


# --------------------------------------------------------------------------- #
# Host keys
# --------------------------------------------------------------------------- #


@dataclass
class CertificateInfo:
    """Fields extracted from an OpenSSH host certificate."""

    serial: Optional[int] = None
    cert_type: Optional[str] = None
    key_id: Optional[str] = None
    principals: List[str] = field(default_factory=list)
    valid_after: Optional[int] = None
    valid_before: Optional[int] = None
    ca_key_type: Optional[str] = None
    ca_fingerprint: Optional[str] = None


@dataclass
class HostKeyInfo:
    """A host key retrieved from the server."""

    algorithm: str
    """The host key algorithm that was negotiated to obtain this key."""

    key_type: str = ""
    """The key type read from the key blob itself."""

    bits: Optional[int] = None
    fingerprint_sha256: str = ""
    key_family: str = ""
    """Normalised family used for size requirements: rsa, dsa, ecdsa, ed25519..."""
    is_certificate: bool = False
    certificate: Optional[CertificateInfo] = None
    kex_used: str = ""
    """Key exchange method used to fetch the key."""
    dh_group_bits: Optional[int] = None
    """Size of the Diffie-Hellman group the server picked, when applicable."""
    modulus: Optional[int] = None
    """RSA modulus, kept so a check can do arithmetic on it rather than trust its size."""
    public_exponent: Optional[int] = None
    """RSA public exponent. An even one, or 1, is not a valid key."""
    error: Optional[str] = None


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #


@dataclass
class AuthMethods:
    """The authentication methods a server offers, read before authenticating."""

    username: str = ""
    """The account the methods were requested for; servers may vary by user."""
    methods: List[str] = field(default_factory=list)
    accepted_without_credentials: bool = False
    """The server accepted the ``none`` method: it grants access to anyone."""
    server_sig_algs: List[str] = field(default_factory=list)
    """Signature algorithms accepted for client keys (RFC 8308 server-sig-algs).

    Not visible in the KEXINIT: a server can advertise a strong host key while
    still accepting SHA-1 signatures from clients.
    """
    extensions: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def available(self) -> bool:
        return self.error is None


@dataclass
class AlgorithmAssessment:
    """One offered algorithm, classified against the policy."""

    name: str
    category: Category = Category.UNKNOWN
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    score: Optional[int] = None
    matched_by: str = "unknown"
    """``exact``, ``pattern:<glob>`` or ``unknown``."""
    directions: List[str] = field(default_factory=list)
    """For directional classes: ``client-to-server`` / ``server-to-client``."""


@dataclass
class ClassAssessment:
    """All algorithms offered for a single algorithm class."""

    key: str
    label: str
    algorithms: List[AlgorithmAssessment] = field(default_factory=list)
    score: Optional[int] = None
    worst_category: Optional[Category] = None
    directions_differ: bool = False
    preferred: Optional[str] = None
    """The server's first choice, which is what a permissive client negotiates."""

    def by_category(self, category: Category) -> List[AlgorithmAssessment]:
        return [a for a in self.algorithms if a.category is category]


@dataclass
class Finding:
    """An actionable issue detected on a server."""

    id: str
    severity: Severity
    title: str
    description: str
    remediation: str = ""
    items: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class ScoreBreakdown:
    """How the final score was reached, so the grade can be justified."""

    class_scores: Dict[str, Optional[int]] = field(default_factory=dict)
    class_weights: Dict[str, int] = field(default_factory=dict)
    total_weight: int = 0
    """Sum of the weights of the classes that could actually be scored."""
    base_score: int = 0
    modifiers: List[Dict[str, Any]] = field(default_factory=list)
    applied_caps: List[str] = field(default_factory=list)
    final_score: int = 0


class ComplianceStatus(str, Enum):
    """Outcome of evaluating a server against one conformance profile."""

    PASS = "pass"
    FAIL = "fail"
    NOT_ASSESSED = "not-assessed"
    """The profile needs data this scan did not collect, e.g. host key sizes."""


@dataclass
class ComplianceViolation:
    """One reason a server does not conform to a profile."""

    algorithm_class: str
    subject: str
    """The offending algorithm, key or property."""
    reason: str
    remediation: str = ""
    """What to change to make this violation go away."""
    # Language-neutral form of the two strings above, so a human report can
    # render them in its own language while the machine formats keep the
    # English `reason`/`remediation`. These never serialise (see
    # _INTERNAL_FIELDS): the JSON report carries the English strings only.
    reason_key: str = ""
    reason_args: Dict[str, Any] = field(default_factory=dict)
    remediation_key: str = ""
    remediation_args: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceResult:
    """Verdict for a single conformance profile."""

    profile_id: str
    name: str
    authority: str
    reference: str
    edition: str = ""
    url: str = ""
    summary: str = ""
    notes: str = ""
    kind: str = "algorithm-strength"
    status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    violations: List[ComplianceViolation] = field(default_factory=list)
    unverified: List[str] = field(default_factory=list)
    """Requirements of this profile that the scan could not test at all.

    Non-empty means the answer is 'not assessed' rather than 'pass': the
    server may conform, but this scan did not establish it."""
    caveats: List[str] = field(default_factory=list)
    """Editorial notes on the profile itself, carried into the report."""

    @property
    def conforms(self) -> bool:
        return self.status is ComplianceStatus.PASS


@dataclass
class SecurityStrength:
    """Effective security strength of a server, per NIST SP 800-57."""

    effective_bits: Optional[int] = None
    level_id: str = "unknown"
    level_label: str = "Unknown"
    level_description: str = ""
    per_class: Dict[str, Optional[int]] = field(default_factory=dict)
    limiting: List[str] = field(default_factory=list)
    """The algorithms that hold the effective strength down."""
    reference: str = ""


@dataclass
class Recommendation:
    """A ready-to-paste ``sshd_config`` directive."""

    directive: str
    value: str
    comment: str
    """Why this line, and what applying it would remove.

    Required, deliberately. A ready-to-paste sshd_config directive with no
    explanation is the dangerous artefact this section could produce: somebody
    pastes it without knowing which algorithms it drops, and finds out when a
    client stops connecting.
    """

    def as_config_line(self) -> str:
        return f"{self.directive} {self.value}"


@dataclass
class TargetResult:
    """Everything known about one scanned server."""

    target: Target
    status: ScanStatus = ScanStatus.ERROR
    error: Optional[str] = None
    resolved_address: Optional[str] = None
    reached_via: str = ""
    """The bastion this target was reached through, when one was used."""
    duration_ms: int = 0
    scanned_at: str = ""

    banner: Optional[BannerInfo] = None
    kexinit: Optional[KexInit] = None
    host_keys: List[HostKeyInfo] = field(default_factory=list)
    auth_methods: Optional[AuthMethods] = None
    login_grace_seconds: Optional[float] = None
    """Measured time the server waits before dropping an unauthenticated connection."""
    sshfp: Optional[SshfpCheck] = None
    known_hosts: Optional[KnownHostsCheck] = None
    effective_config: Optional[EffectiveConfig] = None
    client_config: Optional[ClientConfig] = None
    """What the scanning machine's own ssh client would use to reach this target."""
    max_startups: Optional[int] = None
    """Unauthenticated connections accepted before the server refused."""
    max_startups_probe_limit: Optional[int] = None
    """How many were attempted, so 'accepted all of them' is distinguishable."""

    assessments: List[ClassAssessment] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    recommendations: List[Recommendation] = field(default_factory=list)
    compliance: List[ComplianceResult] = field(default_factory=list)
    vulnerabilities: List[Any] = field(default_factory=list)
    """Known vulnerabilities matched by the policy's detection rules."""
    plugin_findings: List[Finding] = field(default_factory=list)
    """Findings produced by check-kind plugins, kept until they are collated."""
    security_strength: Optional[SecurityStrength] = None

    score: Optional[int] = None
    grade: Optional[str] = None
    verdict: Verdict = Verdict.ERROR
    post_quantum: PostQuantumStatus = PostQuantumStatus.UNKNOWN
    compression: CompressionStatus = CompressionStatus.UNKNOWN
    """Whether the server will compress, and whether it can do so before login."""
    strict_kex: bool = False
    score_breakdown: Optional[ScoreBreakdown] = None

    @property
    def ok(self) -> bool:
        return self.status is ScanStatus.OK

    def assessment(self, key: str) -> Optional[ClassAssessment]:
        for assessment in self.assessments:
            if assessment.key == key:
                return assessment
        return None

    def worst_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)).severity


@dataclass(frozen=True)
class FileMode:
    """Ownership and permissions of one file on the audited host."""

    path: str
    mode: str
    """Octal, as ``stat -c %a`` prints it."""
    owner: str
    group: str

    @property
    def octal(self) -> int:
        try:
            return int(self.mode, 8)
        except ValueError:
            return 0

    @property
    def readable_beyond_owner(self) -> bool:
        """Whether anyone but the owner can read, write or enter this path.

        Any of the six bits, not just world-read: a private host key in a
        group somebody can join is as exposed as one that is world readable,
        and sshd refuses to use either.
        """
        return bool(self.octal & 0o077)

    @property
    def group_or_world_writable(self) -> bool:
        return bool(self.octal & 0o022)


#: Options that limit what a stolen key can be used for. ``restrict`` denies
#: everything and adds permissions back, so it counts on its own.
RESTRICTING_OPTIONS = frozenset(
    {
        "restrict",
        "command",
        "from",
        "no-agent-forwarding",
        "no-port-forwarding",
        "no-pty",
        "no-user-rc",
        "no-x11-forwarding",
        "permitopen",
        "permitlisten",
        "principals",
        "tunnel",
    }
)


@dataclass
class AuthorizedKeyEntry:
    """One line of an ``authorized_keys`` file, parsed.

    The base64 key material is deliberately not kept: it is public, but it is
    bulky and the fingerprint identifies the key just as well in a report.
    """

    key_type: str = ""
    bits: Optional[int] = None
    key_family: str = ""
    fingerprint_sha256: str = ""
    comment: str = ""
    options: List[str] = field(default_factory=list)
    is_certificate: bool = False
    """A ``cert-authority`` entry, which trusts a CA rather than one key."""
    is_certificate_authority: bool = False
    expires_at: Optional[int] = None
    """Unix time from an ``expiry-time=`` option, when present."""
    error: Optional[str] = None

    @property
    def option_names(self) -> List[str]:
        return [option.split("=", 1)[0].lower() for option in self.options]

    @property
    def restricted(self) -> bool:
        return bool(RESTRICTING_OPTIONS.intersection(self.option_names))

    @property
    def expired(self) -> bool:
        if self.expires_at is None:
            return False
        return self.expires_at < time.time()

    @property
    def summary(self) -> str:
        """Short identification for a report: never the key material."""
        parts = [self.key_type or "unknown"]
        if self.bits:
            parts.append(f"{self.bits}-bit")
        if self.fingerprint_sha256:
            parts.append(self.fingerprint_sha256)
        if self.comment:
            parts.append(f"({self.comment})")
        return " ".join(parts)


@dataclass
class MatchContext:
    """The configuration one kind of connection would actually be given.

    ``sshd -T`` with no context reports the global configuration, so a Match
    block that relaxes something for one user or network does not appear in it.
    This is the same question asked again with ``-C``, for a connection that
    the block would match.
    """

    criteria: str = ""
    """The Match line this context was built from."""
    context: str = ""
    """The ``-C`` string, so the result can be reproduced by hand."""
    directives: Dict[str, List[str]] = field(default_factory=dict)
    error: Optional[str] = None
    """Why no context could be built, when one could not."""

    @property
    def resolved(self) -> bool:
        return self.error is None and bool(self.directives)

    def value(self, directive: str) -> Optional[str]:
        values = self.directives.get(directive.lower())
        return values[0] if values else None


@dataclass
class ModuliFile:
    """The Diffie-Hellman groups a server has available to offer.

    The group measured during a scan is only the one the server chose for this
    client's request. The file says what else is in there, which is what a
    client asking for less would be given.
    """

    path: str = ""
    sizes: Dict[int, int] = field(default_factory=dict)
    """Modulus size in bits -> how many groups of that size."""

    @property
    def smallest(self) -> Optional[int]:
        return min(self.sizes) if self.sizes else None

    @property
    def total(self) -> int:
        return sum(self.sizes.values())

    def below(self, bits: int) -> Dict[int, int]:
        return {size: count for size, count in self.sizes.items() if size < bits}


@dataclass
class PackageInfo:
    """The distribution package providing sshd, and the OS it came from.

    Every version-based finding carries a caveat that distributions backport
    fixes without changing the advertised version. This is what settles it.
    """

    manager: str = ""
    """``dpkg``, ``rpm`` or ``apk``."""
    name: str = ""
    version: str = ""
    os_name: str = ""
    changelog_source: str = ""
    """Where the changelog was read from, so the reader can check it too."""
    changelog_cves: List[str] = field(default_factory=list)
    """CVE identifiers the installed package's own changelog names."""
    changelog_error: str = ""
    """Why no changelog could be read, when none could."""

    @property
    def changelog_read(self) -> bool:
        return bool(self.changelog_source)

    @property
    def known(self) -> bool:
        return bool(self.version)

    @property
    def looks_patched(self) -> bool:
        """Whether the version carries a distribution revision.

        ``1:8.4p1-5+deb11u7`` is upstream 8.4p1 plus seven Debian revisions,
        which is a different thing from upstream 8.4p1. It does not prove any
        particular fix is in, but it does mean the advertised version is not
        the whole story.
        """
        return any(marker in self.version for marker in ("-", "+", "~", "_"))


@dataclass
class AccountKeys:
    """One account's authorized_keys, from a host-wide sweep."""

    username: str
    path: str
    entries: List[AuthorizedKeyEntry] = field(default_factory=list)
    readable: bool = True
    shared_with: List[str] = field(default_factory=list)
    """Other accounts resolving to this same file, when the path has no %u."""


@dataclass
class UserPrivateKey:
    """A private key found in a user's ~/.ssh."""

    username: str
    path: str
    mode: Optional[FileMode] = None
    encrypted: Optional[bool] = None
    """``None`` when the file could not be read to find out."""
    bits: Optional[int] = None
    key_type: str = ""

    @property
    def exposed(self) -> bool:
        """Readable by somebody other than its owner."""
        return self.mode is not None and bool(self.mode.octal & 0o077)


@dataclass
class EffectiveConfig:
    """A server's resolved configuration, read by logging in.

    Comes from ``sshd -T``, so Include directives are already followed and
    defaults already applied: an absent directive here means sshd genuinely has
    no value for it, not that the file did not mention it.
    """

    attempted: bool = False
    available: bool = False
    username: str = ""
    directives: Dict[str, List[str]] = field(default_factory=dict)
    file_modes: List[FileMode] = field(default_factory=list)
    authorized_keys: List[AuthorizedKeyEntry] = field(default_factory=list)
    match_blocks: List[str] = field(default_factory=list)
    match_contexts: List[MatchContext] = field(default_factory=list)
    """Each Match block resolved with 'sshd -T -C', or why it could not be."""
    """Match lines found in the configuration files, which sshd -T cannot show."""
    include_directives: List[str] = field(default_factory=list)
    moduli: Optional[ModuliFile] = None
    package: Optional[PackageInfo] = None
    accounts: List[AccountKeys] = field(default_factory=list)
    """authorized_keys for every account that can log in, not just the audited one."""
    unreadable_accounts: List[str] = field(default_factory=list)
    """Accounts whose file exists and could not be read, so nothing is claimed about them."""
    user_keys: List[UserPrivateKey] = field(default_factory=list)
    error: Optional[str] = None

    def value(self, directive: str) -> Optional[str]:
        values = self.directives.get(directive.lower())
        return values[0] if values else None

    def values(self, directive: str) -> List[str]:
        return list(self.directives.get(directive.lower(), []))


@dataclass
class ClientConfig:
    """What this machine's ssh client would use to reach one target.

    Read with ``ssh -G``, so Host and Match blocks are already resolved: an
    absent directive here is one the client genuinely has no value for.
    """

    attempted: bool = False
    available: bool = False
    target: str = ""
    directives: Dict[str, List[str]] = field(default_factory=dict)
    error: Optional[str] = None

    def value(self, directive: str) -> Optional[str]:
        """The resolved value of a client directive.

        No values() beside it, unlike the server's configuration: 'ssh -G'
        prints one line per directive, and a second accessor nobody called was
        a second way to ask the same question.
        """
        values = self.directives.get(directive.lower())
        return values[0] if values else None


@dataclass
class KnownHostsCheck:
    """Result of comparing the host keys against a local known_hosts file."""

    checked: bool = False
    entries_found: int = 0
    matched: List[str] = field(default_factory=list)
    changed: List[str] = field(default_factory=list)
    """Recorded keys of a type the server still offers, but with a different key."""
    revoked: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


@dataclass
class SshfpCheck:
    """Result of comparing DNS SSHFP records against the real host keys."""

    queried: bool = False
    records_found: int = 0
    matched: List[str] = field(default_factory=list)
    """Fingerprints present in DNS that match a key the server presented."""
    unmatched_records: List[str] = field(default_factory=list)
    keys_without_record: List[str] = field(default_factory=list)
    dnssec_authenticated: bool = False
    """The resolver set the AD bit, so it validated the answer with DNSSEC."""
    error: Optional[str] = None


@dataclass
class ProfileConformance:
    """One conformance profile, with the scanned servers grouped by outcome.

    This is the estate seen 'by normativa': instead of asking each server which
    profiles it meets, it asks each profile which servers meet it, so 'how are
    we doing on ISO?' is one place to look rather than a column to reconstruct.
    """

    profile_id: str
    name: str
    authority: str
    edition: str = ""
    passed: List[str] = field(default_factory=list)
    """display names of the servers that conform"""
    failed: List[str] = field(default_factory=list)
    not_assessed: List[str] = field(default_factory=list)
    offenders: Dict[str, List[str]] = field(default_factory=dict)
    """failing server -> the exact algorithms, keys or properties that break it,
    so a report says WHAT fails, not only that it fails."""
    remediation: List[str] = field(default_factory=list)
    """distinct 'what to change to comply' lines for this profile, gathered from
    the violations of the servers that fail it."""
    remediation_specs: List[Tuple[str, Dict[str, Any]]] = field(default_factory=list)
    """the (message key, args) behind each English line in ``remediation``, in
    the same order, so a human report can translate them. Does not serialise."""

    @property
    def assessed(self) -> int:
        """Servers this profile had an outcome for (pass, fail or not-assessed)."""
        return len(self.passed) + len(self.failed) + len(self.not_assessed)


@dataclass
class ScanSummary:
    """Aggregate counters across all scanned targets."""

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    by_verdict: Dict[str, int] = field(default_factory=dict)
    by_grade: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    post_quantum_ready: int = 0
    """Nota: no hay contador dedicado a ninguna CVE. Lo hubo para Terrapin, y
    un contador propio en el resumen es lo que hace que una vulnerabilidad
    parezca mas importante que otra igual de grave. by_vulnerability las
    cuenta todas, ordenadas por cuantas maquinas las comparten."""
    vulnerable: int = 0
    """Targets matching at least one known vulnerability."""
    by_vulnerability: Dict[str, int] = field(default_factory=dict)
    """Vulnerability id -> how many targets matched it, worst severity first."""
    average_score: Optional[float] = None
    by_strength_level: Dict[str, int] = field(default_factory=dict)
    by_profile: Dict[str, Dict[str, int]] = field(default_factory=dict)
    """profile id -> {"pass": n, "fail": n, "not-assessed": n}"""
    conformance_by_profile: List[ProfileConformance] = field(default_factory=list)
    """The estate grouped by normativa: one entry per profile, with the servers
    that pass, fail or could not be assessed. Same facts as each server's
    compliance list, pivoted so a single normativa can be read at a glance."""


@dataclass
class ScanReport:
    """The complete result of a run, and the root object of the JSON output."""

    tool: str
    version: str
    started_at: str
    finished_at: str = ""
    duration_ms: int = 0
    policy: Dict[str, Any] = field(default_factory=dict)
    command_line: str = ""
    results: List[TargetResult] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #


#: Field names whose value is never written to a report, whatever it holds.
_REDACTED_FIELDS = frozenset({"password", "passphrase", "secret", "token", "private_key"})

#: Fields kept out of every report because they exist for the protocol rather
#: than for a reader. BannerInfo.exact is the server's identification string
#: byte for byte -- the exchange hash needs it unchanged, and it is the string
#: a hostile peer has the most control over, so it is not written anywhere.
_INTERNAL_FIELDS = frozenset({
    "exact",
    # i18n metadata on compliance violations / conformance: the report carries
    # the English `reason`/`remediation`, never these render-time helpers.
    "reason_key", "reason_args", "remediation_key", "remediation_args",
    "remediation_specs",
})


def to_jsonable(value: Any) -> Any:
    """Recursively convert dataclasses, enums and sets into JSON-safe values.

    Fields whose name suggests a secret are redacted rather than serialised, so
    a credential cannot reach a report through a path nobody thought about.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            f.name: (
                "[redacted]" if f.name in _REDACTED_FIELDS
                else to_jsonable(getattr(value, f.name))
            )
            for f in dataclasses.fields(value)
            if f.name not in _INTERNAL_FIELDS
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {
            str(k): ("[redacted]" if str(k) in _REDACTED_FIELDS else to_jsonable(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    return value
