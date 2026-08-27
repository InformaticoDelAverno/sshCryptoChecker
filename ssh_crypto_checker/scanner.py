"""Scan orchestration: connect, collect, analyse, summarise.

Targets are scanned concurrently with a thread pool because the work is almost
entirely spent waiting on sockets.
"""

from __future__ import annotations

import base64
import binascii
import concurrent.futures
import datetime
import ipaddress
import socket
import time
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import PRODUCT_NAME, __version__
from .analysis import analyse
from .dns import FAMILY_TO_SSHFP, DNSError, lookup_sshfp
from .known_hosts import load_known_hosts
from .known_hosts import lookup as lookup_known_hosts
from .models import (
    ComplianceStatus,
    HostKeyInfo,
    KnownHostsCheck,
    ProfileConformance,
    ScanReport,
    ScanStatus,
    ScanSummary,
    SshfpCheck,
    Target,
    TargetResult,
    Verdict,
)
from .policy import Policy
from .ssh_config import fetch_client_config
from .ssh_protocol import (
    SSHError,
    fetch_host_key,
    measure_login_grace,
    measure_max_startups,
    probe_auth_methods,
    probe_server,
    select_kex_for_probe,
)
from .sshd_config import fetch_effective_config
from .tunnel import TunnelError, open_tunnel

__all__ = ["ScanOptions", "scan", "scan_target", "summarise"]

#: Guard against a hostile or misconfigured server advertising hundreds of host
#: key algorithms, each of which would cost one extra TCP connection.
MAX_HOST_KEY_PROBES = 12


@dataclass
class ScanOptions:
    """Everything that controls how a scan is performed."""

    timeout: float = 5.0
    concurrency: int = 8
    retries: int = 1
    fetch_host_keys: bool = True
    address_family: int = socket.AF_UNSPEC
    source_address: Optional[str] = None
    max_host_key_probes: int = MAX_HOST_KEY_PROBES
    skip_certificate_probes: bool = False
    """Skip ``*-cert-v01@openssh.com`` algorithms, halving the probes on CA setups."""
    profiles: Optional[Tuple[str, ...]] = None
    """Conformance profiles to evaluate; ``None`` means every one in the policy."""

    probe_auth_methods: bool = False
    """Enumerate authentication methods.

    Off by default: unlike the rest of the scan this completes a key exchange
    and sends a deliberately failing authentication request, which leaves a
    failed-login record in the server's log and could trip an intrusion
    prevention system on a repeated scan.
    """
    auth_username: str = "sshcryptochecker"
    check_sshfp: bool = False
    """Compare the host keys against SSHFP records published in DNS."""
    dns_servers: Optional[Tuple[str, ...]] = None
    """Name servers to ask for SSHFP records. ``None`` uses /etc/resolv.conf."""
    check_known_hosts: bool = False
    """Compare the host keys against the local known_hosts files."""
    known_hosts_paths: Optional[Tuple[str, ...]] = None
    measure_max_startups: bool = False
    """Probe how many unauthenticated connections the server accepts at once."""
    max_startups_probe_limit: int = 20
    audit_config: bool = False
    """Log in and read the effective configuration with 'sshd -T'."""
    ssh_binary: Optional[str] = None
    config_timeout: float = 15.0
    jump_host: Optional[str] = None
    """Reach every target through this bastion, with a local port forward."""
    jump_options: Tuple[str, ...] = ()
    """Extra ssh options for the connection to the bastion."""
    plugins: Optional[Tuple[Any, ...]] = None
    """Detections to run. ``None`` means the ones shipped with the tool."""
    audit_client: bool = False
    """Read the scanning machine's own ssh_config with 'ssh -G'."""
    client_config_file: Optional[str] = None
    """Audit this ssh_config instead of the current user's."""
    measure_login_grace: bool = False
    login_grace_wait: float = 130.0
    """Seconds to wait for the server to drop an unauthenticated connection."""

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if self.retries < 0:
            raise ValueError("retries cannot be negative")


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _host_key_algorithms_to_probe(
    offered: Sequence[str], options: ScanOptions
) -> List[str]:
    """Pick which host key algorithms are worth a dedicated connection.

    Several algorithm names map to the same underlying key (``ssh-rsa``,
    ``rsa-sha2-256`` and ``rsa-sha2-512`` all use the RSA host key), so only one
    representative per key family is probed.
    """
    families = {
        "ssh-ed25519": "ed25519",
        "ssh-ed448": "ed448",
        "ssh-dss": "dsa",
        "rsa-sha2-512": "rsa",
        "rsa-sha2-256": "rsa",
        "ssh-rsa": "rsa",
        "ecdsa-sha2-nistp256": "ecdsa-nistp256",
        "ecdsa-sha2-nistp384": "ecdsa-nistp384",
        "ecdsa-sha2-nistp521": "ecdsa-nistp521",
        "sk-ssh-ed25519@openssh.com": "sk-ed25519",
        "sk-ecdsa-sha2-nistp256@openssh.com": "sk-ecdsa",
    }
    selected: List[str] = []
    seen_families = set()
    for name in offered:
        if options.skip_certificate_probes and "-cert-v0" in name:
            continue
        # Certificates are always probed individually: each one is a distinct
        # object with its own validity window.
        family = None if "-cert-v0" in name else families.get(name, name)
        if family is not None:
            if family in seen_families:
                continue
            seen_families.add(family)
        selected.append(name)
        if len(selected) >= options.max_host_key_probes:
            break
    return selected


def scan_target(
    target: Target, policy: Policy, options: Optional[ScanOptions] = None
) -> TargetResult:
    """Scan a single server and return a fully analysed result."""
    options = options or ScanOptions()
    result = TargetResult(target=target, scanned_at=_utc_now())
    started = time.monotonic()

    # Everything that opens a socket goes through the forward; everything that
    # asks a question about the *name* -- SSHFP, known_hosts -- keeps the real
    # target, because 127.0.0.1 is not what those records are published under.
    tunnel = None
    connect = target
    if options.jump_host:
        try:
            tunnel = open_tunnel(
                options.jump_host,
                target.host,
                target.port,
                ssh_binary=options.ssh_binary or "ssh",
                timeout=max(options.timeout, 15.0),
                extra_options=options.jump_options,
            )
        except TunnelError as exc:
            result.error = str(exc)
            result.verdict = Verdict.ERROR
            result.duration_ms = int((time.monotonic() - started) * 1000)
            return result
        connect = replace(target, host="127.0.0.1", port=tunnel.local_port or 0)

    try:
        return _scan_over(target, connect, result, policy, options, started)
    finally:
        if tunnel is not None:
            tunnel.close()


def _scan_over(
    target: Target,
    connect: Target,
    result: TargetResult,
    policy: Policy,
    options: ScanOptions,
    started: float,
) -> TargetResult:
    """Scan ``target``, opening every connection to ``connect``.

    The two differ only when a bastion is in the way. Keeping them apart is
    what stops the report naming a local forwarding port, and what stops an
    SSHFP lookup being made for 127.0.0.1.
    """
    last_error: Optional[Exception] = None
    attempts = 0
    # A while, not a for over range(retries + 1): every path through the body
    # ends in a break, so the loop can never run out on its own, and writing it
    # as a counted loop left an exit nothing could take.
    while True:
        try:
            banner, kexinit, address = probe_server(
                connect.host,
                connect.port,
                timeout=options.timeout,
                family=options.address_family,
                source_address=options.source_address,
            )
        # One clause, not two: a socket error that escapes probe_server is
        # handled exactly like an SSH one, and splitting them left a branch
        # nothing could take.
        except (SSHError, OSError) as exc:
            last_error = exc
            attempts += 1
            if attempts <= options.retries:
                continue
            break

        result.status = ScanStatus.OK
        result.banner = banner
        result.kexinit = kexinit
        # Through a forward this is 127.0.0.1, which says nothing about the
        # target. Record the bastion instead, which does.
        result.resolved_address = None if options.jump_host else address
        result.reached_via = options.jump_host or ""
        last_error = None
        break

    if result.status is not ScanStatus.OK:
        result.error = str(last_error) if last_error else "unknown error"
        result.verdict = Verdict.ERROR
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    if options.fetch_host_keys and result.kexinit is not None:
        result.host_keys = _collect_host_keys(connect, result, options)

    if options.probe_auth_methods and result.kexinit is not None:
        result.auth_methods = _collect_auth_methods(connect, result, options)

    if options.check_sshfp:
        result.sshfp = _check_sshfp(target, result, options)

    if options.check_known_hosts:
        result.known_hosts = _check_known_hosts(target, result, options)

    # Not through a bastion. The probe counts how many unauthenticated
    # connections the server holds open at once, and every one of them would
    # also be a channel on the bastion's own session -- so what came back would
    # be whichever limit is lower, reported as the target's. A wrong number
    # here is worse than no number.
    if options.measure_max_startups and not options.jump_host:
        result.max_startups_probe_limit = options.max_startups_probe_limit
        result.max_startups = measure_max_startups(
            connect.host,
            connect.port,
            limit=options.max_startups_probe_limit,
            timeout=options.timeout,
            family=options.address_family,
        )

    if options.measure_login_grace:
        result.login_grace_seconds = measure_login_grace(
            connect.host,
            connect.port,
            maximum_wait=options.login_grace_wait,
            connect_timeout=options.timeout,
            family=options.address_family,
            source_address=options.source_address,
        )

    if options.audit_client:
        result.client_config = fetch_client_config(
            target.host,
            target.port,
            ssh_binary=options.ssh_binary or "ssh",
            timeout=options.config_timeout,
            jump_host=options.jump_host,
            extra_options=(
                [*options.jump_options, "-F", options.client_config_file]
                if options.client_config_file
                else options.jump_options
            ),
        )

    if options.audit_config:
        result.effective_config = fetch_effective_config(
            target.host,
            target.port,
            target.credentials,
            timeout=options.config_timeout,
            ssh_binary=options.ssh_binary,
            connect_host=connect.host if options.jump_host else None,
            connect_port=connect.port if options.jump_host else None,
        )

    analyse(result, policy, profiles=options.profiles, plugins=options.plugins)
    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def _collect_host_keys(
    target: Target, result: TargetResult, options: ScanOptions
) -> List[HostKeyInfo]:
    kexinit = result.kexinit
    assert kexinit is not None  # guaranteed by the caller
    kex_algorithm = select_kex_for_probe(kexinit.kex_algorithms)
    if kex_algorithm is None:
        # Happens on hardened servers that only offer post-quantum methods: the
        # scanner cannot drive those, so say so instead of silently reporting
        # that the server has no host keys.
        return [
            HostKeyInfo(
                algorithm=algorithm,
                error=(
                    "the scanner cannot perform any of the key exchange methods this server "
                    "offers, so the host key could not be retrieved"
                ),
            )
            for algorithm in kexinit.host_key_algorithms[:1]
        ]

    host_keys = []
    seen_fingerprints = set()
    for algorithm in _host_key_algorithms_to_probe(kexinit.host_key_algorithms, options):
        key = fetch_host_key(
            target.host,
            target.port,
            host_key_algorithm=algorithm,
            kex_algorithm=kex_algorithm,
            timeout=options.timeout,
            family=options.address_family,
            source_address=options.source_address,
        )
        # Distinct algorithm names can resolve to the same key material, for
        # example when a server offers both rsa-sha2-256 and rsa-sha2-512.
        if key.fingerprint_sha256 and key.fingerprint_sha256 in seen_fingerprints:
            continue
        if key.fingerprint_sha256:
            seen_fingerprints.add(key.fingerprint_sha256)
        host_keys.append(key)
    return host_keys


def scan(
    targets: Sequence[Target],
    policy: Policy,
    options: Optional[ScanOptions] = None,
    on_finish: Optional[Callable[[TargetResult], None]] = None,
    command_line: str = "",
) -> ScanReport:
    """Scan every target concurrently and return a complete report."""
    options = options or ScanOptions()
    started_monotonic = time.monotonic()
    report = ScanReport(
        tool=PRODUCT_NAME,
        version=__version__,
        started_at=_utc_now(),
        command_line=command_line,
        policy={
            "source": str(policy.source),
            "schema_version": policy.schema_version,
            "algorithms_known": policy.algorithm_count(),
            **policy.metadata,
        },
    )

    if not targets:
        report.finished_at = _utc_now()
        report.summary = summarise([])
        return report

    workers = min(options.concurrency, len(targets))
    results: List[Optional[TargetResult]] = [None] * len(targets)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="sshscan"
    ) as executor:
        futures = {}
        for index, target in enumerate(targets):
            futures[executor.submit(scan_target, target, policy, options)] = index

        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # one target must not end the run
                # scan_target turns every failure of a *server* into a result;
                # this catches a failure of this package. It was briefly
                # removed on the grounds that no test could reach it, and the
                # very next run lost a 41-server scan to a one-line NameError.
                # A defect here costs the target it happened on and nothing
                # else, and the error text says which target and what broke.
                result = TargetResult(
                    target=targets[index],
                    status=ScanStatus.ERROR,
                    error=f"internal error scanning this target: {exc}",
                    verdict=Verdict.ERROR,
                    scanned_at=_utc_now(),
                )
            results[index] = result
            if on_finish is not None:
                on_finish(result)

    report.results = [r for r in results if r is not None]
    _run_fleet_checks(report.results, policy, options.plugins)
    report.finished_at = _utc_now()
    report.duration_ms = int((time.monotonic() - started_monotonic) * 1000)
    report.summary = summarise(report.results)
    return report


def _run_fleet_checks(
    results: Sequence[TargetResult], policy: Policy, plugins: Optional[Sequence[Any]]
) -> None:
    """Run the checks that need more than one server, once the scan is done.

    Some problems are not properties of a server. A host key is only shared
    relative to another one, so this cannot happen while a single target is
    being scanned, and it cannot be a per-server plugin however the interface
    is shaped.
    """
    from .plugins import FleetView, ScannedServer, ServerView, builtin_plugins
    from .plugins.runner import run_fleet

    if plugins is None:
        plugins = builtin_plugins()
    if not any(getattr(plugin, "kind", "") == "fleet" for plugin in plugins):
        return

    # A list per address, not one result: an inventory can legitimately name
    # the same server twice, and dropping the finding for all but the last
    # would be a silent loss.
    by_target: Dict[str, List[TargetResult]] = {}
    for result in results:
        by_target.setdefault(str(result.target), []).append(result)
    fleet = FleetView(
        policy=policy,
        servers=[
            ScannedServer(
                target=str(result.target),
                label=result.target.label or "",
                view=ServerView(
                    banner=result.banner,
                    kexinit=result.kexinit,
                    host_keys=result.host_keys,
                    auth_methods=result.auth_methods,
                    config=result.effective_config,
                    client_config=result.client_config,
                    sshfp=result.sshfp,
                    known_hosts=result.known_hosts,
                    login_grace_seconds=result.login_grace_seconds,
                    max_startups=result.max_startups,
                    policy=policy,
                ),
            )
            for result in results
        ],
    )

    for target, findings in run_fleet(plugins, fleet).items():
        for result in by_target.get(target, ()):
            # Inserted at the front: a shared key changes how everything below
            # it should be read.
            for finding in reversed(findings):
                result.findings.insert(0, finding)


def summarise(results: Sequence[TargetResult]) -> ScanSummary:
    """Aggregate counters used by every report format."""
    summary = ScanSummary(total=len(results))
    scores: List[int] = []
    pivot: OrderedDict[str, ProfileConformance] = OrderedDict()

    for result in results:
        if result.ok:
            summary.succeeded += 1
        else:
            summary.failed += 1

        summary.by_verdict[result.verdict.value] = (
            summary.by_verdict.get(result.verdict.value, 0) + 1
        )
        if result.grade:
            summary.by_grade[result.grade] = summary.by_grade.get(result.grade, 0) + 1
        if result.score is not None:
            scores.append(result.score)
        if result.post_quantum.value in {"ready", "enforced"}:
            summary.post_quantum_ready += 1
        matched = [v for v in result.vulnerabilities if not v.undetermined]
        if matched:
            summary.vulnerable += 1
        for match in matched:
            summary.by_vulnerability[match.id] = summary.by_vulnerability.get(match.id, 0) + 1
        if result.security_strength is not None and result.security_strength.effective_bits:
            level = result.security_strength.level_id
            summary.by_strength_level[level] = summary.by_strength_level.get(level, 0) + 1
        for compliance in result.compliance:
            counters = summary.by_profile.setdefault(compliance.profile_id, {})
            counters[compliance.status.value] = counters.get(compliance.status.value, 0) + 1
            entry = pivot.get(compliance.profile_id)
            if entry is None:
                entry = ProfileConformance(
                    profile_id=compliance.profile_id,
                    name=compliance.name,
                    authority=compliance.authority,
                    edition=compliance.edition,
                )
                pivot[compliance.profile_id] = entry
            label = result.target.display_name
            if compliance.status is ComplianceStatus.PASS:
                entry.passed.append(label)
            elif compliance.status is ComplianceStatus.FAIL:
                entry.failed.append(label)
                offenders = [v.subject for v in compliance.violations]
                if offenders:
                    entry.offenders[label] = offenders
                for violation in compliance.violations:
                    if violation.remediation and violation.remediation not in entry.remediation:
                        entry.remediation.append(violation.remediation)
                        # Keep the translatable form in step, so a human report
                        # renders "to comply" in its language while this English
                        # list still serves the machine formats.
                        entry.remediation_specs.append(
                            (violation.remediation_key, violation.remediation_args)
                        )
            else:
                entry.not_assessed.append(label)
        for finding in result.findings:
            summary.by_severity[finding.severity.value] = (
                summary.by_severity.get(finding.severity.value, 0) + 1
            )

    if scores:
        summary.average_score = round(sum(scores) / len(scores), 1)
    # Most widespread first: a fleet report is read to decide what to fix, and
    # that is driven by how many machines share a problem.
    summary.by_vulnerability = dict(
        sorted(summary.by_vulnerability.items(), key=lambda item: (-item[1], item[0]))
    )
    summary.conformance_by_profile = list(pivot.values())
    return summary


def _collect_auth_methods(
    target: Target, result: TargetResult, options: ScanOptions
) -> Any:
    """Ask the server which authentication methods it will accept."""
    kexinit = result.kexinit
    assert kexinit is not None
    kex_algorithm = select_kex_for_probe(kexinit.kex_algorithms)
    if kex_algorithm is None or not kexinit.host_key_algorithms:
        from .models import AuthMethods

        return AuthMethods(
            username=target.credentials.username or options.auth_username,
            error=(
                "the scanner cannot perform any of the key exchange methods this server "
                "offers, so its authentication methods could not be read"
            ),
        )
    return probe_auth_methods(
        target.host,
        target.port,
        kex_algorithm=kex_algorithm,
        host_key_algorithm=kexinit.host_key_algorithms[0],
        username=target.credentials.username or options.auth_username,
        timeout=options.timeout,
        family=options.address_family,
        source_address=options.source_address,
    )


def _check_sshfp(target: Target, result: TargetResult, options: ScanOptions) -> SshfpCheck:
    """Compare the retrieved host keys against SSHFP records in DNS."""
    check = SshfpCheck(queried=True)
    if _looks_like_ip_address(target.host):
        check.error = "SSHFP records are published per name, and this target is an address"
        return check
    # Several targets often share a name (different ports on one host), and the
    # answer will not change during a scan.
    cached = _SSHFP_CACHE.get(target.host)
    if cached is None:
        try:
            cached = lookup_sshfp(
                target.host,
                timeout=options.timeout,
                servers=list(options.dns_servers) if options.dns_servers else None,
            )
        except DNSError as exc:
            _SSHFP_CACHE[target.host] = exc
            check.error = str(exc)
            return check
        _SSHFP_CACHE[target.host] = cached
    if isinstance(cached, DNSError):
        check.error = str(cached)
        return check
    records, authenticated = cached

    check.records_found = len(records)
    check.dnssec_authenticated = authenticated

    # Only SHA-256 records are worth comparing; SHA-1 ones are not trustworthy.
    published = {
        record.fingerprint.lower(): record
        for record in records
        if record.fingerprint_type == 2
    }
    matched_fingerprints = set()

    for key in result.host_keys:
        if key.error is not None or not key.fingerprint_sha256:
            continue
        digest = _sha256_hex(key)
        if digest is None:
            continue
        record = published.get(digest)
        expected = FAMILY_TO_SSHFP.get(key.key_family.lower())
        if record is not None and (expected is None or record.algorithm == expected):
            check.matched.append(f"{key.algorithm} {key.fingerprint_sha256}")
            matched_fingerprints.add(digest)
        else:
            check.keys_without_record.append(f"{key.algorithm} {key.fingerprint_sha256}")

    check.unmatched_records = [
        str(record) for digest, record in published.items() if digest not in matched_fingerprints
    ]
    return check


def _sha256_hex(key: Any) -> Optional[str]:
    """The host key fingerprint as SSHFP stores it: lower-case hexadecimal."""
    if not key.fingerprint_sha256.startswith("SHA256:"):
        return None
    encoded = key.fingerprint_sha256[len("SHA256:") :]
    padding = "=" * (-len(encoded) % 4)
    try:
        return base64.b64decode(encoded + padding).hex()
    except (ValueError, binascii.Error):
        return None


def _looks_like_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


#: DNS answers do not change during a scan, and several targets often share a
#: name. Holds either the answer or the error, so a failure is not retried.
_SSHFP_CACHE: Dict[str, Any] = {}

#: Loaded once per process: the files do not change during a scan.
_KNOWN_HOSTS_CACHE: Dict[Tuple[str, ...], List] = {}


def _check_known_hosts(
    target: Target, result: TargetResult, options: ScanOptions
) -> Any:
    """Compare what the server presents against what a client has recorded."""
    key = tuple(options.known_hosts_paths or ())
    if key not in _KNOWN_HOSTS_CACHE:
        paths = [Path(p) for p in key] if key else None
        _KNOWN_HOSTS_CACHE[key] = load_known_hosts(paths)
    entries = lookup_known_hosts(_KNOWN_HOSTS_CACHE[key], target.host, target.port)

    check = KnownHostsCheck(checked=True, entries_found=len(entries))
    check.sources = sorted({entry.source for entry in entries})
    recorded = {entry.fingerprint: entry for entry in entries}

    presented = {
        key_info.fingerprint_sha256: key_info
        for key_info in result.host_keys
        if key_info.error is None and key_info.fingerprint_sha256
    }
    for fingerprint, entry in recorded.items():
        if entry.marker == "@revoked":
            if fingerprint in presented:
                check.revoked.append(f"{entry.key_type} {fingerprint} ({entry.source})")
            continue
        if fingerprint in presented:
            check.matched.append(f"{entry.key_type} {fingerprint}")
        elif any(k.key_type == entry.key_type for k in presented.values()):
            # Same key type, different key: a rotation or an interception.
            check.changed.append(f"{entry.key_type} recorded {fingerprint} ({entry.source})")
    return check
