"""A small web front end over the same scan the command line runs.

An ADDITIONAL way in, not a replacement: the page collects the same options the
CLI takes, the scan is the same ``scan()`` with the same policy, and the report
is the same ``render()`` -- downloadable in every format the tool defines, in
either language. Zero dependencies, like everything else here: the server is
``http.server`` from the standard library.

Run it with::

    python -m ssh_crypto_checker.web [--host 127.0.0.1] [--port 8417]

Deployment-time functionality arrives the way containers expect, not through
web forms:

- **Custom policy**: mount it and set ``SSH_CRYPTO_CHECKER_CONFIG`` (the same
  variable the CLI honours).
- **Detection plugins**: set ``SSH_CRYPTO_CHECKER_PLUGIN_DIR`` (colon-separated
  directories); loaded once at start-up, exactly as ``--plugin-dir`` would.
- **Access token** (optional): set ``SSH_CRYPTO_CHECKER_WEB_TOKEN`` and every
  ``/api/*`` request must carry it (``X-Auth-Token`` header, constant-time
  compare). Leave it unset -- the default -- for **open access**: anyone who
  reaches the port uses it, on any interface, no accounts, no sign-in. That is
  the frictionless shape on a trusted LAN; setting the token is the one switch
  that closes it. For an internet-facing deployment pair the token with the
  private-target filter below and a TLS-terminating proxy.
- **Refuse internal targets**: set ``SSH_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE=1``
  and a target that resolves to a private, loopback, link-local or reserved
  address is turned away. Defence in depth for an internet-facing deployment.

What deliberately stays CLI-only: ``--audit-config`` (it authenticates with
credentials that do not belong in a browser form), ``--known-hosts`` and the
history/comparison files (they live on the operator's filesystem), and
``--audit-client`` (it audits the machine the tool runs on -- in a container
that is the container).

Security posture (what this layer is, and is not):

- The web layer caps every dimension an anonymous caller could inflate -- body
  size, target count, concurrency, timeout, retries, login-grace, max-startups,
  and the number of scans running at once -- so a request cannot exhaust the
  service. Responses carry ``nosniff``, ``X-Frame-Options: DENY``, a strict
  ``Content-Security-Policy`` and ``Referrer-Policy: no-referrer``; reports
  download as attachments; the token compare is constant time; the report
  renderer escapes everything a scanned server controls (a hostile banner
  cannot inject script). ``tests/test_web.py`` holds all of this.
- Two things it cannot fix in code, only at the boundary. First, scanning
  arbitrary hosts IS the tool's function, so an open deployment is an SSRF
  machine: gate it with the token, the private-target filter, and network
  placement (an egress firewall with no route to your internal ranges is the
  hard guarantee the app-level filter only approximates). Second,
  ``http.server`` is the standard library's basic server, not a hardened edge:
  for the open internet put it behind a reverse proxy that terminates TLS,
  rate-limits, and rejects malformed requests. Treat this as an internal tool
  unless you have done both.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import tempfile
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import PRODUCT_NAME, __version__
from ..cli import _profile_not_met
from ..i18n import LANGUAGES, Translator, resolve_language
from ..messages import MESSAGES
from ..models import ScanReport
from ..plugins import load_plugins
from ..policy import Policy, PolicyError, load_policy
from ..reporting import EXTENSIONS, FORMATS, RenderOptions, render
from ..targets import DEFAULT_PORT, build_targets

__all__ = ["create_server", "main"]

#: Set truthy to REQUIRE a token: every /api request must then carry a matching
#: X-Auth-Token. Unset (the default) the API is OPEN -- anyone who can reach the
#: port uses it, no accounts, no sign-in. Setting a token is the one switch that
#: closes it; on a public edge pair it with BLOCK_PRIVATE_VAR and a TLS proxy.
TOKEN_VAR = "SSH_CRYPTO_CHECKER_WEB_TOKEN"
PLUGIN_VAR = "SSH_CRYPTO_CHECKER_PLUGIN_DIR"
#: When set to a truthy value, a target that resolves to a private, loopback,
#: link-local or otherwise-reserved address is refused. Defence in depth for an
#: internet-facing deployment: it stops the obvious "use your scanner to reach
#: my internal network / 169.254.169.254" abuse. It is BEST EFFORT (a name can
#: rebind between this check and the scan's own resolve); the hard guarantee is
#: network egress control, documented beside it.
BLOCK_PRIVATE_VAR = "SSH_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE"

#: Finished jobs kept for download. Oldest evicted beyond this; a container
#: serving one team does not need more, and unbounded memory is a bug.
MAX_JOBS = 64

# --- Resource ceilings. Every dimension an anonymous caller could inflate has
# a cap, because "publish it on the internet" means someone will try. Generous
# for real use, finite against abuse. --------------------------------------- #
#: Largest request body accepted, before it is read (a huge Content-Length must
#: not turn into a huge allocation). Covers targets + a pasted inventory.
MAX_BODY_BYTES = 2 * 1024 * 1024
#: Most targets one request may ask for. Beyond this it is a scan of somebody
#: else's estate, or an attempt to tie up the service.
MAX_TARGETS = 2048
#: Most DNS servers (for --sshfp) one request may name.
MAX_DNS_SERVERS = 8
#: Scans allowed to run at once across all callers. Past this the answer is
#: 503, not an unbounded pile of threads and sockets.
MAX_RUNNING_JOBS = 8
#: Handler threads (TCP connections) allowed at once. Bounds the one dimension
#: the token cannot -- a connection is accepted, and its thread spawned, before
#: auth runs -- so a flood cannot exhaust threads/FDs anonymously. The reverse
#: proxy is still the real edge; this is the in-process floor.
MAX_CONNECTIONS = 64
#: Ceiling on simultaneous OUTBOUND sockets one scan may open. The max-startups
#: probe holds ``max_startups`` connections open at once, and ``concurrency``
#: targets run in parallel, so their PRODUCT is the real number -- capped here
#: rather than left to multiply two individually-bounded knobs into tens of
#: thousands of file descriptors.
MAX_PROBE_SOCKETS = 256
#: Upper bounds on the numeric knobs, so none can be set to "occupy a worker
#: forever" or "open a million sockets". Lower than the CLI's, on purpose: a
#: shared public form is not an operator tuning their own ulimit.
LIMITS = {
    "port": (1, 65535),
    "timeout": (0.1, 120.0),
    "concurrency": (1, 32),
    "retries": (0, 5),
    "login_grace": (0.1, 300.0),
    "max_startups": (1, 64),
}

_PAGE = Path(__file__).with_name("page.html")

_CONTENT_TYPES = {
    "console": "text/plain; charset=utf-8",
    "txt": "text/plain; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "sarif": "application/json; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "inventory": "text/markdown; charset=utf-8",
    "openmetrics": "text/plain; charset=utf-8",
}


class Job:
    """One scan: its progress while running, its report when done."""

    def __init__(self, language: str, policy: Policy, total: int,
                 presentation: Dict[str, bool], required: List[str]):
        self.id = secrets.token_urlsafe(8)
        self.language = language
        self.policy = policy
        self.total = total
        self.presentation = presentation
        self.required = required
        self.done = 0
        self.status = "running"
        self.error = ""
        self.report: Optional[ScanReport] = None
        #: Rendered output, cached per format: a report is re-requested (each
        #: --format is a separate download) and rendering is O(targets), so the
        #: same bytes are produced once, not on every GET.
        self.rendered: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    def tick(self) -> None:
        """One target finished. Called from several scanner threads at once, so
        the increment is locked -- an unlocked += drops updates."""
        with self._lock:
            self.done += 1

    def as_status(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id, "status": self.status,
            "done": self.done, "total": self.total,
        }
        if self.status == "error":
            payload["error"] = self.error
        if self.report is not None:
            summary = self.report.summary
            payload["summary"] = {
                "total": summary.total,
                "unreachable": summary.failed,
                "average_score": summary.average_score,
                "required_profile_failed": _profile_not_met(self.report, self.required),
            }
        return payload


class TooBusyError(Exception):
    """Raised when the concurrent-scan ceiling is reached; becomes a 503."""


class _State:
    """What the handler needs beyond the request: jobs and configuration."""

    def __init__(self, token: str, plugins: Tuple[Any, ...], block_private: bool):
        self.token = token
        self.plugins = plugins
        self.block_private = block_private
        self.jobs: OrderedDict[str, Job] = OrderedDict()
        self.running = 0
        self.lock = threading.Lock()

    def reserve(self) -> None:
        """Claim one of the concurrent-scan slots, or refuse."""
        with self.lock:
            if self.running >= MAX_RUNNING_JOBS:
                raise TooBusyError(f"{MAX_RUNNING_JOBS} scans already running; try again shortly")
            self.running += 1

    def release(self) -> None:
        with self.lock:
            self.running = max(0, self.running - 1)

    def add(self, job: Job) -> None:
        with self.lock:
            self.jobs[job.id] = job
            while len(self.jobs) > MAX_JOBS:
                self.jobs.popitem(last=False)

    def get(self, job_id: str) -> Optional[Job]:
        with self.lock:
            return self.jobs.get(job_id)

    def remove(self, job_id: str) -> None:
        with self.lock:
            self.jobs.pop(job_id, None)


def _parse_request(body: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the scan request into plain values, or raise ValueError.

    The names mirror the CLI options on purpose: the page is a form over the
    same vocabulary, not a second vocabulary.
    """
    if not isinstance(body, dict):
        raise ValueError("the request body must be a JSON object")

    def _list_of_str(name: str, cap: int) -> List[str]:
        value = body.get(name, [])
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            raise ValueError(f"'{name}' must be a list of strings")
        cleaned = [x.strip() for x in value if x.strip()]
        if len(cleaned) > cap:
            raise ValueError(f"'{name}' has {len(cleaned)} entries; at most {cap} allowed")
        return cleaned

    targets = _list_of_str("targets", MAX_TARGETS)
    inventory = body.get("inventory", "")
    if not isinstance(inventory, str):
        raise ValueError("'inventory' must be text")
    if inventory.count("\n") + 1 > MAX_TARGETS:
        raise ValueError(f"the inventory has more than {MAX_TARGETS} lines")
    if not targets and not inventory.strip():
        raise ValueError("nothing to scan: give at least one target or an inventory")

    def _number(name: str, default: float) -> float:
        low, high = LIMITS[name]
        value = body.get(name, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"'{name}' must be a number")
        if not (low <= value <= high):
            raise ValueError(f"'{name}' must be between {low} and {high}")
        return float(value)

    family = body.get("family", "auto")
    if family not in ("auto", "4", "6"):
        raise ValueError("'family' must be one of auto, 4, 6")

    def _flag(name: str) -> bool:
        return bool(body.get(name, False))

    login_grace = body.get("login_grace")
    if login_grace is not None:
        login_grace = _number("login_grace", 130.0)
    max_startups = body.get("max_startups")
    if max_startups is not None:
        if isinstance(max_startups, bool) or not isinstance(max_startups, int):
            raise ValueError("'max_startups' must be a whole number, or absent")
        low, high = LIMITS["max_startups"]
        if not (low <= max_startups <= high):
            raise ValueError(f"'max_startups' must be between {low} and {high}")

    concurrency = int(_number("concurrency", 8))
    # The max-startups probe holds `max_startups` sockets open per target, and
    # `concurrency` targets run at once: their product is the real outbound-FD
    # count, so it -- not just each factor -- must be bounded.
    if max_startups is not None and concurrency * max_startups > MAX_PROBE_SOCKETS:
        raise ValueError(
            f"concurrency x max_startups must be at most {MAX_PROBE_SOCKETS} "
            "(they multiply into simultaneous connections)"
        )

    return {
        "targets": targets,
        "inventory": inventory,
        "port": int(_number("port", DEFAULT_PORT)),
        "timeout": _number("timeout", 5.0),
        "concurrency": concurrency,
        "retries": int(_number("retries", 1)),
        "family": family,
        "no_host_keys": _flag("no_host_keys"),
        "no_cert_probes": _flag("no_cert_probes"),
        "auth_methods": _flag("auth_methods"),
        "sshfp": _flag("sshfp"),
        "dns_servers": _list_of_str("dns_servers", MAX_DNS_SERVERS),
        "login_grace": None if login_grace is None else float(login_grace),
        "max_startups": max_startups,
        "profiles": _list_of_str("profiles", 128),
        "require": _list_of_str("require", 128),
        "lang": resolve_language(str(body.get("lang", "")) or None),
        "summary_only": _flag("summary_only"),
        "notes": _flag("notes"),
        "no_config_suggestions": _flag("no_config_suggestions"),
    }


def _body_length(header_value: Optional[str]) -> int:
    """The validated request-body length, or raise ValueError.

    A pure helper so the malformed cases are testable without a socket (and so
    a handler thread's coverage never hides them).
    """
    try:
        length = int(header_value or 0)
    except ValueError:
        raise ValueError("invalid Content-Length") from None
    if length < 0:
        raise ValueError("invalid Content-Length")
    return length


def _is_private_address(address: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:  # pragma: no cover - getaddrinfo returns real addresses
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _refuse_private_targets(targets: Any) -> None:
    """Refuse any target that resolves to an internal address.

    Best effort, on by ``BLOCK_PRIVATE_VAR``: a name can rebind between here and
    the scan's own resolve, so this is defence in depth, not the guarantee --
    that is network egress control. It does stop the obvious abuse of a public
    scanner: 127.0.0.1, 169.254.169.254, 10.0.0.0/8 and the rest.
    """
    import socket

    for target in targets:
        try:
            infos = socket.getaddrinfo(target.host, target.port, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            continue  # a name that does not resolve is the scanner's problem, not a bypass
        for info in infos:
            if _is_private_address(str(info[4][0])):
                raise ValueError(
                    f"target '{target.host}' resolves to a private or reserved "
                    "address, which this deployment refuses to scan"
                )


def _refuse_private_dns(dns_servers: List[str]) -> None:
    """The SSHFP DNS server is another host this service will reach out to, so
    the private-address filter has to cover it too -- otherwise BLOCK_PRIVATE
    leaves a UDP channel straight at 169.254.169.254 and friends."""
    import socket

    for spec in dns_servers:
        host = spec
        # 'addr:port' and '[v6]:port', the forms dns.split_server accepts.
        if spec.startswith("[") and "]" in spec:
            host = spec[1:spec.index("]")]
        elif spec.count(":") == 1:
            host = spec.rsplit(":", 1)[0]
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_UDP)
        except socket.gaierror:
            continue
        for info in infos:
            if _is_private_address(str(info[4][0])):
                raise ValueError(
                    f"DNS server '{host}' is a private or reserved address, "
                    "which this deployment refuses to query"
                )


def _resolve_profiles(policy: Policy, wanted: List[str], require: List[str]) -> List[str]:
    """The CLI's rules, held here too: ids must exist, require ⊆ evaluate."""
    for profile_id in wanted + require:
        if policy.resolve_profile(profile_id) is None:
            raise ValueError(f"unknown profile '{profile_id}'")
    if wanted:
        missing = [r for r in require if r not in wanted]
        if missing:
            raise ValueError(
                "requiring a profile implies evaluating it; not evaluated: "
                + ", ".join(missing)
            )
    return wanted


def _start_scan(state: _State, request: Dict[str, Any]) -> Job:
    """Build everything the scan needs and launch it on its own thread."""
    import socket

    from ..scanner import ScanOptions, scan

    try:
        policy = load_policy(None, request["lang"])
    except PolicyError as exc:  # pragma: no cover - needs a broken deployment
        raise ValueError(str(exc)) from exc
    _resolve_profiles(policy, request["profiles"], request["require"])

    files: List[Path] = []
    inventory_path = ""
    if request["inventory"].strip():
        try:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".txt", prefix="sshcc-web-", delete=False, encoding="utf-8"
            ) as holder:
                inventory_path = holder.name
                holder.write(request["inventory"])
        except OSError:  # pragma: no cover - a failing /tmp write
            if inventory_path:
                os.unlink(inventory_path)
            raise ValueError("could not stage the inventory") from None
        files = [Path(inventory_path)]
    try:
        targets, errors = build_targets(request["targets"], files, request["port"])
    finally:
        if inventory_path:
            os.unlink(inventory_path)
    if errors:
        # The parser labels inventory errors with the temp path; the caller has
        # no business seeing it (it names the tempdir and the naming scheme).
        # Only when there IS a temp path -- replacing "" would corrupt every
        # message.
        if inventory_path:
            errors = [e.replace(inventory_path, "inventory") for e in errors]
        raise ValueError("; ".join(errors))
    if not targets:
        raise ValueError("nothing to scan: no valid target survived parsing")
    # The two target sources are capped apart; their sum must not exceed the cap.
    if len(targets) > MAX_TARGETS:
        raise ValueError(f"more than {MAX_TARGETS} targets in total")
    if state.block_private:
        _refuse_private_targets(targets)
        _refuse_private_dns(request["dns_servers"])

    options = ScanOptions(
        timeout=request["timeout"],
        concurrency=request["concurrency"],
        retries=request["retries"],
        fetch_host_keys=not request["no_host_keys"],
        skip_certificate_probes=request["no_cert_probes"],
        address_family=(
            socket.AF_INET if request["family"] == "4"
            else socket.AF_INET6 if request["family"] == "6"
            else socket.AF_UNSPEC
        ),
        profiles=tuple(request["profiles"]) or None,
        probe_auth_methods=request["auth_methods"],
        check_sshfp=request["sshfp"],
        dns_servers=tuple(request["dns_servers"]) or None,
        measure_login_grace=request["login_grace"] is not None,
        login_grace_wait=request["login_grace"] or 130.0,
        measure_max_startups=request["max_startups"] is not None,
        max_startups_probe_limit=request["max_startups"] or 20,
        plugins=state.plugins,
    )

    job = Job(
        language=request["lang"],
        policy=policy,
        total=len(targets),
        presentation={
            "summary_only": request["summary_only"],
            "notes": request["notes"],
            "no_config_suggestions": request["no_config_suggestions"],
        },
        required=request["require"],
    )
    # Claim a concurrency slot last, once the request is known good, so a
    # rejected request never consumes one. TooBusyError propagates to a 503.
    state.reserve()
    state.add(job)

    def _tick(_result: Any) -> None:
        job.tick()

    def _run() -> None:
        try:
            job.report = scan(targets, policy, options, on_finish=_tick)
            job.status = "done"
        except Exception as exc:  # pragma: no cover - no known trigger, kept as a net
            job.status = "error"
            job.error = str(exc)
        finally:
            state.release()

    try:
        threading.Thread(target=_run, daemon=True).start()
    except BaseException as err:
        # start() can raise (thread/memory exhaustion). Without this the slot
        # reserved above would leak, and eight leaks wedge the service until a
        # restart. Give it back and drop the job, then let it become a 503.
        state.release()
        state.remove(job.id)
        raise TooBusyError("could not start the scan; the server is out of capacity") from err
    return job


def _render_job(job: Job, output_format: str) -> bytes:
    if output_format not in FORMATS:
        raise ValueError(
            f"unknown format '{output_format}'; valid: {', '.join(sorted(FORMATS))}"
        )
    cached = job.rendered.get(output_format)
    if cached is not None:
        return cached
    options = RenderOptions(
        color=False,
        unicode=True,
        width=100,
        summary_only=job.presentation["summary_only"],
        include_config_snippet=not job.presentation["no_config_suggestions"],
        show_algorithm_notes=job.presentation["notes"],
        translator=Translator(job.language, MESSAGES),
    )
    assert job.report is not None  # guarded by the caller
    body = render(output_format, job.report, job.policy, options).encode("utf-8")
    job.rendered[output_format] = body
    return body


def _meta(policy: Policy) -> Dict[str, Any]:
    return {
        "tool": PRODUCT_NAME,
        "version": __version__,
        "languages": list(LANGUAGES),
        "formats": ["console", *sorted(n for n in FORMATS if n != "console")],
        "profiles": [
            {
                "id": profile.id,
                "name": profile.name,
                "authority": profile.authority,
                "edition": profile.edition,
            }
            for profile in policy.profiles.values()
        ],
    }


#: Locks in the browser: no framing, no sniffing, and a policy that forbids
#: loading anything off-origin. The page is entirely self-contained, so the
#: strictest CSP that still lets its own inline script run is the right one; a
#: downloaded report is served ``attachment`` and never rendered in this origin.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
}


def _make_handler(state: _State) -> type:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"{PRODUCT_NAME}-web/{__version__}"
        protocol_version = "HTTP/1.1"
        #: A slow client must not pin a thread forever (a slow-loris hedge; the
        #: real edge protection is a reverse proxy, documented in server.py).
        timeout = 30

        def version_string(self) -> str:
            return self.server_version  # not the Python version too; free fingerprint

        def log_message(self, format: str, *args: Any) -> None:
            pass  # a scan target in every access-log line helps nobody

        # -- plumbing --------------------------------------------------- #

        def _send(self, code: int, body: bytes, content_type: str,
                  extra: Optional[Dict[str, str]] = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in _SECURITY_HEADERS.items():
                self.send_header(name, value)
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: Dict[str, Any]) -> None:
            self._send(code, json.dumps(payload).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _authorised(self) -> bool:
            if not state.token:
                return True
            supplied = self.headers.get("X-Auth-Token", "")
            # Constant time: a plain == leaks the token one character at a time
            # to anyone who can measure the reply.
            if secrets.compare_digest(supplied, state.token):
                return True
            self._json(401, {"error": "missing or wrong X-Auth-Token"})
            return False

        def _path_and_query(self) -> Tuple[str, Dict[str, str]]:
            path, _, query = self.path.partition("?")
            params = {}
            for pair in query.split("&"):
                name, _, value = pair.partition("=")
                if name:
                    params[name] = value
            return path, params

        # -- routes ----------------------------------------------------- #

        def do_GET(self) -> None:
            path, params = self._path_and_query()
            if path == "/" or path == "/index.html":
                self._send(200, _PAGE.read_bytes(), "text/html; charset=utf-8")
                return
            if not path.startswith("/api/"):
                self._json(404, {"error": "not found"})
                return
            if not self._authorised():
                return
            if path == "/api/meta":
                language = resolve_language(params.get("lang") or None)
                self._json(200, _meta(load_policy(None, language)))
                return
            parts = path.split("/")  # '', 'api', 'scan', <id>[, 'report']
            if len(parts) == 4 and parts[2] == "scan":
                job = state.get(parts[3])
                if job is None:
                    self._json(404, {"error": "no such scan"})
                    return
                self._json(200, job.as_status())
                return
            if len(parts) == 5 and parts[2] == "scan" and parts[4] == "report":
                job = state.get(parts[3])
                if job is None:
                    self._json(404, {"error": "no such scan"})
                    return
                if job.report is None:
                    self._json(409, {"error": f"scan is {job.status}; no report yet"})
                    return
                name = params.get("format", "console")
                try:
                    body = _render_job(job, name)
                except ValueError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                filename = f"scan-{job.id}{EXTENSIONS[name]}"
                self._send(200, body, _CONTENT_TYPES[name], {
                    "Content-Disposition": f'attachment; filename="{filename}"',
                })
                return
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            path, _params = self._path_and_query()
            if path != "/api/scan":
                self._json(404, {"error": "not found"})
                return
            if not self._authorised():
                # The body was not read: on a keep-alive socket the next request
                # would be parsed starting mid-body. Close instead of desyncing.
                self.close_connection = True
                return
            try:
                length = _body_length(self.headers.get("Content-Length"))
            except ValueError as exc:
                self.close_connection = True  # body unread; same desync hazard
                self._json(400, {"error": str(exc)})
                return
            if length > MAX_BODY_BYTES:
                # Do not read the oversized body: reject and drop the connection
                # rather than allocate it or leave it half-read for the next
                # request on a keep-alive socket to trip over.
                self.close_connection = True
                self._json(413, {"error": f"request body over {MAX_BODY_BYTES} bytes"})
                return
            raw = self.rfile.read(length) if length else b""
            try:
                request = _parse_request(json.loads(raw.decode("utf-8") or "null"))
                job = _start_scan(state, request)
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError,
                    RecursionError) as exc:
                # RecursionError: deeply nested JSON, well under the size cap.
                message = str(exc) or exc.__class__.__name__
                self._json(400, {"error": message})
                return
            except TooBusyError as exc:
                self._json(503, {"error": str(exc)})
                return
            self._json(202, {"id": job.id})

    return Handler


class _BoundedServer(ThreadingHTTPServer):
    """A ThreadingHTTPServer that will not spawn more than MAX_CONNECTIONS
    handler threads at once.

    ``http.server`` starts a thread per connection, before any auth runs, so
    without this a flood of open sockets exhausts threads and file descriptors
    anonymously -- the one dimension the token cannot guard. Excess connections
    are closed at once instead of queued, so a slow flood cannot bank them. The
    reverse proxy remains the real edge; this is the in-process floor.
    """

    daemon_threads = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.close_request(request)  # over capacity: drop it, do not queue
            return
        super().process_request(request, client_address)

    def shutdown_request(self, request: Any) -> None:
        # Runs in the handler thread's finally, once per accepted connection --
        # exactly the ones that acquired a slot, so releases balance acquires.
        try:
            super().shutdown_request(request)
        finally:
            self._slots.release()


def create_server(host: str, port: int) -> ThreadingHTTPServer:
    """Build the configured server (not yet serving); tests drive it directly."""
    token = os.environ.get(TOKEN_VAR, "")
    plugin_dirs = [
        Path(part) for part in os.environ.get(PLUGIN_VAR, "").split(os.pathsep) if part
    ]
    plugins, problems = load_plugins(plugin_dirs or None)
    for problem in problems:
        print(f"warning: plugin not loaded: {problem}")
    block_private = _is_truthy(os.environ.get(BLOCK_PRIVATE_VAR, ""))
    state = _State(token=token, plugins=tuple(plugins), block_private=block_private)
    return _BoundedServer((host, port), _make_handler(state))


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ssh_crypto_checker.web",
        description="Web front end for sshCryptoChecker (same scan, same reports).",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default: %(default)s; 0.0.0.0 in a container)")
    parser.add_argument("--port", type=int, default=8417,
                        help="listen port (default: %(default)s)")
    args = parser.parse_args(argv)

    # Open by default: with no token anyone who can reach the port uses it, on
    # any interface -- that is the frictionless local deployment. Setting a token
    # is the switch that closes it; the internet-exposure guidance lives in the
    # docs, not in a startup nag.
    guard = "token required" if os.environ.get(TOKEN_VAR) else "OPEN — no token"
    server = create_server(args.host, args.port)
    print(f"{PRODUCT_NAME} web {__version__} on http://{args.host}:{args.port}/  [{guard}]")
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive stop
        pass
    finally:
        server.server_close()
    return 0
