"""The client's own effective configuration, read with ``ssh -G``.

Everything else in this tool judges the server. But a permissive client undoes
much of it: ``StrictHostKeyChecking no`` means the strongest host key on the
best-configured server is never actually checked, and a forwarded agent turns
one compromised server into access to every host the operator can reach.

``ssh -G`` is to the client what ``sshd -T`` is to the server: it resolves the
system file, the user file, every Host and Match block, and the compiled-in
defaults, and prints what this connection would really use. Asking it about a
specific destination matters, because a Host block can relax settings for one
target and nothing global would show it.

Nothing is connected: ``-G`` resolves and prints, it does not open a socket.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence
from typing import Dict, List, Optional

from .models import ClientConfig
from .ssh_protocol import printable

__all__ = ["fetch_client_config"]


def fetch_client_config(
    host: str,
    port: int,
    ssh_binary: str = "ssh",
    timeout: float = 10.0,
    extra_options: Sequence[str] = (),
    jump_host: Optional[str] = None,
) -> ClientConfig:
    """Resolve what this machine's ssh client would use to reach ``host``.

    Never raises: a missing or unusable ssh binary is a result with an error,
    because one target that cannot be resolved must not abort a fleet scan.
    """
    config = ClientConfig(attempted=True, target=f"{host}:{port}")

    binary = shutil.which(ssh_binary)
    if binary is None:
        config.error = f"no '{ssh_binary}' binary on PATH, so the client config cannot be read"
        return config

    # 'ssh -G' resolves and prints; it opens nothing. The bastion is passed
    # only because ProxyJump changes what the resolved configuration says.
    jump = ["-J", jump_host] if jump_host else []
    command = [binary, "-G", "-p", str(port), *jump, *extra_options, host]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:  # never fatal
        config.error = f"{ssh_binary} -G failed: {exc}"
        return config

    if completed.returncode != 0:
        # Peer text, for the same reason as the server audit's.
        detail = printable((completed.stderr or "").strip()).splitlines()
        config.error = f"{ssh_binary} -G exited {completed.returncode}" + (
            f": {detail[-1]}" if detail else ""
        )
        return config

    # Cleaned for the same reason as the server's transcript: this is another
    # program's output on its way to a terminal.
    config.directives = _parse(printable(completed.stdout, keep_newlines=True).splitlines())
    config.available = bool(config.directives)
    if not config.available:
        config.error = f"{ssh_binary} -G printed nothing"
    return config


def _parse(lines: Sequence[str]) -> Dict[str, List[str]]:
    """Parse ``key value`` lines.

    A few directives may appear more than once -- identityfile above all -- so
    every value is kept, in the order ssh printed them.
    """
    directives: Dict[str, List[str]] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, _, value = stripped.partition(" ")
        directives.setdefault(name.lower(), []).append(value.strip())
    return directives
