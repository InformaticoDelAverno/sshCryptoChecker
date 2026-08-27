"""Reaching a segmented network through a bastion.

Most of this tool opens its own TCP sockets and speaks SSH over them, which is
what lets it see what a server offers without authenticating. That also means
``ProxyJump`` cannot help it: that option belongs to the ssh client, and there
is no ssh client in the path.

So the jump is made the other way round. A local port forward is opened
through the bastion with a real ssh client, and the scan connects to the local
end of it. Everything downstream is unchanged -- it is still a TCP socket to a
server that speaks SSH -- and the report still names the real target, because
127.0.0.1:41337 is not a useful thing to tell somebody.

The forward is per target and short-lived. It carries every connection that
target's checks make, since each new connection to the local port becomes a
new channel.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from collections.abc import Sequence
from typing import List, Optional, Tuple

from .ssh_protocol import printable

__all__ = ["Tunnel", "TunnelError", "open_tunnel"]

#: How many times to retry when the chosen local port is taken between our
#: releasing it and ssh binding it.
_PORT_ATTEMPTS = 3


class TunnelError(Exception):
    """The forward could not be established."""


def split_destination(destination: str) -> Tuple[str, Optional[int]]:
    """Split ``[user@]host[:port]`` into an ssh destination and a port.

    A bare IPv6 address is full of colons of its own, so only the bracketed
    form can carry a port. Getting this wrong would send the forward to a host
    named after half an address.
    """
    user, separator, remainder = destination.rpartition("@")
    prefix = f"{user}@" if separator else ""

    if remainder.startswith("["):
        closing = remainder.find("]")
        if closing != -1:
            host = remainder[1:closing]
            tail = remainder[closing + 1 :]
            if tail.startswith(":") and tail[1:].isdigit():
                return prefix + host, int(tail[1:])
            return prefix + host, None
    if remainder.count(":") == 1:
        host, _, port = remainder.partition(":")
        if port.isdigit():
            return prefix + host, int(port)
    return destination, None


def _free_port() -> int:
    """Ask the kernel for an unused port, then let go of it.

    There is a window between letting go and ssh binding it. It is closed by
    ExitOnForwardFailure, which makes ssh exit rather than carry on without the
    forward, and by retrying with a different port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class Tunnel:
    """A local port forward through a bastion, as a context manager."""

    def __init__(
        self,
        jump_host: str,
        host: str,
        port: int,
        ssh_binary: str = "ssh",
        timeout: float = 15.0,
        extra_options: Sequence[str] = (),
    ) -> None:
        self.jump_host = jump_host
        self.host = host
        self.port = port
        self.ssh_binary = ssh_binary
        self.timeout = timeout
        self.extra_options = list(extra_options)
        self.local_port: Optional[int] = None
        self._process: Optional[subprocess.Popen] = None

    # -- lifecycle ------------------------------------------------------- #

    # No __enter__/__exit__. open_tunnel() returns an open tunnel and every
    # caller closes it in a finally, so a context manager would be a second way
    # to do the same thing -- and one that cannot compose with open_tunnel,
    # since entering it would open a tunnel that is already open.

    def open(self) -> None:
        binary = shutil.which(self.ssh_binary)
        if binary is None:
            raise TunnelError(f"no '{self.ssh_binary}' binary on PATH to reach the bastion")

        last_error = ""
        for _attempt in range(_PORT_ATTEMPTS):
            local_port = _free_port()
            command = self._command(binary, local_port)
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True,
                )
            except OSError as exc:
                raise TunnelError(f"cannot start {self.ssh_binary}: {exc}") from exc

            self._process = process
            self.local_port = local_port
            if self._wait_until_ready():
                return
            last_error = self._drain_error() or "the forward never accepted a connection"
            self.close()

        raise TunnelError(
            f"cannot forward {self.host}:{self.port} through {self.jump_host}: {last_error}"
        )

    def close(self) -> None:
        process = self._process
        self._process = None
        self.local_port = None
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # A wedged ssh that ignores SIGTERM. Rare, and the reason the
                # scan does not hang behind it.
                process.kill()
                process.wait(timeout=5)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    # -- internals ------------------------------------------------------- #

    def _command(self, binary: str, local_port: int) -> List[str]:
        destination, jump_port = split_destination(self.jump_host)
        return [
            binary,
            "-N",
            *(["-p", str(jump_port)] if jump_port else []),
            # Exit rather than run on without the forward, so a port taken in
            # the meantime is a failure we can retry instead of a scan that
            # silently connects to whatever else is listening.
            "-o", "ExitOnForwardFailure=yes",
            # Never prompt: a scan of fifty hosts must not stop on a password
            # prompt nobody is there to answer.
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={int(max(1, self.timeout))}",
            *self.extra_options,
            "-L", f"127.0.0.1:{local_port}:{self.host}:{self.port}",
            destination,
        ]

    def _wait_until_ready(self) -> bool:
        """Wait for the local end to accept, or for ssh to give up."""
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            process = self._process
            if process is None or process.poll() is not None:
                return False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.5)
                if probe.connect_ex(("127.0.0.1", self.local_port or 0)) == 0:
                    return True
            time.sleep(0.1)
        return False

    def _drain_error(self) -> str:
        process = self._process
        if process is None or process.stderr is None:
            return ""
        try:
            process.terminate()
            _out, error = process.communicate(timeout=5)
        except (subprocess.TimeoutExpired, ValueError, OSError):
            return ""
        # What ssh printed, which includes what the bastion said: cleaned
        # before it becomes the reason in a report.
        lines = [
            printable(line.strip())
            for line in (error or "").splitlines()
            if line.strip()
        ]
        return lines[-1] if lines else ""


def open_tunnel(
    jump_host: str,
    host: str,
    port: int,
    ssh_binary: str = "ssh",
    timeout: float = 15.0,
    extra_options: Sequence[str] = (),
) -> Tunnel:
    """Open a forward and return it; the caller must close it."""
    tunnel = Tunnel(jump_host, host, port, ssh_binary, timeout, extra_options)
    tunnel.open()
    return tunnel
