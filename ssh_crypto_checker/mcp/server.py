"""Model Context Protocol (MCP) front end: the same scan, driven by an LLM.

A third way to use the tool, beside the command line and the web page, and the
same guarantee behind all three: one scan that does the work and one renderer
that writes it. This speaks **JSON-RPC 2.0 over stdio** -- the MCP stdio
transport, one JSON message per line -- with nothing but the standard library: no
MCP SDK, no framework. Run it with ``python -m ssh_crypto_checker.mcp`` or the
installed ``ssh-crypto-checker-mcp`` command, and point an MCP client at it.

Why it cannot lose a CLI option: every tool call ends in :func:`_run_cli`, which
runs the very same ``ssh_crypto_checker.cli.main`` the terminal runs, capturing
its stdout and stderr. The ``scan`` tool takes the CLI's own ``argv``, so it is
exactly as capable as the command line -- by construction, not by a schema kept
in sync by hand. The convenience tools (``help``, ``list_profiles``,
``list_plugins``, ``list_vulnerabilities``, ``show_policy``) are the same call
with a fixed flag, offered because an LLM should not have to guess them.

Exit codes are information, not failures: a scan of a weak server exits non-zero
on purpose. So a completed run is never reported as a tool error -- the exit code
is appended to the text instead. ``isError`` is reserved for a call that could
not be made (bad arguments) or an unexpected exception, which is caught here so
one tool can never take the server down.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from typing import IO, Any, Callable, Dict, List, Optional, Tuple

from .. import PRODUCT_NAME, __version__
from ..cli import build_parser
from ..cli import main as cli_main
from ..i18n import LANGUAGES

__all__ = ["MCPServer", "main"]

#: The MCP revision this server implements. When a client asks for another, its
#: request is echoed back (the negotiated version), which is what MCP expects.
PROTOCOL_VERSION = "2024-11-05"

#: The name a client sees for this server. The launcher name, so the two match.
SERVER_NAME = "ssh-crypto-checker-mcp"

#: A run that produced no text at all still says so, rather than an empty bubble.
_NO_OUTPUT = "(no output)"


class _RpcError(Exception):
    """A JSON-RPC level error (bad method, bad params): becomes an error reply."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _ToolInputError(Exception):
    """A tool's arguments were malformed: becomes an ``isError`` tool result."""


CliRunner = Callable[[List[str]], Tuple[str, int]]
ArgvBuilder = Callable[[Dict[str, Any]], List[str]]


def _run_cli(argv: List[str], run: Callable[..., int] = cli_main) -> Tuple[str, int]:
    """Run the CLI with ``argv``, returning its captured output and exit code.

    stdout and stderr are folded into one stream, the way a person reads the
    terminal. ``ssh_crypto_checker.cli.main`` writes to the streams it is handed
    (default ``sys.stdout``/``sys.stderr``, which the redirects capture), and
    exits by raising ``SystemExit`` for ``--help``/``--version``/a usage error;
    that is a normal ending here, so its code is returned like any other. ``run``
    is injected only so the tests can exercise those endings.
    """
    buffer = io.StringIO()
    with redirect_stdout(buffer), redirect_stderr(buffer):
        try:
            code = run(argv)
        except SystemExit as exit_:
            code = _exit_code(exit_.code)
    return buffer.getvalue(), code


def _exit_code(code: object) -> int:
    """A ``SystemExit`` code as an int: ``None`` means success, a string means 1."""
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    return 1


def _lang_prefix(arguments: Dict[str, Any]) -> List[str]:
    """The ``--lang`` flag for a tool that accepts one, or nothing."""
    lang = arguments.get("lang")
    if lang is None:
        return []
    if lang not in LANGUAGES:
        raise _ToolInputError(f"unknown language {lang!r}; choose from {', '.join(LANGUAGES)}")
    return ["--lang", str(lang)]


def _scan_argv(arguments: Dict[str, Any]) -> List[str]:
    """The ``scan`` tool: its ``args`` array is the CLI's own ``argv``."""
    args = arguments.get("args", [])
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise _ToolInputError("'args' must be an array of strings (the command-line arguments)")
    return list(args)


def _flag_argv(*flags: str) -> ArgvBuilder:
    """A tool that is just a fixed flag, optionally in a chosen language."""

    def build(arguments: Dict[str, Any]) -> List[str]:
        return [*_lang_prefix(arguments), *flags]

    return build


@dataclass(frozen=True)
class _Tool:
    """One exposed tool: how it looks to a client, and how it becomes ``argv``."""

    name: str
    description: str
    input_schema: Dict[str, Any]
    build_argv: ArgvBuilder


def _options_summary() -> str:
    """Every CLI option, one per line, taken from the parser itself so it cannot
    drift from the command line the way a hand-written list would."""
    lines: List[str] = []
    for action in build_parser()._actions:
        if action.dest == "help" or not action.option_strings:
            continue
        lines.append(f"  {', '.join(action.option_strings)}  {action.help or ''}".rstrip())
    return "\n".join(lines)


_LANG_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "lang": {
            "type": "string",
            "enum": list(LANGUAGES),
            "description": "language for human-readable text (default: English)",
        }
    },
    "additionalProperties": False,
}


def _build_tools() -> List[_Tool]:
    """The tools this server offers. The web and SSH servers share this shape;
    only the product and its convenience listings differ."""
    scan_description = (
        f"Audit the cryptography an SSH server negotiates, exactly as the "
        f"{PRODUCT_NAME} command line does. 'args' is the argument vector the CLI "
        f"itself takes -- e.g. [\"server.example.com\", \"--format\", \"json\"]. "
        f"Every option works; nothing is lost. Options:\n" + _options_summary()
    )
    return [
        _Tool(
            name="scan",
            description=scan_description,
            input_schema={
                "type": "object",
                "properties": {
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "the command-line arguments (targets and options)",
                    }
                },
                "required": ["args"],
                "additionalProperties": False,
            },
            build_argv=_scan_argv,
        ),
        _Tool(
            name="help",
            description="The full command-line help: every option, in the chosen language.",
            input_schema=_LANG_SCHEMA,
            build_argv=_flag_argv("--help"),
        ),
        _Tool(
            name="list_profiles",
            description="List the conformance profiles (NIST, FIPS, ENS, PCI DSS, ...) available.",
            input_schema=_LANG_SCHEMA,
            build_argv=_flag_argv("--list-profiles"),
        ),
        _Tool(
            name="list_plugins",
            description="List the detection plugins that would load.",
            input_schema=_LANG_SCHEMA,
            build_argv=_flag_argv("--list-plugins"),
        ),
        _Tool(
            name="list_vulnerabilities",
            description="List the known vulnerabilities the policy checks for.",
            input_schema=_LANG_SCHEMA,
            build_argv=_flag_argv("--list-vulnerabilities"),
        ),
        _Tool(
            name="show_policy",
            description="Show the active scoring policy: classes, weights, grade ladder, source.",
            input_schema=_LANG_SCHEMA,
            build_argv=_flag_argv("--show-policy"),
        ),
    ]


def _error(id_: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _tool_error(message: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


class MCPServer:
    """A minimal MCP server over JSON-RPC 2.0. ``runner`` is injectable so the
    tests can stand in for a real CLI run."""

    def __init__(self, runner: Optional[CliRunner] = None) -> None:
        self._runner: CliRunner = runner or _run_cli
        self._tools: Dict[str, _Tool] = {tool.name: tool for tool in _build_tools()}

    # -- transport ------------------------------------------------------- #

    def serve(self, source: IO[str], sink: IO[str]) -> None:
        """Read one JSON-RPC message per line until end of input, replying to
        each request (a notification, which has no id, gets no reply)."""
        for line in source:
            stripped = line.strip()
            if not stripped:
                continue
            response = self._handle_line(stripped)
            if response is not None:
                sink.write(json.dumps(response) + "\n")
                sink.flush()

    def _handle_line(self, text: str) -> Optional[Dict[str, Any]]:
        try:
            message = json.loads(text)
        except json.JSONDecodeError:
            return _error(None, -32700, "Parse error")
        return self.handle(message)

    def handle(self, message: Any) -> Optional[Dict[str, Any]]:
        """Dispatch one parsed message; return the reply, or ``None`` to stay
        silent (a notification, or an error on one)."""
        if not isinstance(message, dict) or message.get("method") is None:
            return _error(None, -32600, "Invalid Request")
        is_notification = "id" not in message
        id_ = message.get("id")
        params = message.get("params")
        if not isinstance(params, dict):
            params = {}
        try:
            result = self._dispatch(str(message["method"]), params)
        except _RpcError as error:
            return None if is_notification else _error(id_, error.code, error.message)
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": id_, "result": result}

    # -- methods --------------------------------------------------------- #

    def _dispatch(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if method == "initialize":
            return self._initialize(params)
        if method == "tools/list":
            return {"tools": self._tool_specs()}
        if method == "tools/call":
            return self._call_tool(params)
        if method in ("ping", "notifications/initialized"):
            return {}
        raise _RpcError(-32601, f"Method not found: {method}")

    def _initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        requested = params.get("protocolVersion")
        version = requested if isinstance(requested, str) else PROTOCOL_VERSION
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
        }

    def _tool_specs(self) -> List[Dict[str, Any]]:
        return [
            {"name": tool.name, "description": tool.description, "inputSchema": tool.input_schema}
            for tool in self._tools.values()
        ]

    def _call_tool(self, params: Dict[str, Any]) -> Dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str) or name not in self._tools:
            raise _RpcError(-32602, f"Unknown tool: {name!r}")
        tool = self._tools[name]
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        try:
            argv = tool.build_argv(arguments)
        except _ToolInputError as error:
            return _tool_error(str(error))
        try:
            text, code = self._runner(argv)
        except Exception as error:  # never let one tool call kill the server
            return _tool_error(f"internal error running the tool: {error}")
        body = (text if text else _NO_OUTPUT).rstrip("\n") + f"\n\n[exit code: {code}]"
        return {"content": [{"type": "text", "text": body}], "isError": False}


def main(argv: Optional[List[str]] = None) -> int:
    """Serve MCP over stdio. ``--version`` prints and exits without serving."""
    parser = argparse.ArgumentParser(
        prog="python -m ssh_crypto_checker.mcp",
        description="MCP server for sshCryptoChecker (same scan, same reports, over stdio).",
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    args = parser.parse_args(argv)
    if args.version:
        print(f"{PRODUCT_NAME} MCP {__version__}")
        return 0
    MCPServer().serve(sys.stdin, sys.stdout)
    return 0
