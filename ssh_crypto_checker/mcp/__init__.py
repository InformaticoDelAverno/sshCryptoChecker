"""MCP front end: the same scan and the same reports, driven by an LLM.

See ``server.py`` for the design and the transport. Run with
``python -m ssh_crypto_checker.mcp`` or the ``ssh-crypto-checker-mcp`` command.
"""

from .server import MCPServer, main

__all__ = ["MCPServer", "main"]
