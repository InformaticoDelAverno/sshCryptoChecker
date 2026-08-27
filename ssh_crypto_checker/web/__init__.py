"""Web front end: the same scan and the same reports, served over HTTP.

See ``server.py`` for the design and the deployment contract. Run with
``python -m ssh_crypto_checker.web``.
"""

from .server import create_server, main

__all__ = ["create_server", "main"]
