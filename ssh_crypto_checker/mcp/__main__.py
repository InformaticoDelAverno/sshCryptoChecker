"""``python -m ssh_crypto_checker.mcp`` starts the MCP server over stdio."""

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main())
