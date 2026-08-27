"""``python -m ssh_crypto_checker.web`` starts the web front end."""

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main())
