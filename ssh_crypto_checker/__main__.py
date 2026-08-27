"""Entry point for ``python -m ssh_crypto_checker`` and ``python ssh_crypto_checker``.

Both invocations must work. Run as a module (``python -m ssh_crypto_checker``)
the package context is set and the relative import resolves. Run as a directory
(``python3 ssh_crypto_checker``), Python executes this file with no package and
puts the package directory itself on ``sys.path``, so ``from .cli`` would fail
with 'attempted relative import with no known parent package'; there we add the
parent directory and import by absolute name instead.
"""

from __future__ import annotations

import sys

if __package__:
    from .cli import main
else:  # run as a path, e.g. 'python3 ssh_crypto_checker'
    import os

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from ssh_crypto_checker.cli import main

if __name__ == "__main__":
    sys.exit(main())
