"""Language selection and a tiny translation engine (English, Spanish of Spain).

The tool is bilingual. English is the default; Spanish is selected with
``--lang es`` or by a Spanish system locale (``LANG``/``LC_ALL`` starting with
``es``), unless ``--lang`` overrides it. The message catalogs live in
``messages.py`` as ``{key: {"en": ..., "es": ...}}``; a test checks that every
key has both languages, so 'complete in both' is enforced rather than hoped for.
"""

# This module is intentionally kept generic and portable.

from __future__ import annotations

import os
from typing import Dict, Mapping, Optional

#: The languages the tool ships. English first: it is the default and the
#: fallback when a Spanish string is somehow missing.
LANGUAGES = ("en", "es")
DEFAULT_LANGUAGE = "en"

#: Environment variables that name the system locale, most specific first.
_LOCALE_VARS = ("LC_ALL", "LC_MESSAGES", "LANG")


def resolve_language(
    explicit: Optional[str] = None, env: Optional[Mapping[str, str]] = None
) -> str:
    """Pick the language: an explicit choice wins, then a Spanish locale, else English.

    ``explicit`` is the value of ``--lang`` (or None). ``env`` defaults to the
    process environment. A locale like ``es_ES.UTF-8`` selects Spanish; anything
    else, including an unset or ``C`` locale, stays English.
    """
    if explicit is not None:
        choice = explicit.lower()
        if choice in LANGUAGES:
            return choice
        # A short form such as 'es_ES' or 'en-GB' is accepted by its prefix.
        if choice[:2] in LANGUAGES:
            return choice[:2]
        return DEFAULT_LANGUAGE
    environ = os.environ if env is None else env
    for var in _LOCALE_VARS:
        value = environ.get(var, "")
        if value[:2].lower() == "es":
            return "es"
    return DEFAULT_LANGUAGE


class Translator:
    """Turns a message key into text in the chosen language.

    Callable: ``t("key")`` or ``t("key", name="x")`` for a string with
    ``{name}`` placeholders. A missing key returns the key itself (so a gap is
    visible, never a crash); a key present in English but not Spanish falls back
    to English.
    """

    def __init__(self, language: str, catalog: Dict[str, Dict[str, str]]):
        self.language = language if language in LANGUAGES else DEFAULT_LANGUAGE
        self._catalog = catalog

    def __call__(self, key: str, **kwargs: object) -> str:
        entry = self._catalog.get(key)
        if entry is None:
            return key
        text = entry.get(self.language) or entry.get(DEFAULT_LANGUAGE) or key
        return text.format(**kwargs) if kwargs else text
