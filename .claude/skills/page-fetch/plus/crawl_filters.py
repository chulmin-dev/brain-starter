"""Deep-crawl URL filtering (P34).

A `FilterChain` decides whether a discovered link is allowed into the crawl
frontier. Three independent, composable filters:

  * same-registrable-domain (DEFAULT ON) — keeps the crawl on the start URL's
    registrable domain. This is the safe default because a deep link-following
    crawl amplifies fetch volume, and unbounded cross-domain crawling from a
    single egress IP risks rate-limit bans. Opt out
    with `same_domain=False`.
  * --allow PATTERN  — substring/regex allowlist; a URL must match at least one
    allow pattern (when any are given) to pass.
  * --deny PATTERN   — substring/regex denylist; a URL matching any deny pattern
    is rejected outright (deny wins over allow).

Patterns are treated as regular expressions; an invalid regex degrades to a
plain substring test (documented, never silently dropped) so a caller passing
a literal path fragment still works.

Provenance: the FilterChain / URLPatternFilter / DomainFilter shape is adapted
from crawl4ai's deep_crawling/filters.py (Apache-2.0, unclecode/crawl4ai).
Re-implemented in pure stdlib here; nothing is vendored.
"""
from __future__ import annotations

import re
import sys
from urllib.parse import urlsplit

try:
    # Reuse the engine's PSL-aware registrable-domain helper so the scope gate
    # matches the engine's own apex logic (no second PSL implementation).
    from engine.url_transforms import _registrable_domain as _eng_registrable
except Exception:  # noqa: BLE001 — fall back to a naive last-two-labels split
    _eng_registrable = None


def _registrable_domain(host: str) -> str:
    """Return the registrable domain for `host`, PSL-aware when possible."""
    host = (host or "").lower().strip(".")
    if not host:
        return ""
    if _eng_registrable is not None:
        try:
            return _eng_registrable(host)
        except Exception:  # noqa: BLE001
            pass
    # Naive fallback: last two labels (good enough for common gTLDs; the engine
    # helper is preferred and present in this codebase).
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _compile(pattern: str):
    """Compile `pattern` as regex; fall back to escaped-substring on error.

    Returns a compiled pattern object. An invalid regex (e.g. a literal path
    with unbalanced brackets) is escaped and matched as a literal substring,
    with a one-time stderr note so the degradation is visible, never silent.
    """
    try:
        return re.compile(pattern)
    except re.error as e:
        print(
            f"[plus] crawl filter: pattern {pattern!r} is not valid regex "
            f"({e}); treating it as a literal substring.",
            file=sys.stderr,
        )
        return re.compile(re.escape(pattern))


class FilterChain:
    """Decide whether a URL is allowed into the crawl frontier."""

    def __init__(
        self,
        *,
        start_url: str,
        same_domain: bool = True,
        allow: list[str] | None = None,
        deny: list[str] | None = None,
    ) -> None:
        self.same_domain = same_domain
        self._start_registrable = _registrable_domain(urlsplit(start_url).hostname or "")
        self._allow = [_compile(p) for p in (allow or [])]
        self._deny = [_compile(p) for p in (deny or [])]

    def _same_registrable(self, url: str) -> bool:
        host = urlsplit(url).hostname or ""
        return _registrable_domain(host) == self._start_registrable

    def allowed(self, url: str) -> bool:
        """Return True if `url` passes every active filter.

        Order: same-domain gate → deny (wins) → allow (require-at-least-one).
        """
        if not url:
            return False
        if self.same_domain and not self._same_registrable(url):
            return False
        for pat in self._deny:
            if pat.search(url):
                return False
        if self._allow and not any(pat.search(url) for pat in self._allow):
            return False
        return True
