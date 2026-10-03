"""Deep-crawl frontier scoring (P34).

`KeywordRelevanceScorer` assigns a relevance score in [0.0, 1.0] to a candidate
URL based on how many query keywords appear in the URL itself (path + query).
The deep-crawl frontier is a max-priority queue ordered by this score, so the
most relevant links are fetched first within the crawl's wall-clock / page
budget — a best-first crawl rather than a blind breadth-first one.

The scorer is intentionally cheap (URL text only, no page fetch) because it has
to rank every frontier candidate before any of them is fetched. When no query
is supplied, `score()` returns a constant so the frontier degrades to FIFO
(plain breadth-first), preserving the no-query behaviour.

Provenance: the KeywordRelevanceScorer / best-first frontier shape is adapted
from crawl4ai's deep_crawling/scorers.py + bff_strategy.py (Apache-2.0,
unclecode/crawl4ai). Re-implemented in pure stdlib here; nothing is vendored.
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

# Split a URL path/query into lowercase word tokens for keyword matching.
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _url_tokens(url: str) -> set[str]:
    """Return the set of lowercase word tokens in `url`'s path + query."""
    parts = urlsplit(url)
    text = unquote(f"{parts.path} {parts.query}").lower()
    return set(_TOKEN_RE.findall(text))


class KeywordRelevanceScorer:
    """Score a URL by keyword overlap with a query.

    `weight` scales the final score (default 1.0). With no keywords the scorer
    returns `weight` for every URL so the frontier stays FIFO.
    """

    def __init__(self, keywords: list[str] | None = None, *, weight: float = 1.0):
        self.weight = weight
        # Normalize keywords to lowercase tokens once.
        kws: set[str] = set()
        for kw in (keywords or []):
            kws.update(_TOKEN_RE.findall(kw.lower()))
        self.keywords = kws

    def score(self, url: str) -> float:
        """Return a relevance score in [0.0, weight] for `url`.

        Score = (fraction of distinct query keywords present in the URL) *
        weight. No keywords → returns `weight` (constant → FIFO frontier).
        """
        if not self.keywords:
            return self.weight
        if not url:
            return 0.0
        tokens = _url_tokens(url)
        hits = sum(1 for kw in self.keywords if kw in tokens)
        return (hits / len(self.keywords)) * self.weight
