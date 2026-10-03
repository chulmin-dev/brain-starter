"""Content filtering for page-fetch (P29) — pure-Python boilerplate pruning
and query-driven block selection. LLM-input token reduction without any new
dependency: stdlib (`math`, `re`, `collections`) + the already-required `bs4`.

Two independent filters, both ported from crawl4ai's algorithm descriptions
(not its package — `crawl4ai` is NOT imported here):

  * ``prune_html(html, threshold=...)`` — PruningContentFilter. Walks the DOM
    and decomposes nodes whose composite score (text density + link density +
    tag weight + class/id weight + text length) falls below a threshold,
    leaving the dense content blocks.

  * ``bm25_filter(html, query, threshold=...)`` — inline BM25. Splits the DOM
    into text blocks, scores each block against the query with a self-contained
    Okapi BM25 (no `rank_bm25` dependency, no nltk stemmer), and returns the
    relevant blocks in original document order.

Both are soft on bs4 the same way ``extract.py`` is: the importer raises a
clear, actionable RuntimeError only when these functions are actually called.

Korean / CJK note: BM25 tokenization here is whitespace + word-character based.
It works well for space-delimited languages; for Korean (no inter-word spaces)
recall is reduced because tokens collapse to whole phrases. This is documented
rather than silently degraded — callers wanting CJK precision should prefer the
trafilatura markdown path. No stemming is applied (intentional: avoids an nltk
dependency and keeps behavior deterministic across machines).
"""
from __future__ import annotations

import math
import re
from collections import defaultdict


def _import_bs4():
    """Import BeautifulSoup lazily. Raises RuntimeError with a clear hint."""
    try:
        from bs4 import BeautifulSoup  # noqa: F401
        return BeautifulSoup
    except ImportError as e:
        raise RuntimeError(
            "beautifulsoup4 is required for --prune / --query content "
            "filtering. Install it with: pip install beautifulsoup4"
        ) from e


# Tag weights mirror crawl4ai's PruningContentFilter table: structural content
# tags score high, generic containers low, inline noise lowest.
_TAG_WEIGHTS = {
    "article": 1.5,
    "main": 1.4,
    "section": 1.2,
    "p": 1.0,
    "h1": 1.2, "h2": 1.1, "h3": 1.0, "h4": 0.9, "h5": 0.8, "h6": 0.8,
    "blockquote": 1.0,
    "pre": 1.0, "code": 1.0,
    "li": 0.8,
    "td": 0.7, "th": 0.7,
    "div": 0.5,
    "span": 0.3,
}
_DEFAULT_TAG_WEIGHT = 0.5

# class / id substrings that mark navigational / promotional chrome.
_NEGATIVE_CLASS_ID = re.compile(
    r"nav|footer|sidebar|side-bar|menu|ads?\b|advert|comment|promo|social|"
    r"share|related|breadcrumb|pagination|cookie|banner|widget|popup|modal|"
    r"newsletter|subscribe",
    re.IGNORECASE,
)

# Tags that never carry body content — stripped before scoring.
_STRIP_TAGS = ("script", "style", "noscript", "template", "svg", "form")

# Default pruning threshold. crawl4ai uses 0.48 for fixed mode; we match it.
_DEFAULT_PRUNE_THRESHOLD = 0.48

# Tags whose own score is evaluated for pruning (block-level candidates). Inline
# and structural-root tags are skipped so we don't decompose <body>/<html>.
_PRUNE_CANDIDATE_TAGS = frozenset({
    "article", "main", "section", "div", "aside", "nav", "header", "footer",
    "ul", "ol", "li", "table", "form", "figure",
})


def _node_text(node) -> str:
    """Visible text of a node, whitespace-collapsed."""
    return re.sub(r"\s+", " ", node.get_text(separator=" ", strip=True)).strip()


def _link_text_len(node) -> int:
    """Total length of anchor text inside a node (navigation proxy)."""
    total = 0
    for a in node.find_all("a"):
        total += len(a.get_text(strip=True))
    return total


def _class_id_blob(node) -> str:
    cls = node.get("class") or []
    if isinstance(cls, str):
        cls = [cls]
    return " ".join(cls) + " " + (node.get("id") or "")


def _composite_score(node) -> float:
    """Weighted composite score for one DOM node.

    Higher = more likely real content. Components (weights mirror crawl4ai):
      text_density   (0.4) — text length vs. raw markup length
      link_density   (0.2) — 1 - (anchor text / text); menus score low
      tag_weight     (0.2) — structural tags up-weighted
      class_id_weight(0.1) — nav/footer/ads substrings penalized
      text_length    (0.1) — log(text_len) so long blocks edge up
    """
    text = _node_text(node)
    text_len = len(text)
    if text_len == 0:
        return 0.0

    markup_len = len(str(node)) or 1
    text_density = text_len / markup_len  # 0..1, clamped naturally below 1

    link_len = _link_text_len(node)
    link_density = 1.0 - (link_len / text_len if text_len else 0.0)
    if link_density < 0.0:
        link_density = 0.0

    tag_weight = _TAG_WEIGHTS.get(node.name, _DEFAULT_TAG_WEIGHT)
    # Normalize tag weight into ~0..1 range (max table entry is 1.5).
    tag_component = min(tag_weight / 1.5, 1.0)

    class_id_weight = 1.0
    if _NEGATIVE_CLASS_ID.search(_class_id_blob(node)):
        class_id_weight = 0.5

    text_length_component = min(math.log(text_len + 1) / math.log(1000), 1.0)

    return (
        0.4 * min(text_density, 1.0)
        + 0.2 * link_density
        + 0.2 * tag_component
        + 0.1 * class_id_weight
        + 0.1 * text_length_component
    )


def prune_html(html: str, threshold: float = _DEFAULT_PRUNE_THRESHOLD) -> str:
    """Return HTML with low-score (boilerplate) blocks removed.

    Parses ``html``, strips non-content tags, then decomposes every block-level
    candidate node whose composite score is below ``threshold``. Returns the
    pruned HTML as a string (still valid HTML — feed it to trafilatura/bs4 to
    get fit_markdown / fit_text).

    Conservative: only decomposes recognized container tags so the document
    root and body are never removed. If pruning would empty the body, the
    original (stripped) HTML is returned instead of an empty document — a
    silent-empty result would be worse than over-inclusion.
    """
    BeautifulSoup = _import_bs4()
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup(list(_STRIP_TAGS)):
        tag.decompose()

    # Evaluate deepest candidates first so a parent's score isn't dominated by
    # children we're about to remove. Collect then prune to avoid mutating the
    # tree mid-iteration.
    candidates = [
        n for n in soup.find_all(_PRUNE_CANDIDATE_TAGS)
    ]
    # Sort by depth descending (leaf-most first).
    candidates.sort(key=lambda n: len(list(n.parents)), reverse=True)

    for node in candidates:
        if node.decomposed:  # parent already removed it
            continue
        if _composite_score(node) < threshold:
            node.decompose()

    body = soup.find("body") or soup
    if not _node_text(body):
        # Pruning emptied the document — fall back to the stripped HTML rather
        # than returning nothing (explicit, not a silent default).
        soup2 = BeautifulSoup(html, "html.parser")
        for tag in soup2(list(_STRIP_TAGS)):
            tag.decompose()
        return str(soup2)

    return str(soup)


# ---------------------------------------------------------------------------
# BM25 query filter
# ---------------------------------------------------------------------------

_BM25_K1 = 1.2
_BM25_B = 0.75
_DEFAULT_BM25_THRESHOLD = 1.0

# Block-level tags whose text becomes a scorable unit.
_BM25_BLOCK_TAGS = (
    "p", "li", "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6",
    "td", "article", "section",
)

# Priority tags get a score multiplier so headings/titles surface.
_BM25_PRIORITY = {
    "title": 4.0, "h1": 5.0, "h2": 4.0, "h3": 3.0, "h4": 2.0,
    "strong": 2.0, "b": 1.5, "em": 1.5, "code": 2.0,
    "blockquote": 1.2, "pre": 1.0,
}

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


def _tokenize(text: str) -> list[str]:
    """Lowercase word-character tokenization. No stemming (deterministic)."""
    return _TOKEN_RE.findall(text.lower())


def _extract_blocks(soup) -> list[tuple[str, str]]:
    """Return (tag_name, text) pairs for each block-level node, in order.

    Deepest-first dedup: if a block's text is fully contained in an
    already-collected block we skip it, so we don't double-count nested
    paragraphs against their container.
    """
    blocks: list[tuple[str, str]] = []
    for node in soup.find_all(_BM25_BLOCK_TAGS):
        # Skip nodes that themselves contain other block tags — let the inner
        # blocks be the scorable units (avoids counting a <section> and its
        # <p> children both).
        if node.find(_BM25_BLOCK_TAGS):
            continue
        text = _node_text(node)
        if text:
            blocks.append((node.name, text))
    return blocks


def _bm25_score(query_tokens, doc_tokens, idf, avgdl) -> float:
    """Okapi BM25 score of one document (block) against the query."""
    if not doc_tokens:
        return 0.0
    doc_len = len(doc_tokens)
    freqs: dict[str, int] = defaultdict(int)
    for t in doc_tokens:
        freqs[t] += 1

    score = 0.0
    for term in query_tokens:
        if term not in freqs:
            continue
        tf = freqs[term]
        num = tf * (_BM25_K1 + 1)
        den = tf + _BM25_K1 * (1 - _BM25_B + _BM25_B * doc_len / avgdl)
        score += idf.get(term, 0.0) * num / den
    return score


def bm25_filter(
    html: str,
    query: str,
    threshold: float = _DEFAULT_BM25_THRESHOLD,
) -> str:
    """Return only the text blocks relevant to ``query``, in document order.

    Splits the DOM into block-level text units, scores each against ``query``
    with an inline Okapi BM25 (priority tags up-weighted), and joins the blocks
    scoring at or above ``threshold`` with blank lines.

    If no block clears the threshold, the single highest-scoring block is
    returned so the caller never gets an empty result from a non-empty page
    (explicit fallback, not a silent default). If the query is empty, the full
    visible text is returned unchanged.
    """
    BeautifulSoup = _import_bs4()

    query_tokens = _tokenize(query)
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(list(_STRIP_TAGS)):
        tag.decompose()

    if not query_tokens:
        return _node_text(soup)

    blocks = _extract_blocks(soup)
    if not blocks:
        return ""

    tokenized = [_tokenize(text) for _, text in blocks]
    # CR-L4: make the zero-division guard local — `if not blocks: return ""`
    # above guarantees len(tokenized) >= 1 today, but compute defensively so a
    # later refactor of that guard can't reintroduce a ZeroDivisionError. The
    # trailing `or 1.0` also keeps avgdl strictly positive when every block
    # tokenizes to empty (preserves the prior `... or 1.0` behaviour).
    avgdl = ((sum(len(t) for t in tokenized) / len(tokenized)) if tokenized else 1.0) or 1.0

    # IDF over the block corpus.
    n_docs = len(tokenized)
    df: dict[str, int] = defaultdict(int)
    for toks in tokenized:
        for term in set(toks):
            df[term] += 1
    idf = {
        term: math.log(1 + (n_docs - d + 0.5) / (d + 0.5))
        for term, d in df.items()
    }

    scored: list[tuple[float, int, str]] = []
    for i, ((tag, text), toks) in enumerate(zip(blocks, tokenized)):
        base = _bm25_score(query_tokens, toks, idf, avgdl)
        weight = _BM25_PRIORITY.get(tag, 1.0)
        scored.append((base * weight, i, text))

    kept = [(i, text) for score, i, text in scored if score >= threshold]
    if not kept:
        # No block cleared the bar — return the single best block so a relevant
        # page is never reduced to nothing.
        best = max(scored, key=lambda s: s[0])
        if best[0] <= 0.0:
            return ""
        kept = [(best[1], best[2])]

    kept.sort(key=lambda p: p[0])  # original document order
    return "\n\n".join(text for _, text in kept)
