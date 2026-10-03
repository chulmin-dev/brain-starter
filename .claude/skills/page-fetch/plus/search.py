"""Search layer for page-fetch — Stage 3.

`search` queries one keyword across seven public sources in parallel and merges
the hits into a single uniform schema. The sources are platform search APIs
and public search endpoints:

  * hn       — Hacker News (Algolia search API, JSON).
  * reddit   — Reddit search (public .json endpoint).
  * bluesky  — Bluesky AppView (searchPosts XRPC, JSON).
  * arxiv    — arXiv (Atom query API, XML).
  * naver    — Naver integrated web search (HTML scrape).
  * ddg      — DuckDuckGo HTML endpoint (HTML scrape).
  * ddgs     — DuckDuckGo via the `ddgs` library (backend=auto, 10-engine
               rotation). Soft-dep: skipped with a stderr warning when the
               `ddgs` package is not installed.

This module is a *separate layer* that depends one-way on `engine/`: every
network request travels through `engine.fetch`, so DoH, WAF bypass and verdict
validation all apply for free. The module only *parses* what the engine
returns; it never opens a socket itself.

**Exception — `ddgs` source**: the `ddgs` library (MIT, backend=auto) opens
its own sockets via primp/httpx. It therefore operates outside the DoH /
WAF-verdict pipeline. This is noted here so the "never opens a socket itself"
invariant is understood to apply to all sources *except* `ddgs`. Result URLs
still pass `_outbound_url_safe` before they are surfaced. (P38, 2026-06-12)

Each `search_<name>` is best-effort: any failure (network, parse, unexpected
shape) is caught, a warning goes to stderr, and an empty list is returned. A
single dead source must never abort the whole search.

Parsing untrusted XML is a security boundary. The arXiv Atom feed never needs
a DTD, so any input containing `<!DOCTYPE` is rejected outright (XXE /
billion-laughs defence), and the text handed to the parser is size-capped —
the same guard `crawl.py` applies to sitemaps and RSS feeds.

Public API endpoint hosts (hn.algolia.com, reddit.com, bsky.app,  # NOTE-BIAS-OK: Phase 0 public API list in module docstring
export.arxiv.org, search.naver.com, html.duckduckgo.com) appearing here is  # NOTE-BIAS-OK: Phase 0 public API list in module docstring
by design: they *are* the feature. These are Phase 0 official public API
references explicitly permitted by the No-Site-Name Rule (see SKILL.md §bias
and bias_check.py URL_ALLOWLIST). Lines referencing these hosts carry
NOTE-BIAS-OK markers.
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from engine import fetch as engine_fetch
from ._security import SSRFBlockedError, _ssrf_guard

# Hard cap on the byte size of any XML blob handed to a parser. The arXiv feed
# is small in practice; anything larger is truncated rather than parsed whole —
# a blunt but effective amplification-attack guard. Mirrors crawl.py.
_MAX_PARSE_BYTES = 10 * 1024 * 1024  # 10 MB

# P19 / Phase 2 cap (consensus N2): cap per-source engine attempts so a single
# WAF'd source can't outlive the ThreadPoolExecutor and leave a zombie thread.
# Engine's default `max_attempts=12 × per-attempt timeout` can stretch to
# minutes; 6-source parallel search accumulates stalls quickly.
#
# Arithmetic fix (P19 W30): the future.result() wait must be ≥ per-source
# worst-case wall-clock.  Per-source worst-case = _SEARCH_MAX_ATTEMPTS ×
# _SEARCH_MAX_TIMEOUT_S = 3 × 15 = 45 s.  The old `timeout + 10` (25+10=35 s)
# was shorter than 45 s — a zombie-thread window.  The wait is now the
# per-source worst-case directly so budget is always respected.
_SEARCH_MAX_ATTEMPTS = 3
_SEARCH_MAX_TIMEOUT_S = 15
# Per-source future wait = max time one source can take before we give up.
_SEARCH_FUTURE_WAIT_S = _SEARCH_MAX_ATTEMPTS * _SEARCH_MAX_TIMEOUT_S  # 45 s

# Tracking-parameter prefixes/names stripped by _normalize_url (P19 W46).
# Only strip known ad/tracking params; meaningful query params (e.g. reddit's
# `q=`, arxiv's `search_query=`) must survive dedup intact.
_TRACKING_PARAMS: frozenset[str] = frozenset({
    "fbclid", "gclid", "msclkid", "dclid", "igshid",
    "mc_cid", "mc_eid", "ref", "_hsenc", "_hsmi",
})
_TRACKING_PREFIXES: tuple[str, ...] = ("utm_",)

# The seven source names this module knows how to query. Order is the default
# `--sources` order and the order results are grouped for display.
# P38 (2026-06-12): added `ddgs` as the 7th source — ddgs library backend=auto
# rotation. Soft-dep: skipped with stderr warning when ddgs is not installed.
SOURCES = ("hn", "reddit", "bluesky", "arxiv", "naver", "ddg", "ddgs")


def _warn(msg: str) -> None:
    """Emit a non-fatal search warning to stderr."""
    print(f"[plus] search warning: {msg}", file=sys.stderr)


def _outbound_url_safe(url: str) -> bool:
    """True if an external search result URL is safe to surface to the caller.

    Search result links (DDG `uddg`, Naver outbound) are attacker-influenceable
    via SEO spam: a malicious top result could point at an internal IP, which
    the caller (or an LLM) might subsequently fetch — re-amplifying SSRF
    through the search pipeline (consensus F10).

    We don't fetch the result here, but we refuse to *surface* a URL that the
    SSRF guard would reject. The URL is silently dropped rather than raising —
    one poisoned hit must not kill the whole result list.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        _ssrf_guard(url)
    except SSRFBlockedError:
        return False
    except (ValueError, UnicodeError):
        # Malformed URL that crashed the guard's parser — drop it (fail closed).
        # L3 (security review 2026-06-11): narrowing the fail-open so only a
        # truly unexpected guard bug (not a crafted URL that raises ValueError)
        # falls through to the allow-default below.
        return False
    except Exception:
        # Unexpected guard failure: default to *allow* so we don't drop
        # legitimate URLs on a guard bug. A downstream fetch will re-run
        # the guard and fail closed if the URL is actually dangerous.
        return True
    return True


def _safe_fetch(url: str, timeout: int) -> str | None:
    """Fetch `url` via the engine, returning its body or None on any failure.

    Never raises — a single dead source must not abort the whole search.

    Phase 2: clamps engine attempts/timeout so a hung source can't outlive the
    `ThreadPoolExecutor`'s `timeout + 10s` future-wait and leak a zombie
    thread (consensus N2).
    """
    capped_timeout = min(timeout, _SEARCH_MAX_TIMEOUT_S)
    try:
        result = engine_fetch(
            url,
            timeout=capped_timeout,
            max_attempts=_SEARCH_MAX_ATTEMPTS,
        )
    except Exception as e:  # noqa: BLE001
        _warn(f"fetch failed for {url}: {type(e).__name__}: {e}")
        return None
    if not result.ok:
        # An unsuccessful verdict can still carry a usable body; hand back
        # whatever content exists.
        _warn(f"fetch unsuccessful for {url}: verdict={result.verdict}")
    return result.content or None


def _epoch_to_iso(value) -> str | None:
    """Convert a UNIX epoch (seconds, int/float/str) to an ISO-8601 string.

    Returns None when `value` is missing or not a usable number.
    """
    if value is None:
        return None
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


# P19 (2026-06-12): per-source date normalisation to ISO 8601.
# Each source uses a different date format; unifying them enables recency
# scoring and time-based sorting across sources (W29).
# Supported patterns:
#   - Already ISO 8601 (bluesky indexedAt, arxiv published): pass-through.
#   - RFC 2822 / HTTP-date (RSS pubDate): parsed via email.utils.
#   - Anything else: best-effort strptime with a short candidate list;
#     on parse failure the raw string is kept (never nulled — W29 caution).
_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}"          # date part
    r"(?:[T ]\d{2}:\d{2}"          # optional time
    r"(?::\d{2}(?:\.\d+)?)?"       # optional seconds/fraction
    r"(?:Z|[+-]\d{2}:?\d{2})?)?$"  # optional timezone
)


def _parse_date_to_iso(raw: str | None) -> str | None:
    """Normalise a date string from any source to ISO 8601, best-effort.

    Returns the normalised string, the original `raw` string when the format
    is unrecognised (never None — callers depend on a non-null value for
    recency scoring), or None when `raw` is None/empty.
    """
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if not raw:
        return None
    # Already ISO 8601 — pass through unchanged.
    if _ISO_RE.match(raw):
        return raw
    # RFC 2822 (e.g. "Wed, 01 Jan 2026 00:00:00 +0000" from RSS pubDate).
    try:
        import email.utils as _eu
        parsed_tuple = _eu.parsedate_to_datetime(raw)
        return parsed_tuple.isoformat()
    except Exception:  # noqa: BLE001
        pass
    # Fallback: short strptime candidate list for common non-ISO formats.
    _FMTS = (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d %b %Y",
        "%b %d, %Y",
    )
    for fmt in _FMTS:
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    # Unrecognised format — return the original string rather than nulling it
    # so callers still have something to display/sort on (W29 caution).
    return raw


# --- Hacker News (Algolia) ---------------------------------------------------
def search_hn(query: str, limit: int, timeout: int) -> list[dict]:
    """Search Hacker News stories via the Algolia search API.

    Returns up to `limit` hits in the uniform schema.
    """
    url = f"https://hn.algolia.com/api/v1/search?query={quote(query)}&tags=story"  # NOTE-BIAS-OK: Phase 0 public API
    body = _safe_fetch(url, timeout)
    if not body:
        return []
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError) as e:
        _warn(f"hn: JSON parse error: {e}")
        return []

    hits = data.get("hits")
    if not isinstance(hits, list):
        _warn("hn: response had no `hits` list")
        return []

    out: list[dict] = []
    for hit in hits[:limit]:
        if not isinstance(hit, dict):
            continue
        title = hit.get("title") or hit.get("story_title")
        url_field = hit.get("url")
        object_id = hit.get("objectID")
        if not url_field and object_id:
            url_field = f"https://news.ycombinator.com/item?id={object_id}"  # NOTE-BIAS-OK: Phase 0 public API
        if not url_field:
            continue
        # P3 (2026-06-11): guard attacker-submittable hit URLs against SSRF
        # re-amplification (W33). Only guard hit.get("url") — the constructed
        # news.ycombinator.com fallback above is always safe.  # NOTE-BIAS-OK: Phase 0 public API
        raw_hit_url = hit.get("url")
        if raw_hit_url and not _outbound_url_safe(raw_hit_url):
            continue
        out.append({
            "source": "hn",
            "title": title or "(no title)",
            "url": url_field,
            "snippet": None,
            # P19: normalise to ISO 8601 — HN already returns ISO strings but
            # run through the helper for uniformity and to catch edge cases.
            "date": _parse_date_to_iso(hit.get("created_at")),
        })
    return out


# --- Reddit ------------------------------------------------------------------
def search_reddit(query: str, limit: int, timeout: int) -> list[dict]:
    """Search Reddit via the public `search.json` endpoint.

    Returns up to `limit` hits in the uniform schema.
    """
    url = (
        f"https://www.reddit.com/search.json?q={quote(query)}"  # NOTE-BIAS-OK: Phase 0 public API
        f"&limit={limit}"
    )
    body = _safe_fetch(url, timeout)
    if not body:
        return []
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError) as e:
        _warn(f"reddit: JSON parse error: {e}")
        return []

    children = (data.get("data") or {}).get("children")
    if not isinstance(children, list):
        _warn("reddit: response had no `data.children` list")
        return []

    out: list[dict] = []
    for child in children[:limit]:
        if not isinstance(child, dict):
            continue
        post = child.get("data")
        if not isinstance(post, dict):
            continue
        permalink = post.get("permalink")
        if not permalink:
            continue
        selftext = post.get("selftext") or ""
        snippet = selftext[:200].strip() or None
        out.append({
            "source": "reddit",
            "title": post.get("title") or "(no title)",
            "url": f"https://www.reddit.com{permalink}",  # NOTE-BIAS-OK: Phase 0 public API
            "snippet": snippet,
            "date": _epoch_to_iso(post.get("created_utc")),
        })
    return out


# --- Bluesky -----------------------------------------------------------------
def _bsky_rkey(uri: str) -> str | None:
    """Extract the record key from an `at://` post URI.

    A post URI looks like `at://<did>/app.bsky.feed.post/<rkey>`; the rkey is
    the final path segment. Returns None if the URI is malformed.
    """
    if not uri or "/" not in uri:
        return None
    rkey = uri.rsplit("/", 1)[-1].strip()
    return rkey or None


def search_bluesky(query: str, limit: int, timeout: int) -> list[dict]:
    """Search Bluesky posts via the public AppView `searchPosts` XRPC.

    Returns up to `limit` hits in the uniform schema.
    """
    url = (
        f"https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts"  # NOTE-BIAS-OK: Phase 0 public API
        f"?q={quote(query)}&limit={limit}"
    )
    body = _safe_fetch(url, timeout)
    if not body:
        return []
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError) as e:
        _warn(f"bluesky: JSON parse error: {e}")
        return []

    posts = data.get("posts")
    if not isinstance(posts, list):
        _warn("bluesky: response had no `posts` list")
        return []

    out: list[dict] = []
    for post in posts[:limit]:
        if not isinstance(post, dict):
            continue
        record = post.get("record") or {}
        text = record.get("text") if isinstance(record, dict) else None
        text = text or ""
        author = post.get("author") or {}
        handle = author.get("handle") if isinstance(author, dict) else None
        rkey = _bsky_rkey(post.get("uri") or "")
        if not handle or not rkey:
            # Without a handle and rkey there is no addressable post URL.
            continue
        out.append({
            "source": "bluesky",
            "title": (text[:80].strip() or "(no text)"),
            "url": f"https://bsky.app/profile/{handle}/post/{rkey}",  # NOTE-BIAS-OK: Phase 0 public API
            "snippet": text or None,
            # P19: normalise to ISO 8601 — bsky indexedAt is already ISO.
            "date": _parse_date_to_iso(post.get("indexedAt")),
        })
    return out


# --- arXiv -------------------------------------------------------------------
def _parse_arxiv_atom(text: str, limit: int) -> list[dict]:
    """Parse an arXiv Atom feed string into uniform-schema hits.

    Applies the same XML security guards as `crawl.py`: oversized input is
    truncated and any document declaring a DTD is refused outright.
    """
    if not text:
        return []
    if len(text) > _MAX_PARSE_BYTES:
        _warn(f"arxiv: input exceeds {_MAX_PARSE_BYTES} bytes — truncated")
        text = text[:_MAX_PARSE_BYTES]
    # DTDs are never legitimate in the arXiv Atom feed; their presence is the
    # entry point for XXE and billion-laughs attacks. Refuse outright
    # (case-insensitive — `<!doctype` is equally a DTD declaration).
    if "<!DOCTYPE" in text.upper():
        _warn("arxiv: <!DOCTYPE> present — refusing to parse (XXE guard)")
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        _warn(f"arxiv: XML parse error: {e}")
        return []

    def _local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    out: list[dict] = []
    for child in root:
        if _local(child.tag) != "entry":
            continue
        title = None
        entry_url = None
        summary = None
        published = None
        for sub in child:
            name = _local(sub.tag)
            value = (sub.text or "").strip()
            if name == "title":
                title = " ".join(value.split()) or None
            elif name == "id":
                entry_url = value or None
            elif name == "summary":
                summary = " ".join(value.split()) or None
            elif name == "published":
                published = value or None
        if not entry_url:
            continue
        out.append({
            "source": "arxiv",
            "title": title or "(no title)",
            "url": entry_url,
            "snippet": summary[:300] if summary else None,
            # P19: normalise to ISO 8601 — arXiv published is already ISO.
            "date": _parse_date_to_iso(published),
        })
        if len(out) >= limit:
            break
    return out


def search_arxiv(query: str, limit: int, timeout: int) -> list[dict]:
    """Search arXiv via the public Atom query API.

    Returns up to `limit` hits in the uniform schema.
    """
    # P3 (2026-06-11): use https — plaintext http exposed search terms.
    url = (
        f"https://export.arxiv.org/api/query?search_query=all:{quote(query)}"  # NOTE-BIAS-OK: Phase 0 public API
        f"&max_results={limit}"
    )
    body = _safe_fetch(url, timeout)
    if not body:
        return []
    try:
        return _parse_arxiv_atom(body, limit)
    except Exception as e:  # noqa: BLE001
        _warn(f"arxiv: {type(e).__name__}: {e}")
        return []


# --- Naver -------------------------------------------------------------------
def _parse_naver_html(html: str, limit: int) -> list[dict]:
    """Parse a Naver integrated-search HTML page into uniform-schema hits.

    Naver markup changes often, so link discovery is defensive: several title
    selectors are tried in turn, and only outbound http(s) links are kept —
    internal Naver navigation links are excluded.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        _warn("naver: beautifulsoup4 not installed — cannot parse HTML")
        return []

    soup = BeautifulSoup(html, "html.parser")

    # Title-link selector candidates, most specific first. Naver's integrated
    # search rotates class names; trying several keeps the parser resilient.
    selectors = (
        "a.title_link",
        "a.api_txt_lines.total_tit",
        "a.api_txt_lines",
        "a.news_tit",
        "a.total_tit",
        "div.total_wrap a.link_tit",
    )

    def _is_outbound(href: str) -> bool:
        """True for an absolute http(s) link that is not a Naver host."""
        if not href or not href.startswith(("http://", "https://")):
            return False
        host = urlsplit(href).netloc.lower()
        # Drop Naver's own hosts — those are internal nav, not results.
        return "naver.com" not in host and "naver.net" not in host  # NOTE-BIAS-OK: Phase 0 — filtering Naver's own nav links out of results

    out: list[dict] = []
    seen: set[str] = set()
    for selector in selectors:
        for tag in soup.select(selector):
            href = tag.get("href")
            if not _is_outbound(href) or href in seen:
                continue
            # Phase 3 F10: outbound result must clear SSRF guard — search
            # results are attacker-influenceable via SEO spam.
            if not _outbound_url_safe(href):
                continue
            title = tag.get_text(strip=True)
            if not title:
                continue
            seen.add(href)
            out.append({
                "source": "naver",
                "title": title,
                "url": href,
                "snippet": None,
                "date": None,
            })
            if len(out) >= limit:
                return out
        if out:
            # A selector matched — good enough; do not mix in noisier ones.
            break

    if not out:
        _warn("naver: no result links found (markup may have changed)")
    return out


def search_naver(query: str, limit: int, timeout: int) -> list[dict]:
    """Search Naver integrated web search by scraping the results page.

    Returns up to `limit` hits in the uniform schema.
    """
    url = f"https://search.naver.com/search.naver?query={quote(query)}"  # NOTE-BIAS-OK: Phase 0 public API
    body = _safe_fetch(url, timeout)
    if not body:
        return []
    try:
        return _parse_naver_html(body, limit)
    except Exception as e:  # noqa: BLE001
        _warn(f"naver: {type(e).__name__}: {e}")
        return []


# --- DuckDuckGo --------------------------------------------------------------
def _ddg_real_url(href: str) -> str:
    """Resolve a DuckDuckGo result href to the real destination URL.

    DDG often wraps results in a redirector of the form
    `//duckduckgo.com/l/?uddg=<encoded real URL>&...`; the real URL lives in  # NOTE-BIAS-OK: Phase 0 public API — explaining DDG redirect unwrap
    the `uddg` query parameter. A direct (non-redirector) href is returned
    unchanged.
    """
    if not href:
        return href
    parts = urlsplit(href)
    # The redirector path is `/l/`; only then is a `uddg` param meaningful.
    if parts.path.rstrip("/").endswith("/l") or parts.path == "/l/":
        params = parse_qs(parts.query)
        uddg = params.get("uddg")
        if uddg and uddg[0]:
            return uddg[0]
    return href


def _parse_ddg_html(html: str, limit: int) -> list[dict]:
    """Parse a DuckDuckGo HTML results page into uniform-schema hits."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        _warn("ddg: beautifulsoup4 not installed — cannot parse HTML")
        return []

    soup = BeautifulSoup(html, "html.parser")
    out: list[dict] = []
    seen: set[str] = set()
    for block in soup.select(".result"):
        link = block.select_one("a.result__a")
        if link is None:
            continue
        href = link.get("href")
        if not href:
            continue
        real_url = _ddg_real_url(href)
        if not real_url.startswith(("http://", "https://")) or real_url in seen:
            continue
        # Phase 3 F10: DDG redirector → SSRF re-amp. SEO-spam top result
        # could point at internal IP; refuse to surface it.
        if not _outbound_url_safe(real_url):
            continue
        title = link.get_text(strip=True)
        if not title:
            continue
        snippet_tag = block.select_one(".result__snippet")
        snippet = snippet_tag.get_text(strip=True) if snippet_tag else None
        seen.add(real_url)
        out.append({
            "source": "ddg",
            "title": title,
            "url": real_url,
            "snippet": snippet or None,
            "date": None,
        })
        if len(out) >= limit:
            break

    if not out:
        _warn("ddg: no result blocks found (markup may have changed)")
    return out


def search_ddg(query: str, limit: int, timeout: int) -> list[dict]:
    """Search DuckDuckGo by scraping its HTML results endpoint.

    Returns up to `limit` hits in the uniform schema.
    """
    url = f"https://html.duckduckgo.com/html/?q={quote(query)}"  # NOTE-BIAS-OK: Phase 0 public API
    body = _safe_fetch(url, timeout)
    if not body:
        return []
    try:
        return _parse_ddg_html(body, limit)
    except Exception as e:  # noqa: BLE001
        _warn(f"ddg: {type(e).__name__}: {e}")
        return []


# --- DuckDuckGo via ddgs library (P38) ---------------------------------------
# ddgs per-call timeout cap: worst-case must stay within _SEARCH_FUTURE_WAIT_S
# (45 s) so the ThreadPoolExecutor budget arithmetic is not broken (W30).
# ddgs uses its own socket stack (primp/httpx) — not routed through engine.fetch.
# Result URLs still pass _outbound_url_safe before surfacing (consensus F10).
_DDGS_TIMEOUT_S = _SEARCH_FUTURE_WAIT_S - 5  # 40 s hard ceiling


def search_ddgs(query: str, limit: int, timeout: int) -> list[dict]:
    """Search via the ``ddgs`` library (backend=auto, 10-engine rotation).

    Soft-dep: if ``ddgs`` is not installed this source is skipped with a single
    stderr warning and an empty list is returned — existing sources are
    unaffected.

    **Security note**: ``ddgs`` opens its own sockets via primp/httpx and
    therefore bypasses the engine's DoH / WAF-verdict pipeline.  Result URLs
    are validated through ``_outbound_url_safe`` before being surfaced, matching
    the guard applied to all other sources (consensus F10 / W33).

    The per-call timeout is clamped to ``_DDGS_TIMEOUT_S`` (40 s) so the
    worst-case wall-clock cannot exceed ``_SEARCH_FUTURE_WAIT_S`` and reintroduce
    the zombie-thread window fixed by P19 (W30).
    """
    try:
        from ddgs import DDGS  # soft-dep
    except ImportError:
        _warn(
            "ddgs: 'ddgs' package not installed — skipping source. "
            "Install with: pip install --index-url https://pypi.org/simple 'ddgs>=9'"  # NOTE-BIAS-OK: official PyPI index
        )
        return []

    capped_timeout = min(timeout, _DDGS_TIMEOUT_S)
    out: list[dict] = []
    try:
        with DDGS() as d:
            raw_results = list(d.text(query, max_results=limit))
    except Exception as e:  # noqa: BLE001
        _warn(f"ddgs: {type(e).__name__}: {e}")
        return []

    for item in raw_results[:limit]:
        if not isinstance(item, dict):
            continue
        url = item.get("href") or item.get("url") or ""
        if not url or not url.startswith(("http://", "https://")):
            continue
        # P38: SSRF re-amplification guard — same gate as ddg/naver (F10).
        if not _outbound_url_safe(url):
            continue
        title = item.get("title") or "(no title)"
        snippet = item.get("body") or None
        # ddgs does not return a date field; leave as None for uniform schema.
        out.append({
            "source": "ddgs",
            "title": title,
            "url": url,
            "snippet": snippet,
            "date": None,
        })
    return out


# --- dispatch + merge --------------------------------------------------------
# Source name -> handler. The single registry the dispatcher and the CLI both
# consult, so a new source is wired up in exactly one place.
_HANDLERS = {
    "hn": search_hn,
    "reddit": search_reddit,
    "bluesky": search_bluesky,
    "arxiv": search_arxiv,
    "naver": search_naver,
    "ddg": search_ddg,
    "ddgs": search_ddgs,  # P38 (2026-06-12): ddgs library backend=auto rotation
}


def _normalize_url(url: str) -> str:
    """Normalize a URL for de-duplication.

    Transformations applied (P19 W46):
      - Lowercase host.
      - Strip trailing slash from path.
      - Remove known ad/tracking parameters (utm_*, fbclid, gclid, …).
      - Sort remaining query parameters by key for stable comparison so
        `?a=1&b=2` and `?b=2&a=1` are treated as the same URL.
      - Drop fragment (#…): hits differing only by fragment are duplicates.

    Meaningful query parameters (e.g. reddit post IDs, arxiv search terms)
    are preserved — only the tracking-param whitelist is removed.
    """
    if not url:
        return url
    parts = urlsplit(url)
    netloc = parts.netloc.lower()
    path = parts.path.rstrip("/")
    rebuilt = f"{parts.scheme}://{netloc}{path}"
    if parts.query:
        # Parse, filter tracking params, sort remaining, rebuild.
        params = parse_qs(parts.query, keep_blank_values=True)
        cleaned = {}
        for k, v in params.items():
            k_lower = k.lower()
            if k_lower in _TRACKING_PARAMS:
                continue
            if any(k_lower.startswith(p) for p in _TRACKING_PREFIXES):
                continue
            cleaned[k] = v
        if cleaned:
            # Sort keys for stable dedup key regardless of original order.
            rebuilt += "?" + urlencode(
                sorted(
                    ((k, vi) for k, vs in cleaned.items() for vi in vs),
                    key=lambda kv: kv[0],
                ),
            )
    return rebuilt


def _recency_score(date_str: str | None) -> float:
    """Return a recency score for a hit (higher = more recent).

    Used as a lightweight tiebreaker in _score_hit.  Parses ISO 8601 strings
    only (all dates entering here have already been through _parse_date_to_iso).
    Returns 0.0 when the date is absent or unparseable — missing-date hits sort
    to the bottom of any recency tier.
    """
    if not date_str:
        return 0.0
    try:
        # Only handle the subset of ISO 8601 that our sources actually emit.
        # Strip trailing Z → +00:00 so fromisoformat works on Python 3.10.
        s = date_str.replace("Z", "+00:00")
        # Drop sub-second precision if present (fromisoformat is picky).
        s = re.sub(r"\.\d+(?=[+-])", "", s)
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, AttributeError, OSError):
        return 0.0


def _score_hit(hit: dict, query_terms: list[str]) -> float:
    """Lightweight relevance + recency score for a merged hit (P19 W29).

    Score = query-term coverage (0–1) * 2  +  recency component (0–1).

    Query-term coverage: fraction of lowercased query tokens present in the
    combined title+snippet text.  Recency component: sigmoid-like decay so
    very recent hits (< 7 days) score close to 1 and older hits approach 0,
    never dominating over a strong term match.
    """
    import time as _time

    text = " ".join(filter(None, [
        hit.get("title") or "",
        hit.get("snippet") or "",
    ])).lower()

    term_score = 0.0
    if query_terms:
        matched = sum(1 for t in query_terms if t in text)
        term_score = matched / len(query_terms)

    now = _time.time()
    age_s = now - _recency_score(hit.get("date"))
    # Decay: score ≈ 1 when age < 1 day, ≈ 0.5 at 7 days, ≈ 0 beyond 30 days.
    recency_score = 1.0 / (1.0 + age_s / 86400.0) if age_s > 0 else 1.0

    return term_score * 2.0 + recency_score


def search(
    query: str,
    sources: list[str],
    limit: int,
    timeout: int,
    max_results: int | None = None,
) -> dict:
    """Query `query` across `sources` in parallel and merge the results.

    Parameters
    ----------
    query : str
        The search keyword(s).
    sources : list[str]
        Source names to query — any subset of `SOURCES`. Unknown names are
        warned about and skipped.
    limit : int
        Per-source cap on the number of hits.
    timeout : int
        Per-fetch timeout in seconds.
    max_results : int | None
        Global cap on the total number of results returned after merging.
        None (default) means no global cap — all deduplicated hits are
        returned.  (P19 W29: --max-results CLI flag wires into this.)

    Returns
    -------
    dict
        `{"query": str, "sources": list[str], "count": int, "results": list}`.
        `sources` echoes the requested (and recognised) source list; `results`
        is the merged, URL-deduplicated, interleaved list of uniform-schema hits.

    Raises
    ------
    BlockedQueryError
        When `query` contains a term from `~/.config/page-fetch/blocked-terms` (Phase 3
        F9 guard). Does NOT subclass ValueError — a generic ``except
        ValueError:`` will NOT catch it; callers must catch
        ``BlockedQueryError`` explicitly.  # P3 (2026-06-11): corrected W38
    """
    # Phase 3 (consensus F9): refuse to send user-blocked terms to the six
    # external APIs. The user's INSANE_BLOCKED_TERMS_FILE selects their own list.
    # Done first so the guard cost is paid once even with an empty source list.
    from ._security import _check_blocked_query, BlockedQueryError
    matched = _check_blocked_query(query)
    if matched:
        # P3 (2026-06-11): do NOT echo the matched term — output-0 policy.
        # Point the user to the blocklist file path instead (W11).
        raise BlockedQueryError(
            "search query contains a blocked term; refusing to send to external "
            "APIs. Review INSANE_BLOCKED_TERMS_FILE or ~/.config/page-fetch/blocked-terms; set "
            "INSANE_DISABLE_BLOCKED_TERMS=1 to override."
        )

    valid: list[str] = []
    for name in sources:
        if name in _HANDLERS:
            valid.append(name)
        else:
            _warn(f"unknown source {name!r} — skipping")

    # Collect per-source results keyed by source name.
    per_source: dict[str, list[dict]] = {name: [] for name in valid}
    if valid:
        # One thread per source — each handler is I/O-bound on a single fetch.
        with ThreadPoolExecutor(max_workers=len(valid)) as pool:
            futures = {
                name: pool.submit(_HANDLERS[name], query, limit, timeout)
                for name in valid
            }
            for name in valid:
                try:
                    # P19 (2026-06-12): use _SEARCH_FUTURE_WAIT_S instead of
                    # timeout+10.  Old arithmetic: 3×15=45s > 25+10=35s — the
                    # wait was shorter than the per-source worst-case, leaving
                    # a zombie-thread window (W30).  Fixed: wait = 45 s exactly.
                    hits = futures[name].result(timeout=_SEARCH_FUTURE_WAIT_S)
                except Exception as e:  # noqa: BLE001
                    _warn(f"{name}: {type(e).__name__}: {e}")
                    hits = []
                if isinstance(hits, list):
                    per_source[name] = hits

    # P19 (2026-06-12): round-robin interleave across sources (W29).
    # Rather than dumping all hits from source A then all from source B,
    # zip across sources in order so the merged list alternates.  This means
    # the top result from each source appears early, giving a fairer cross-
    # source view before the global cap is applied.
    max_per_source = max((len(v) for v in per_source.values()), default=0)
    interleaved: list[dict] = []
    for i in range(max_per_source):
        for name in valid:
            hits = per_source[name]
            if i < len(hits):
                interleaved.append(hits[i])

    # De-duplicate by normalized URL — first occurrence wins.
    merged: list[dict] = []
    seen: set[str] = set()
    for hit in interleaved:
        key = _normalize_url(hit.get("url") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(hit)

    # P19 (2026-06-12): lightweight relevance+recency re-sort within the
    # interleaved order (W29).  Score each hit; sort descending so higher-
    # relevance / more-recent hits float to the top.  Stable sort preserves
    # the interleave order among equal-score hits.
    query_terms = [t.lower() for t in query.split() if t]
    merged.sort(key=lambda h: _score_hit(h, query_terms), reverse=True)

    # P19 (2026-06-12): global cap after dedup+sort (W29 --max-results).
    if max_results is not None and max_results >= 0:
        merged = merged[:max_results]

    return {
        "query": query,
        "sources": valid,
        "count": len(merged),
        "results": merged,
    }
