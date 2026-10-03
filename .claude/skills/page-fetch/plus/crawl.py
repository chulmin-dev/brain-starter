"""Crawl layer for page-fetch — Stage 2.

`crawl` discovers many URLs from a starting point and optionally collects each
one. Discovery has three concrete modes plus an `auto` chooser:

  * sitemap  — robots.txt → Sitemap: → sitemap.xml / sitemapindex (1-level
               recursion only).
  * rss      — an RSS/Atom feed, found directly or via an HTML <link rel>,
               including JSON Feed (jsonfeed.org).  # NOTE-BIAS-OK: spec site
  * paginate — follow `rel="next"` from page to page.

Every network fetch goes through the engine (`engine.fetch`), so DoH, WAF
bypass and verdict validation all apply for free. This module only *parses*
what the engine returns; it never opens a socket itself.

Parsing untrusted XML is a security boundary. Sitemaps and RSS feeds never
need a DTD, so any input containing `<!DOCTYPE` is rejected outright (XXE /
billion-laughs defence), and the text handed to the parser is size-capped.

Politeness (P5): inter-request delay, robots Crawl-delay, 429 backoff.
  INSANE_CRAWL_DELAY_MS  — base inter-request delay, default 500 ms.
  INSANE_RESPECT_ROBOTS  — set to "1" to also honour robots.txt Disallow rules.
                           Default off (bypass-tool nature; user opt-in only).

Discovery expansion (P37, origin Skill_Seekers + trafilatura 5/6):
  * llms.txt probe — `discover_llms_txt` GETs /llms.txt (+ /llms-full.txt),
    the LLM-friendly index many doc sites now ship, so documentation crawls
    skip WAF bypass entirely when one exists.
  * sitemap GUESSES + .txt + gzip + plausibility — beyond /sitemap.xml the
    discovery now tries common alternative paths, accepts newline-delimited
    .txt sitemaps, decompresses .gz bodies, and validates each candidate is
    actually a sitemap (plausibility guard) so a WAF block page returned as a
    200 is not mis-parsed as a sitemap.
  * JSON Feed — `discover_rss` recognizes application/feed+json bodies (the
    jsonfeed.org standard) and links alongside RSS/Atom.  # NOTE-BIAS-OK: spec
  * gnews probe — `gnews_search_url` builds a Google News RSS query URL for a
    keyword so news discovery has a no-bypass path.
  All P37 probes reuse the existing _safe_fetch SSRF guard and the
  _MAX_CRAWL_SECONDS / _MAX_SITEMAP_URLS budgets — no new network primitive.
"""
from __future__ import annotations

import gzip
import json
import os
import sys
import time
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus, urljoin, urlsplit

from engine import fetch as engine_fetch

# Hard cap on the byte size of any XML/HTML blob handed to a parser. Sitemaps
# and feeds are small in practice; anything larger is truncated rather than
# parsed whole — a blunt but effective amplification-attack guard.
_MAX_PARSE_BYTES = 10 * 1024 * 1024  # 10 MB

# Cap on how many `Sitemap:` URLs we follow out of one robots.txt. Real sites
# list 1-5; a flood of entries would be a fetch-amplification vector.
_MAX_SITEMAP_URLS = 20


def _int_env(name: str, default: int) -> int:
    """Read a positive int from `name` env or fall back to `default`."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        v = int(raw)
        return v if v > 0 else default
    except ValueError:
        return default


# Phase 2 budgets (consensus NEW: GPT/Gemini sitemap-fan-out + total-time).
# Sitemap discovery follows N sub-sitemaps, each of which can itself be a
# slow fetch. Without a wall-clock cap, an attacker-controlled robots.txt
# pointing at slow endpoints can stall the crawler for many minutes.
_MAX_CRAWL_SECONDS = _int_env("INSANE_CRAWL_MAX_SECONDS", 120)
_MAX_CHILD_SITEMAPS = _int_env("INSANE_CRAWL_MAX_CHILD_SITEMAPS", 50)

# P20 (2026-06-12): clamp crawl _safe_fetch engine attempts to match
# search.py's pattern (consensus N2) — prevents a single WAF'd URL from
# burning the full 12-attempt engine budget during a crawl fetch.
# Kept separate from sitemap's wall-clock budget: the clamp is per-request,
# the budget is total wall-clock for a discovery phase.
_CRAWL_MAX_ATTEMPTS = _int_env("INSANE_CRAWL_MAX_ATTEMPTS", 3)

# P5: Crawl politeness — base inter-request delay.
# Default 500 ms is a conservative floor to reduce rate-limit ban risk
# for production egress addresses.
_CRAWL_DELAY_MS = _int_env("INSANE_CRAWL_DELAY_MS", 500)
# 429 one-shot backoff duration (seconds).  A single 60 s wait is enough to
# clear transient rate limits without looping indefinitely.
_RATE_LIMIT_BACKOFF_S = 60
# Opt-in: honour robots.txt Disallow rules (default off — bypass tool).
_RESPECT_ROBOTS = os.environ.get("INSANE_RESPECT_ROBOTS") == "1"

# P37: common sitemap path guesses tried (in order) after robots.txt /
# sitemap.xml yields nothing. Real sites use one of these conventions; the
# list is short and ordered by prevalence so the fetch-amplification cost is
# bounded by _MAX_SITEMAP_URLS + len(this list).
_SITEMAP_GUESSES = (
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/sitemap.xml.gz",
    "/sitemap.txt",
    "/wp-sitemap.xml",
)

# P37: llms.txt index files tried, most-specific first. llms-full.txt is the
# expanded variant; llms.txt is the curated index (llmstxt.org convention).  # NOTE-BIAS-OK: spec site
_LLMS_TXT_PATHS = ("/llms.txt", "/llms-full.txt")

# P37: Google News RSS endpoint for keyword search (no bypass needed — it is a
# public RSS feed). hl/gl/ceid default to Korean locale to match the user's
# primary use; callers can override via gnews_search_url params.
_GNEWS_SEARCH_BASE = "https://news.google.com/rss/search"  # NOTE-BIAS-OK: public RSS search endpoint, load-bearing


def _extract_crawl_delay(robots_text: str) -> float | None:
    """Return the first Crawl-delay value (seconds) found in robots.txt, or None.

    Scans all User-agent blocks; takes the first numeric value found.
    """
    if not robots_text:
        return None
    for line in robots_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("crawl-delay:"):
            value = stripped.split(":", 1)[1].strip()
            try:
                v = float(value)
                return v if v > 0 else None
            except ValueError:
                continue
    return None


def _extract_disallow_paths(robots_text: str) -> list[str]:
    """Return all Disallow paths from robots.txt (for opt-in INSANE_RESPECT_ROBOTS).

    Collects from every User-agent block; ignores the specific agent.
    """
    paths: list[str] = []
    if not robots_text:
        return paths
    for line in robots_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("disallow:"):
            value = stripped.split(":", 1)[1].strip()
            if value:
                paths.append(value)
    return paths


def _is_disallowed(url: str, disallow_paths: list[str]) -> bool:
    """Return True if `url` matches any Disallow path."""
    path = urlsplit(url).path or "/"
    for prefix in disallow_paths:
        if path.startswith(prefix):
            return True
    return False


def _politeness_delay(robots_crawl_delay_s: float | None) -> None:
    """Sleep the configured inter-request delay.

    The actual delay is max(INSANE_CRAWL_DELAY_MS, robots Crawl-delay * 1000)
    so the robots Crawl-delay is treated as a floor when it is larger.
    """
    base_ms = _CRAWL_DELAY_MS
    if robots_crawl_delay_s is not None:
        robots_ms = int(robots_crawl_delay_s * 1000)
        base_ms = max(base_ms, robots_ms)
    if base_ms > 0:
        time.sleep(base_ms / 1000.0)


def _last_status(result) -> int:
    """Return the HTTP status of the last trace attempt, or 0 if unavailable."""
    try:
        if result.trace:
            return result.trace[-1].status
    except (AttributeError, IndexError):
        pass
    return 0


def _warn(msg: str) -> None:
    """Emit a non-fatal crawl warning to stderr."""
    print(f"[plus] crawl warning: {msg}", file=sys.stderr)


def _site_root(url: str) -> str:
    """Return `scheme://host/` for `url` (the site root)."""
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}/"


def _localname(tag: str) -> str:
    """Strip any XML namespace, returning the bare local tag name.

    ElementTree reports namespaced tags as `{namespace}localname`; sitemap and
    Atom documents are namespaced, so all tag matching uses the local name and
    is therefore namespace-agnostic.
    """
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _safe_fetch(url: str, timeout: int) -> str | None:
    """Fetch `url` via the engine, returning its body or None on any failure.

    Never raises — a single dead URL must not abort the whole crawl.

    P20 (2026-06-12): clamps engine max_attempts to _CRAWL_MAX_ATTEMPTS
    (default 3), matching search.py's pattern (consensus N2).  Without this
    clamp the engine's default of 12 attempts could stall a sitemap/rss/
    paginate fetch for minutes on a WAF'd URL (W31).
    """
    try:
        result = engine_fetch(url, timeout=timeout,
                              max_attempts=_CRAWL_MAX_ATTEMPTS)
    except Exception as e:  # noqa: BLE001
        _warn(f"fetch failed for {url}: {type(e).__name__}: {e}")
        return None
    if not result.ok:
        # An unsuccessful verdict can still carry a usable body (e.g. weak_ok
        # downgraded by missing selectors); hand back whatever content exists.
        _warn(f"fetch unsuccessful for {url}: verdict={result.verdict}")
    # Coerce an empty body to None on both paths so callers have one sentinel.
    return result.content or None


def _maybe_gunzip(text: str | None, url: str) -> str | None:
    """If `url` looks gzip-compressed, attempt to decompress `text`.

    The engine returns a decoded `str`, not bytes, so a `.gz` body has been
    charset-decoded already. We round-trip through latin-1 (a 1:1 byte<->code
    point map) to recover the original bytes, then gunzip. Latin-1 is the only
    encoding that never raises on decode, so the round-trip is lossless for the
    byte range a gzip stream occupies.

    Returns the decompressed UTF-8 text, or the original `text` unchanged when
    the URL is not gz / decompression fails (best-effort — never raises).
    """
    if text is None:
        return None
    if not url.lower().endswith(".gz"):
        return text
    try:
        raw = text.encode("latin-1", errors="replace")
        decompressed = gzip.decompress(raw)
        return decompressed.decode("utf-8", errors="replace")
    except (OSError, EOFError, ValueError) as e:
        _warn(f"gzip: failed to decompress {url}: {type(e).__name__}: {e}")
        return text


def _looks_like_sitemap(text: str | None) -> bool:
    """P37 plausibility guard: True if `text` plausibly is an XML sitemap.

    A WAF block page (or any HTML) returned with a 200 status would otherwise
    be handed to the XML parser, fail, and waste a guess. We require the body
    to contain a sitemap/urlset root tag and NOT be an obvious HTML document.
    Cheap substring checks only — the authoritative parse still happens in
    _parse_xml (with its DOCTYPE/XXE guard).
    """
    if not text:
        return False
    head = text.lstrip()[:512].lower()
    if head.startswith("<!doctype html") or head.startswith("<html"):
        return False
    return ("<urlset" in text[:2048].lower()
            or "<sitemapindex" in text[:2048].lower())


def _parse_txt_sitemap(text: str | None) -> list[dict]:
    """P37: parse a newline-delimited .txt sitemap into URL entries.

    A .txt sitemap (the sitemaps.org spec) is one absolute URL per line.  # NOTE-BIAS-OK: spec site
    Blank lines and obvious non-URLs (no scheme) are skipped. No lastmod is
    available in this format, so every entry's lastmod is None.
    """
    entries: list[dict] = []
    seen: set[str] = set()
    if not text:
        return entries
    for line in text.splitlines():
        loc = line.strip()
        if not loc or "://" not in loc:
            continue
        if not loc.lower().startswith(("http://", "https://")):
            continue
        if loc in seen:
            continue
        seen.add(loc)
        entries.append({"loc": loc, "lastmod": None})
    return entries


def _parse_xml(text: str, source: str) -> ET.Element | None:
    """Parse `text` into an XML root element, with security guards.

    Rejects any document declaring a DTD and truncates oversized input before
    parsing. Returns None (with a warning) on rejection or malformed XML.
    """
    if text is None:
        return None
    if len(text) > _MAX_PARSE_BYTES:
        _warn(f"{source}: input exceeds {_MAX_PARSE_BYTES} bytes — truncated")
        text = text[:_MAX_PARSE_BYTES]
    # DTDs are never legitimate in a sitemap or feed; their presence is the
    # entry point for XXE and billion-laughs attacks. Refuse outright.
    if "<!DOCTYPE" in text:
        _warn(f"{source}: <!DOCTYPE> present — refusing to parse (XXE guard)")
        return None
    try:
        return ET.fromstring(text)
    except ET.ParseError as e:
        _warn(f"{source}: XML parse error: {e}")
        return None


# --- sitemap discovery -------------------------------------------------------
def _parse_sitemap_root(root: ET.Element) -> tuple[list[dict], list[str]]:
    """Split a parsed sitemap document into URL entries and child sitemaps.

    Returns `(url_entries, child_sitemap_locs)`. For a `<urlset>` the first
    list is populated; for a `<sitemapindex>` the second is.
    """
    kind = _localname(root.tag)
    url_entries: list[dict] = []
    child_locs: list[str] = []

    if kind == "sitemapindex":
        for child in root:
            if _localname(child.tag) != "sitemap":
                continue
            for sub in child:
                if _localname(sub.tag) == "loc" and (sub.text or "").strip():
                    child_locs.append(sub.text.strip())
    elif kind == "urlset":
        for child in root:
            if _localname(child.tag) != "url":
                continue
            loc = None
            lastmod = None
            for sub in child:
                name = _localname(sub.tag)
                if name == "loc" and (sub.text or "").strip():
                    loc = sub.text.strip()
                elif name == "lastmod" and (sub.text or "").strip():
                    lastmod = sub.text.strip()
            if loc:
                url_entries.append({"loc": loc, "lastmod": lastmod})
    else:
        _warn(f"sitemap: unexpected root <{kind}> — expected urlset/sitemapindex")

    return url_entries, child_locs


def _extract_sitemap_lines(robots_text: str) -> list[str]:
    """Pull every `Sitemap:` URL out of a robots.txt body (case-insensitive)."""
    out: list[str] = []
    for line in robots_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("sitemap:"):
            value = stripped.split(":", 1)[1].strip()
            if value:
                out.append(value)
    return out


def discover_llms_txt(base_url: str, timeout: int) -> list[dict]:
    """P37: probe a site's llms.txt index (llmstxt.org convention).  # NOTE-BIAS-OK: spec site

    Many documentation sites ship `/llms.txt` (a curated, LLM-friendly index)
    and/or `/llms-full.txt`. When present they list the canonical doc URLs as
    Markdown links — so a documentation crawl can read those directly and skip
    WAF bypass entirely.

    Returns `[{"loc": str, "lastmod": None, "title": str | None}, ...]`,
    de-duplicated by loc. Empty list when no llms.txt exists or it lists no
    absolute URLs. FetchResult exposes no HEAD, so this is a small GET; the
    body is plausibility-checked (must not be HTML) before link extraction.
    """
    root_url = _site_root(base_url)
    entries: list[dict] = []
    seen: set[str] = set()
    for path in _LLMS_TXT_PATHS:
        body = _safe_fetch(urljoin(root_url, path), timeout)
        if not body:
            continue
        head = body.lstrip()[:512].lower()
        if head.startswith("<!doctype html") or head.startswith("<html"):
            # A WAF/404 HTML page served with 200 — not an llms.txt index.
            continue
        for loc, title in _extract_llms_links(body):
            if loc in seen:
                continue
            seen.add(loc)
            entries.append({"loc": loc, "lastmod": None, "title": title})
        if entries:
            # First file that yielded links wins — don't double-fetch the
            # full variant when the curated index already produced URLs.
            break
    return entries


def _extract_llms_links(text: str) -> list[tuple[str, str | None]]:
    """Extract `(url, title)` pairs from an llms.txt body.

    Recognizes Markdown link syntax `[title](url)` and bare absolute URLs on
    their own line. Only http(s) URLs are returned. Pure stdlib regex — no bs4.
    """
    import re

    out: list[tuple[str, str | None]] = []
    # Markdown links: [title](https URL)  # NOTE-BIAS-OK: placeholder, not a host
    for m in re.finditer(r"\[([^\]]*)\]\((https?://[^\s)]+)\)", text):
        title = m.group(1).strip() or None
        out.append((m.group(2).strip(), title))
    # Bare absolute URLs on a line (skip ones already captured as md links).
    captured = {u for _, u in out}
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(("http://", "https://")) and " " not in s:
            if s not in captured:
                out.append((s, None))
                captured.add(s)
    return out


def discover_sitemap(base_url: str, timeout: int) -> list[dict]:
    """Discover URLs for a site via its sitemap(s).

    Resolves the site root from `base_url`, reads `robots.txt` for `Sitemap:`
    lines (falling back to `/sitemap.xml` then the P37 guess list), then
    fetches and parses each sitemap. A `<sitemapindex>` is recursed exactly one
    level deep. P37: `.txt` sitemaps and gzip-compressed (`.gz`) sitemaps are
    also handled, and every candidate body is plausibility-checked before XML
    parsing so a 200 WAF/HTML page is never mis-read as a sitemap.

    Wall-clock budget: `INSANE_CRAWL_MAX_SECONDS` (default 120s) caps the
    whole discovery; partial results are returned with a warning when hit.
    Child sitemap fan-out is also capped by `INSANE_CRAWL_MAX_CHILD_SITEMAPS`
    (default 50) per sitemapindex.

    Returns `[{"loc": str, "lastmod": str | None}, ...]`, de-duplicated by loc.
    """
    deadline = time.monotonic() + _MAX_CRAWL_SECONDS
    root_url = _site_root(base_url)

    sitemap_urls: list[str] = []
    robots = _safe_fetch(urljoin(root_url, "/robots.txt"), timeout)
    if robots:
        sitemap_urls = _extract_sitemap_lines(robots)[:_MAX_SITEMAP_URLS]
    if not sitemap_urls:
        # No robots.txt, or it named no sitemaps — try the conventional path
        # first, then the P37 guess list (common alternative conventions).
        sitemap_urls = [urljoin(root_url, "/sitemap.xml")]
        sitemap_urls += [urljoin(root_url, g) for g in _SITEMAP_GUESSES]

    entries: list[dict] = []
    seen_locs: set[str] = set()
    visited_sitemaps: set[str] = set()
    budget_hit = False
    # P37: nested queue so a child sitemapindex (one level) and the guess list
    # share a single FIFO; the visited set still guards cycles and the child
    # cap still bounds fan-out.
    queue: list[tuple[str, int]] = [(u, 0) for u in sitemap_urls]

    def _ingest(url_entries: list[dict]) -> None:
        for entry in url_entries:
            loc = entry["loc"]
            if loc in seen_locs:
                continue
            seen_locs.add(loc)
            entries.append(entry)

    def _over_budget() -> bool:
        nonlocal budget_hit
        if time.monotonic() > deadline:
            if not budget_hit:
                _warn(
                    f"sitemap: total budget {_MAX_CRAWL_SECONDS}s exhausted "
                    "— returning partial results"
                )
                budget_hit = True
            return True
        return False

    children_seen = 0
    while queue:
        if _over_budget():
            break
        sm_url, depth = queue.pop(0)
        if sm_url in visited_sitemaps:
            continue
        visited_sitemaps.add(sm_url)

        body = _maybe_gunzip(_safe_fetch(sm_url, timeout), sm_url)
        if not body:
            continue

        # P37: .txt sitemap branch — newline-delimited URLs, no XML.
        if sm_url.lower().endswith(".txt"):
            _ingest(_parse_txt_sitemap(body))
            continue

        # P37 plausibility guard: refuse to XML-parse a body that is clearly
        # not a sitemap (e.g. a WAF block page served with status 200).
        if not _looks_like_sitemap(body):
            _warn(f"sitemap {sm_url}: body is not a plausible sitemap — skipped")
            continue

        root = _parse_xml(body, f"sitemap {sm_url}")
        if root is None:
            continue
        url_entries, child_locs = _parse_sitemap_root(root)
        _ingest(url_entries)
        # One level of recursion only — never queue a child index's children.
        if depth == 0:
            for child_url in child_locs:
                if children_seen >= _MAX_CHILD_SITEMAPS:
                    _warn(
                        f"sitemap {sm_url}: {len(child_locs)} child sitemaps "
                        f"listed, only first {_MAX_CHILD_SITEMAPS} followed"
                    )
                    break
                if child_url in visited_sitemaps:
                    continue
                children_seen += 1
                queue.append((child_url, 1))

    return entries


# --- RSS / Atom discovery ----------------------------------------------------
def _parse_feed_root(root: ET.Element) -> list[dict]:
    """Parse an RSS or Atom feed root into a list of item dicts.

    Returns `[{"title", "link", "date", "summary"}, ...]`. Supports both RSS
    (`<channel><item>`) and Atom (`<feed><entry>`).
    """
    kind = _localname(root.tag)
    items: list[dict] = []

    if kind == "rss":
        # RSS items live under <rss><channel><item>.
        for channel in root:
            if _localname(channel.tag) != "channel":
                continue
            for item in channel:
                if _localname(item.tag) != "item":
                    continue
                rec = {"title": None, "link": None, "date": None, "summary": None}
                for sub in item:
                    name = _localname(sub.tag)
                    text = (sub.text or "").strip() or None
                    if name == "title":
                        rec["title"] = text
                    elif name == "link":
                        rec["link"] = text
                    elif name == "pubDate":
                        rec["date"] = text
                    elif name == "description":
                        rec["summary"] = text
                items.append(rec)
    elif kind == "feed":
        # Atom entries live directly under <feed><entry>.
        for entry in root:
            if _localname(entry.tag) != "entry":
                continue
            rec = {"title": None, "link": None, "date": None, "summary": None}
            updated = None
            published = None
            for sub in entry:
                name = _localname(sub.tag)
                if name == "title":
                    rec["title"] = (sub.text or "").strip() or None
                elif name == "link":
                    # Prefer rel="alternate"; accept the first link otherwise.
                    href = sub.get("href")
                    if href and (sub.get("rel") in (None, "alternate")
                                 or rec["link"] is None):
                        rec["link"] = href
                elif name == "updated":
                    updated = (sub.text or "").strip() or None
                elif name == "published":
                    published = (sub.text or "").strip() or None
                elif name == "summary":
                    rec["summary"] = (sub.text or "").strip() or None
            rec["date"] = updated or published
            items.append(rec)
    else:
        _warn(f"rss: unexpected feed root <{kind}> — expected rss/feed")

    return items


def _parse_json_feed(text: str | None) -> list[dict] | None:
    """P37: parse a JSON Feed body into item dicts (jsonfeed.org spec).  # NOTE-BIAS-OK: spec site

    Returns `[{"title", "link", "date", "summary"}, ...]` when `text` is a
    valid JSON Feed (object with a `version` containing "jsonfeed" and an
    `items` array), else None so the caller can fall through to XML/HTML.
    Never raises.
    """
    if not text:
        return None
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    version = doc.get("version")
    if not (isinstance(version, str) and "jsonfeed" in version.lower()):
        return None
    raw_items = doc.get("items")
    if not isinstance(raw_items, list):
        return None
    items: list[dict] = []
    for it in raw_items:
        if not isinstance(it, dict):
            continue
        items.append({
            "title": it.get("title"),
            "link": it.get("url") or it.get("external_url"),
            "date": it.get("date_published") or it.get("date_modified"),
            "summary": it.get("summary")
                       or it.get("content_text"),
        })
    return items


def _find_feed_links(html: str, base_url: str) -> list[str]:
    """Find `<link rel="alternate">` feed hrefs in an HTML document.

    Returns absolute URLs (resolved against `base_url`). P37: JSON Feed
    (`application/feed+json` / `application/json`) link types are recognized
    alongside RSS/Atom.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        _warn("rss: beautifulsoup4 not installed — cannot scan HTML for feeds")
        return []
    soup = BeautifulSoup(html, "html.parser")
    feeds: list[str] = []
    _FEED_TYPES = (
        "application/rss+xml",
        "application/atom+xml",
        "application/feed+json",
        "application/json",
    )
    for link in soup.find_all("link", rel=True):
        rels = link.get("rel") or []
        if "alternate" not in [r.lower() for r in rels]:
            continue
        ltype = (link.get("type") or "").lower()
        if ltype in _FEED_TYPES:
            href = link.get("href")
            if href:
                feeds.append(urljoin(base_url, href))
    return feeds


def discover_rss(url: str, timeout: int,
                 deadline: float | None = None) -> list[dict]:
    """Discover feed items from `url`.

    `url` may be a feed itself, or an HTML page that links to one via
    `<link rel="alternate" type="application/rss+xml|atom+xml">`.

    `deadline` is an optional monotonic clock value (time.monotonic() + budget)
    beyond which the feed fan-out is aborted and partial results are returned.
    When None (default) the caller's _MAX_CRAWL_SECONDS budget is used.

    Returns `[{"title", "link", "date", "summary"}, ...]`.

    P20 (2026-06-12): applies a wall-clock cap to the HTML→feed fan-out loop
    (W31).  Previously each linked feed was fetched without any budget guard,
    allowing an attacker-controlled page with many feed links to stall the
    crawler indefinitely.  The _over_budget() pattern is reused from
    discover_sitemap.
    """
    # P20: establish a deadline for this discovery call.  If the caller
    # already has a deadline (e.g. run() passes its own budget), use that;
    # otherwise create a fresh per-call budget from _MAX_CRAWL_SECONDS.
    if deadline is None:
        deadline = time.monotonic() + _MAX_CRAWL_SECONDS

    budget_hit = [False]

    def _over_budget() -> bool:
        if time.monotonic() > deadline:
            if not budget_hit[0]:
                _warn(
                    "rss: total budget exhausted — returning partial results"
                )
                budget_hit[0] = True
            return True
        return False

    body = _safe_fetch(url, timeout)
    if not body:
        return []

    # P37: if the body is already a JSON Feed, parse it straight away.
    json_items = _parse_json_feed(body)
    if json_items is not None:
        return json_items

    # If the body is already an XML feed, parse it straight away. Try XML
    # first; only fall through to HTML scanning when the root is not a feed.
    root = _parse_xml(body, f"feed {url}")
    if root is not None and _localname(root.tag) in ("rss", "feed"):
        return _parse_feed_root(root)

    # Otherwise treat it as HTML and look for a linked feed.
    feed_urls = _find_feed_links(body, url)
    if not feed_urls:
        _warn(f"rss: no feed found at {url} (no rel=alternate feed link)")
        return []

    items: list[dict] = []
    seen_links: set[str] = set()

    def _ingest(parsed: list[dict]) -> None:
        # De-dup by link — a page often links both RSS and Atom of one feed.
        for item in parsed:
            link = item.get("link")
            if link and link in seen_links:
                continue
            if link:
                seen_links.add(link)
            items.append(item)

    for feed_url in feed_urls:
        # P20: check budget before each fan-out fetch.
        if _over_budget():
            break
        feed_body = _safe_fetch(feed_url, timeout)
        if not feed_body:
            continue
        # P37: a linked feed may itself be a JSON Feed.
        json_parsed = _parse_json_feed(feed_body)
        if json_parsed is not None:
            _ingest(json_parsed)
            continue
        feed_root = _parse_xml(feed_body, f"feed {feed_url}")
        if feed_root is None:
            continue
        _ingest(_parse_feed_root(feed_root))
    return items


def gnews_search_url(query: str, *, hl: str = "ko", gl: str = "KR",
                     ceid: str = "KR:ko") -> str:
    """P37: build a Google News RSS search URL for `query`.

    Google News exposes a public RSS feed for keyword searches, so news
    discovery has a no-bypass path: hand the returned URL to `discover_rss`
    (mode rss) and the RSS parser handles the rest. Locale defaults to Korean
    to match the primary use; override hl/gl/ceid for other locales.

    The query is percent-encoded; this function never fetches — it only
    composes the URL (the caller routes it through the SSRF-guarded engine).
    """
    return (f"{_GNEWS_SEARCH_BASE}?q={quote_plus(query)}"
            f"&hl={quote_plus(hl)}&gl={quote_plus(gl)}&ceid={quote_plus(ceid)}")


# --- pagination --------------------------------------------------------------
def _find_next_link(html: str, base_url: str) -> str | None:
    """Find the `rel="next"` URL in an HTML document, or None.

    Checks both `<link rel="next">` and `<a rel="next">`; the href is resolved
    against `base_url`.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        _warn("paginate: beautifulsoup4 not installed — cannot find next link")
        return None
    soup = BeautifulSoup(html, "html.parser")
    for tag_name in ("link", "a"):
        for tag in soup.find_all(tag_name, rel=True):
            rels = [r.lower() for r in (tag.get("rel") or [])]
            if "next" in rels:
                href = tag.get("href")
                if href:
                    return urljoin(base_url, href)
    return None


def _safe_fetch_with_result(url: str, timeout: int):
    """Like `_safe_fetch` but returns the raw FetchResult (or None on exception).

    Used where the caller needs to inspect HTTP status (e.g. 429 detection).
    """
    try:
        return engine_fetch(url, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        _warn(f"fetch failed for {url}: {type(e).__name__}: {e}")
        return None


def paginate(
    start_url: str,
    max_pages: int,
    timeout: int,
    robots_crawl_delay_s: float | None = None,
    deadline: float | None = None,
) -> list[str]:
    """Follow `rel="next"` links from `start_url`, up to `max_pages` pages.

    Returns the visited URLs in order, starting with `start_url`. A visited
    set guards against `rel="next"` cycles.

    Politeness: sleeps `_politeness_delay` between pages; backs off 60 s on a
    429 response (one shot — if a second 429 follows the backoff the page is
    skipped and pagination stops).

    P20 (2026-06-12): `deadline` is an optional monotonic wall-clock limit
    (time.monotonic() + budget).  When exceeded, pagination stops and partial
    results are returned with a warning (W31).  When None, a fresh per-call
    budget from _MAX_CRAWL_SECONDS is used so the function is always bounded.
    """
    if deadline is None:
        deadline = time.monotonic() + _MAX_CRAWL_SECONDS

    visited: list[str] = []
    seen: set[str] = set()
    current: str | None = start_url
    backed_off = False

    while current and current not in seen and len(visited) < max_pages:
        # P20: check wall-clock budget before each page fetch.
        if time.monotonic() > deadline:
            _warn(
                f"paginate: total budget exhausted after {len(visited)} "
                "page(s) — returning partial results"
            )
            break

        # Delay before every request except the very first.
        if visited:
            _politeness_delay(robots_crawl_delay_s)

        result = _safe_fetch_with_result(current, timeout)
        if result is None:
            break

        # 429 handling: one-shot 60 s backoff, then retry once.
        if _last_status(result) == 429 and not backed_off:
            _warn(
                f"paginate: 429 rate-limit on {current} — "
                f"backing off {_RATE_LIMIT_BACKOFF_S}s"
            )
            time.sleep(_RATE_LIMIT_BACKOFF_S)
            backed_off = True
            result = _safe_fetch_with_result(current, timeout)
            if result is None:
                break
            if _last_status(result) == 429:
                _warn(f"paginate: 429 persists after backoff — stopping")
                break

        body = result.content or None
        if not body:
            break

        visited.append(current)
        seen.add(current)
        nxt = _find_next_link(body, current)
        if not nxt or nxt in seen:
            break
        current = nxt

    return visited


# --- deep link-following crawl (P34) -----------------------------------------
import hashlib  # noqa: E402 — kept local to the deep-crawl section
import heapq  # noqa: E402
from pathlib import Path  # noqa: E402

from ._atomic import atomic_write_json, exclusive_lock  # noqa: E402

# Default cap on frontier link-following depth. Depth 0 = the start URL only;
# each followed <a href> increments depth. A small default bounds fan-out.
_DEEP_MAX_DEPTH = _int_env("INSANE_CRAWL_MAX_DEPTH", 2)

# Default cap on total pages a deep crawl visits, independent of depth — a hard
# ceiling so even a shallow but very wide site can't blow the budget.
_DEEP_MAX_PAGES = _int_env("INSANE_CRAWL_MAX_PAGES", 100)

# CR-MEDIUM (P34): the frontier heap is bounded so a wide site (10k links/page)
# can't enqueue ~10^6 tuples while only `max_pages` are ever popped. We keep the
# top `_FRONTIER_CAP_FACTOR × max_pages` entries by score; when the heap grows
# past that, the lowest-scored (least relevant) links are dropped. Only the
# most-relevant links ever survive, which is exactly best-first's intent — so
# this caps memory without changing which pages a normal crawl would fetch. The
# factor leaves generous headroom (a page worth visiting may itself yield many
# links worth following) while keeping the ceiling O(max_pages), not O(site).
_FRONTIER_CAP_FACTOR = _int_env("INSANE_CRAWL_FRONTIER_FACTOR", 50)

# Checkpoint directory for --resume (one JSON file per crawl signature).
# Checkpoints are local runtime data, not files shipped inside the skill.
_CHECKPOINT_DIR = Path.home() / ".cache" / "brain" / "page-fetch" / "crawl-checkpoints"


def _extract_links(html: str, base_url: str) -> list[str]:
    """Extract absolute `<a href>` URLs from an HTML document.

    Resolves relative hrefs against `base_url`, drops fragments and non-http(s)
    schemes (mailto:, javascript:, tel:, ...). De-duplicated, order-preserving.
    Returns [] when bs4 is unavailable (documented soft dep, same as paginate).
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        _warn("deep: beautifulsoup4 not installed — cannot extract links")
        return []
    soup = BeautifulSoup(html, "html.parser")
    out: list[str] = []
    seen: set[str] = set()
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        absolute = urljoin(base_url, href)
        # Drop the fragment — same page, different anchor is not a new URL.
        absolute = absolute.split("#", 1)[0]
        if not absolute.lower().startswith(("http://", "https://")):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        out.append(absolute)
    return out


def _checkpoint_key(start_url: str, max_depth: int, filter_sig: str) -> str:
    """Derive a stable checkpoint filename for a deep crawl configuration.

    Keyed on start URL + mode + depth + filter-config hash so resuming only
    ever picks up a crawl with the *same* scope — a different --allow/--deny or
    depth produces a different key and starts fresh (never silently resumes a
    crawl with mismatched scope).
    """
    raw = f"deep|{start_url}|depth={max_depth}|{filter_sig}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _checkpoint_path(key: str) -> Path | None:
    if _CHECKPOINT_DIR is None:
        return None
    return _CHECKPOINT_DIR / f"{key}.json"


def _load_checkpoint(key: str) -> dict | None:
    """Read a deep-crawl checkpoint, or None if absent/corrupt."""
    path = _checkpoint_path(key)
    if path is None or not path.is_file():
        return None
    try:
        import json as _json
        data = _json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _save_checkpoint(key: str, state: dict) -> None:
    """Atomically persist a deep-crawl checkpoint (best-effort, never raises)."""
    path = _checkpoint_path(key)
    if path is None:
        return
    try:
        with exclusive_lock(path):
            atomic_write_json(path, state, indent=2, sort_keys=True)
        # S39-2: checkpoints record crawled URLs (visited + frontier). Lock the
        # dir to 0700 so they aren't world-readable on a shared host, mirroring
        # the P21 cookie-jar precedent (_cookie_jar_path chmods its base 0700).
        # Best-effort: a chmod failure must not break the (already-written)
        # checkpoint.
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
    except OSError:
        pass


def _clear_checkpoint(key: str) -> None:
    """Remove a completed crawl's checkpoint (best-effort)."""
    path = _checkpoint_path(key)
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def discover_deep(
    start_url: str,
    timeout: int,
    *,
    max_depth: int = _DEEP_MAX_DEPTH,
    max_pages: int = _DEEP_MAX_PAGES,
    scorer=None,
    filter_chain=None,
    robots_crawl_delay_s: float | None = None,
    deadline: float | None = None,
    resume: bool = False,
    checkpoint_key: str | None = None,
) -> list[dict]:
    """Best-first link-following crawl from `start_url` (P34).

    Builds the link frontier itself (page-fetch had no BFS crawl before P34):
    fetches a page, extracts its `<a href>` links, filters them through
    `filter_chain`, scores them with `scorer`, and pushes them onto a max-heap
    priority frontier so the most relevant links are fetched first.

    Bounds: `max_depth` (link hops from the start), `max_pages` (hard page
    ceiling), `deadline` (wall-clock), and the per-request politeness delay —
    all reused from the existing crawl politeness/budget infrastructure.

    `resume`/`checkpoint_key`: when resume=True and a checkpoint for the key
    exists, the visited set and frontier are restored so a long crawl that was
    interrupted continues instead of restarting. The checkpoint is updated each
    page and cleared on clean completion.

    Returns `[{"loc": str, "depth": int, "score": float}, ...]` for every page
    successfully fetched, in fetch order.
    """
    if deadline is None:
        deadline = time.monotonic() + _MAX_CRAWL_SECONDS

    from .crawl_scoring import KeywordRelevanceScorer
    if scorer is None:
        scorer = KeywordRelevanceScorer()

    # Frontier is a max-heap on score; heapq is a min-heap so we negate the
    # score. Tie-break on an incrementing counter to keep ordering stable and
    # avoid comparing URL strings when scores collide.
    frontier: list[tuple[float, int, str, int]] = []
    counter = 0
    visited: set[str] = set()
    results: list[dict] = []

    # Resume: restore prior state when a matching checkpoint exists.
    if resume and checkpoint_key:
        saved = _load_checkpoint(checkpoint_key)
        if saved:
            visited = set(saved.get("visited", []))
            results = list(saved.get("results", []))
            for entry in saved.get("frontier", []):
                # entry = [neg_score, counter, url, depth]
                if isinstance(entry, list) and len(entry) == 4:
                    # CR-L (S39 defence-in-depth): re-validate each restored
                    # frontier URL against the live filter before trusting it.
                    # The checkpoint key binds scope so a config mismatch starts
                    # fresh, but an individually-tampered on-disk frontier URL
                    # (checkpoints live in the local cache) would otherwise be
                    # fetched verbatim. _safe_fetch still SSRF-guards the fetch;
                    # this is the scope (allow/deny/same-domain) backstop.
                    restored_url = str(entry[2])
                    if filter_chain is not None and not filter_chain.allowed(restored_url):
                        continue
                    heapq.heappush(frontier, tuple(entry))  # type: ignore[arg-type]
                    counter = max(counter, int(entry[1]) + 1)

    # Seed the frontier with the start URL when not resuming an in-progress one.
    if not frontier and start_url not in visited:
        heapq.heappush(frontier, (-scorer.score(start_url), counter, start_url, 0))
        counter += 1

    def _over_budget() -> bool:
        return time.monotonic() > deadline

    # CR-MEDIUM: bound the frontier heap. `max(1, ...)` so a max_pages=0 edge
    # never yields a zero cap that drops everything.
    frontier_cap = max(1, max_pages * _FRONTIER_CAP_FACTOR)

    def _trim_frontier() -> None:
        # Keep only the `frontier_cap` best-scored entries (smallest neg_score).
        # heapq.nsmallest gives them in O(n log cap); rebuilding the heap from
        # the survivors is O(cap). Cheaper than per-push eviction and only runs
        # when the heap actually overflows.
        nonlocal frontier
        if len(frontier) <= frontier_cap:
            return
        frontier = heapq.nsmallest(frontier_cap, frontier)
        heapq.heapify(frontier)

    # CR-L: throttle checkpoint writes — every page re-serialized the entire
    # growing state under an exclusive lock (O(n²) write amplification). Write
    # at most once per `_CKPT_EVERY_PAGES` pages or `_CKPT_EVERY_SECONDS`,
    # whichever comes first; always force a final write on clean stop below.
    _CKPT_EVERY_PAGES = 10
    _CKPT_EVERY_SECONDS = 5.0
    _last_ckpt = {"pages": 0, "t": time.monotonic()}

    def _maybe_checkpoint(force: bool = False) -> None:
        if not checkpoint_key:
            return
        now = time.monotonic()
        due = (
            force
            or (len(results) - _last_ckpt["pages"]) >= _CKPT_EVERY_PAGES
            or (now - _last_ckpt["t"]) >= _CKPT_EVERY_SECONDS
        )
        if not due:
            return
        _save_checkpoint(checkpoint_key, {
            "start_url": start_url,
            "visited": sorted(visited),
            "results": results,
            "frontier": [list(e) for e in frontier],
        })
        _last_ckpt["pages"] = len(results)
        _last_ckpt["t"] = now

    first = True
    while frontier and len(results) < max_pages:
        if _over_budget():
            _warn(
                f"deep: total budget exhausted after {len(results)} page(s) "
                "— returning partial results"
            )
            break

        neg_score, _, url, depth = heapq.heappop(frontier)
        if url in visited:
            continue
        visited.add(url)

        if not first:
            _politeness_delay(robots_crawl_delay_s)
        first = False

        body = _safe_fetch(url, timeout)
        if not body:
            continue

        results.append({"loc": url, "depth": depth, "score": round(-neg_score, 4)})

        # Expand: extract + filter + score child links, push the unvisited
        # ones, then bound the heap to the top-N best-scored entries so a wide
        # site can't enqueue ~10^6 tuples (CR-MEDIUM). We keep expanding even at
        # the page cap so a --resume frontier survives; the trim is what caps
        # memory, not a fan-out short-circuit (which would empty the frontier
        # and break resume).
        if depth < max_depth:
            for link in _extract_links(body, url):
                if link in visited:
                    continue
                if filter_chain is not None and not filter_chain.allowed(link):
                    continue
                heapq.heappush(
                    frontier, (-scorer.score(link), counter, link, depth + 1)
                )
                counter += 1
            _trim_frontier()  # bound the heap to the top-N best-scored links

        # Persist progress so an interrupted crawl can resume (throttled).
        _maybe_checkpoint()

    # Clean completion = the frontier is genuinely drained (no more links to
    # follow). Hitting max_pages or the wall-clock deadline with links still in
    # the frontier is a *partial* stop — force a final (un-throttled) checkpoint
    # so a later --resume picks up the remaining frontier instead of losing the
    # batch the write-throttle hadn't flushed yet.
    if checkpoint_key and not frontier:
        _clear_checkpoint(checkpoint_key)
    else:
        _maybe_checkpoint(force=True)

    return results


# --- top-level orchestration -------------------------------------------------
def _fetch_robots(url: str, timeout: int) -> tuple[str | None, float | None, list[str]]:
    """Fetch robots.txt for the site hosting `url`.

    Returns ``(robots_body, crawl_delay_s, disallow_paths)``.

    On fetch failure: returns ``(None, None, [])`` and emits a stderr warning
    (never silent — robots fetch failure must be visible per P5 anti-slop rule).
    """
    root_url = _site_root(url)
    robots_url = urljoin(root_url, "/robots.txt")
    try:
        result = engine_fetch(robots_url, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        print(
            f"[plus] crawl warning: robots.txt fetch failed for {robots_url}: "
            f"{type(e).__name__}: {e} — using default delay",
            file=sys.stderr,
        )
        return None, None, []
    if not result.ok or not result.content:
        print(
            f"[plus] crawl warning: robots.txt unavailable at {robots_url} "
            f"(verdict={result.verdict}) — using default delay",
            file=sys.stderr,
        )
        return None, None, []
    body = result.content
    # L2 (security review 2026-06-11): robots.txt is attacker-controlled.
    # The engine caps at 10MB (_MAX_BODY_BYTES) but a 10MB robots.txt still
    # means ~5M splitlines() iterations. Real robots.txt is never legitimately
    # larger than a few KB; 512KB is a generous hard cap before parsing.
    _MAX_ROBOTS_BYTES = 512 * 1024
    if len(body) > _MAX_ROBOTS_BYTES:
        body = body[:_MAX_ROBOTS_BYTES]
    crawl_delay = _extract_crawl_delay(body)
    disallow = _extract_disallow_paths(body) if _RESPECT_ROBOTS else []
    return body, crawl_delay, disallow


def _run_deep(
    url: str,
    timeout: int,
    opts: dict,
    *,
    robots_crawl_delay_s: float | None,
    deadline: float | None,
) -> list[dict]:
    """Build scorer/filter/checkpoint from `opts` and run discover_deep (P34).

    `opts` keys: query (list[str]), max_depth (int), allow/deny (list[str]),
    same_domain (bool, default True), resume (bool, default False).
    """
    from .crawl_scoring import KeywordRelevanceScorer
    from .crawl_filters import FilterChain

    query = opts.get("query") or []
    max_depth = int(opts.get("max_depth", _DEEP_MAX_DEPTH))
    allow = opts.get("allow") or []
    deny = opts.get("deny") or []
    same_domain = bool(opts.get("same_domain", True))
    resume = bool(opts.get("resume", False))

    scorer = KeywordRelevanceScorer(query)
    filter_chain = FilterChain(
        start_url=url, same_domain=same_domain, allow=allow, deny=deny,
    )

    # Checkpoint key binds start URL + depth + the full filter signature so a
    # resume only ever continues a crawl of identical scope.
    filter_sig = (
        f"same={int(same_domain)}|allow={'|'.join(sorted(allow))}"
        f"|deny={'|'.join(sorted(deny))}|q={'|'.join(sorted(query))}"
    )
    key = _checkpoint_key(url, max_depth, filter_sig)

    return discover_deep(
        url, timeout,
        max_depth=max_depth,
        scorer=scorer,
        filter_chain=filter_chain,
        robots_crawl_delay_s=robots_crawl_delay_s,
        deadline=deadline,
        resume=resume,
        checkpoint_key=key,
    )


def run(
    url: str,
    mode: str,
    limit: int,
    max_pages: int,
    timeout: int,
    *,
    deep_opts: dict | None = None,
) -> dict:
    """Run a crawl and return a structured result.

    Parameters
    ----------
    url : str
        Starting URL.
    mode : str
        "sitemap", "rss", "paginate", "llms", "deep", or "auto". `auto` tries
        llms.txt, then sitemap, then rss when each is empty.
    limit : int
        Cap on the number of discovered items returned.
    max_pages : int
        Page cap for the `paginate` mode.
    timeout : int
        Per-fetch timeout in seconds.
    deep_opts : dict | None
        P34 deep-crawl options (only used when mode=="deep"). Keys:
        ``query`` (list[str] for the relevance scorer), ``max_depth`` (int),
        ``allow``/``deny`` (list[str] filter patterns), ``same_domain`` (bool,
        default True), ``resume`` (bool). Ignored for other modes.

    Returns
    -------
    dict
        `{"mode": str, "source_url": str, "count": int, "items": list}`.
        `mode` is the mode actually performed (resolved for `auto`).
    """
    items: list
    actual_mode = mode

    # P5: Fetch robots.txt once up front to extract Crawl-delay and Disallow.
    # sitemap/auto discovery already fetches robots.txt internally for Sitemap:
    # lines; that fetch is separate (engine-level) from this politeness fetch.
    _robots_body, crawl_delay_s, disallow_paths = _fetch_robots(url, timeout)

    # P20 (2026-06-12): establish a single wall-clock deadline shared across
    # all discovery phases so the total crawl time is bounded by
    # _MAX_CRAWL_SECONDS regardless of which mode is used (W31).
    # discover_sitemap manages its own internal deadline; the shared one is
    # passed to discover_rss and paginate which previously had no deadline.
    _run_deadline = time.monotonic() + _MAX_CRAWL_SECONDS

    if mode == "sitemap":
        items = discover_sitemap(url, timeout)
    elif mode == "llms":
        # P37: explicit llms.txt-only discovery.
        items = discover_llms_txt(url, timeout)
    elif mode == "deep":
        # P34: best-first link-following crawl. Scope defaults to the start
        # URL's registrable domain (egress ban-risk safety); scorer ranks by
        # --query keyword overlap; --resume restores a prior checkpoint.
        items = _run_deep(url, timeout, deep_opts or {},
                          robots_crawl_delay_s=crawl_delay_s,
                          deadline=_run_deadline)
    elif mode == "rss":
        items = discover_rss(url, timeout, deadline=_run_deadline)
    elif mode == "paginate":
        items = [
            {"url": u}
            for u in paginate(url, max_pages, timeout,
                              robots_crawl_delay_s=crawl_delay_s,
                              deadline=_run_deadline)
        ]
    elif mode == "auto":
        # P37: try llms.txt first — a single cheap GET that, when present,
        # yields the cleanest doc-URL list and skips WAF bypass entirely.
        items = discover_llms_txt(url, timeout)
        if items:
            actual_mode = "llms"
        else:
            items = discover_sitemap(url, timeout)
            if items:
                actual_mode = "sitemap"
            else:
                items = discover_rss(url, timeout, deadline=_run_deadline)
                # Only claim "rss" if it actually found something; otherwise the
                # envelope would mislabel a total miss as a successful crawl.
                actual_mode = "rss" if items else "auto"
    else:
        raise ValueError(f"unknown crawl mode: {mode!r}")

    if limit is not None and limit >= 0:
        items = items[:limit]

    # P5: Filter Disallow paths when INSANE_RESPECT_ROBOTS=1.
    if _RESPECT_ROBOTS and disallow_paths and items:
        before = len(items)
        items = [
            item for item in items
            if not _is_disallowed(
                _item_url_from_dict(item) or "", disallow_paths
            )
        ]
        removed = before - len(items)
        if removed:
            print(
                f"[plus] crawl: robots Disallow filtered {removed} URL(s) "
                f"(INSANE_RESPECT_ROBOTS=1)",
                file=sys.stderr,
            )

    return {
        "mode": actual_mode,
        "source_url": url,
        "count": len(items),
        "items": items,
        # Expose crawl_delay_s so the --fetch loop in __main__.py can honour it.
        # Not part of the public JSON output contract (filtered before emit).
        "_crawl_delay_s": crawl_delay_s,
    }


def _item_url_from_dict(item: dict) -> str | None:
    """Extract the URL from a crawl item dict (sitemap=loc, rss=link, paginate=url)."""
    return item.get("loc") or item.get("link") or item.get("url")
