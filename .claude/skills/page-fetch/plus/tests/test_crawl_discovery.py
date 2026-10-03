"""P18: crawl discovery regression tests — fixed fixtures only, no live network.

Pins:
- sitemap XML parser (urlset / sitemapindex / mixed)
- RSS/Atom feed parser
- discover_sitemap wall-clock budget, child-sitemap cap, cycle guard
- _parse_xml DTD/DOCTYPE rejection (XXE guard)
- _parse_sitemap_root output shape
- _parse_feed_root RSS and Atom branches

P20 additions (2026-06-12):
- discover_rss feed fan-out wall-clock cap
- paginate wall-clock cap
- crawl _safe_fetch max_attempts clamp
"""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest import mock

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

import plus  # noqa: E402 — triggers engine_proxy.install()
from plus.crawl import (  # noqa: E402
    _CRAWL_MAX_ATTEMPTS,
    _MAX_CHILD_SITEMAPS,
    _MAX_CRAWL_SECONDS,
    _MAX_PARSE_BYTES,
    _extract_llms_links,
    _looks_like_sitemap,
    _maybe_gunzip,
    _parse_feed_root,
    _parse_json_feed,
    _parse_sitemap_root,
    _parse_txt_sitemap,
    _parse_xml,
    discover_llms_txt,
    discover_rss,
    discover_sitemap,
    gnews_search_url,
    paginate,
)
import xml.etree.ElementTree as ET  # noqa: E402


# ---------------------------------------------------------------------------
# Synthetic XML fixtures
# ---------------------------------------------------------------------------

_SITEMAP_URLSET = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://site.example.test/page-one</loc>
    <lastmod>2026-01-01</lastmod>
  </url>
  <url>
    <loc>https://site.example.test/page-two</loc>
    <lastmod>2026-01-02</lastmod>
  </url>
  <url>
    <loc>https://site.example.test/page-three</loc>
  </url>
</urlset>
"""

_SITEMAP_INDEX = """\
<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://site.example.test/sitemap-a.xml</loc>
  </sitemap>
  <sitemap>
    <loc>https://site.example.test/sitemap-b.xml</loc>
  </sitemap>
</sitemapindex>
"""

_SITEMAP_WITH_DOCTYPE = """\
<?xml version="1.0"?>
<!DOCTYPE urlset [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://evil.example.test/&xxe;</loc></url>
</urlset>
"""

_SITEMAP_WITH_DOCTYPE_NO_NS = """\
<?xml version="1.0"?>
<!DOCTYPE urlset []>
<urlset>
  <url><loc>https://evil.example.test/</loc></url>
</urlset>
"""

_SITEMAP_MALFORMED = "<urlset><url><loc>Broken</url></urlset>"

_RSS_FEED = """\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Synthetic RSS Feed</title>
    <item>
      <title>Item One</title>
      <link>https://rss.example.test/item-one</link>
      <pubDate>Wed, 01 Jan 2026 00:00:00 +0000</pubDate>
      <description>Summary of item one.</description>
    </item>
    <item>
      <title>Item Two</title>
      <link>https://rss.example.test/item-two</link>
    </item>
  </channel>
</rss>
"""

_ATOM_FEED = """\
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Atom Entry One</title>
    <link rel="alternate" href="https://atom.example.test/entry-one"/>
    <published>2026-01-01T00:00:00Z</published>
    <updated>2026-01-02T00:00:00Z</updated>
    <summary>Summary of entry one.</summary>
  </entry>
  <entry>
    <title>Atom Entry Two</title>
    <link href="https://atom.example.test/entry-two"/>
    <updated>2026-01-03T00:00:00Z</updated>
  </entry>
</feed>
"""

_ROBOTS_WITH_SITEMAP = (
    "User-agent: *\n"
    "Sitemap: https://site.example.test/sitemap.xml\n"
)

_ROBOTS_EMPTY = "User-agent: *\nDisallow:\n"


# ---------------------------------------------------------------------------
# _parse_xml security guard
# ---------------------------------------------------------------------------

class TestParseXmlGuard(unittest.TestCase):
    """_parse_xml rejects DOCTYPE declarations and handles oversized input."""

    def test_doctype_uppercase_rejected(self):
        result = _parse_xml(_SITEMAP_WITH_DOCTYPE, "test-sitemap")
        self.assertIsNone(result, "DOCTYPE-bearing XML must be rejected (XXE guard)")

    def test_doctype_no_ns_rejected(self):
        result = _parse_xml(_SITEMAP_WITH_DOCTYPE_NO_NS, "test-sitemap")
        self.assertIsNone(result, "DOCTYPE without namespace must also be rejected")

    def test_malformed_xml_returns_none(self):
        result = _parse_xml(_SITEMAP_MALFORMED, "malformed")
        self.assertIsNone(result)

    def test_none_input_returns_none(self):
        result = _parse_xml(None, "none-input")
        self.assertIsNone(result)

    def test_valid_xml_parsed(self):
        result = _parse_xml(_SITEMAP_URLSET, "urlset")
        self.assertIsNotNone(result)

    def test_oversized_input_does_not_raise(self):
        """Oversized input is truncated before parsing — must not raise."""
        oversized = _SITEMAP_URLSET + " " * (_MAX_PARSE_BYTES + 1)
        try:
            _parse_xml(oversized, "oversized")
        except Exception as exc:  # noqa: BLE001
            self.fail(f"_parse_xml raised on oversized input: {exc}")


# ---------------------------------------------------------------------------
# _parse_sitemap_root — urlset and sitemapindex branches
# ---------------------------------------------------------------------------

class TestParseSitemapRoot(unittest.TestCase):
    """_parse_sitemap_root splits urlset and sitemapindex correctly."""

    def _root(self, xml_text: str) -> ET.Element:
        return ET.fromstring(xml_text)

    def test_urlset_returns_url_entries(self):
        root = ET.fromstring(_SITEMAP_URLSET)
        url_entries, child_locs = _parse_sitemap_root(root)
        self.assertEqual(len(url_entries), 3)
        self.assertEqual(child_locs, [])

    def test_urlset_entry_has_loc_and_lastmod(self):
        root = ET.fromstring(_SITEMAP_URLSET)
        url_entries, _ = _parse_sitemap_root(root)
        self.assertEqual(url_entries[0]["loc"], "https://site.example.test/page-one")
        self.assertEqual(url_entries[0]["lastmod"], "2026-01-01")

    def test_urlset_entry_without_lastmod_is_none(self):
        root = ET.fromstring(_SITEMAP_URLSET)
        url_entries, _ = _parse_sitemap_root(root)
        third = next(e for e in url_entries if e["loc"].endswith("page-three"))
        self.assertIsNone(third["lastmod"])

    def test_sitemapindex_returns_child_locs(self):
        root = ET.fromstring(_SITEMAP_INDEX)
        url_entries, child_locs = _parse_sitemap_root(root)
        self.assertEqual(url_entries, [])
        self.assertEqual(len(child_locs), 2)
        self.assertIn("https://site.example.test/sitemap-a.xml", child_locs)
        self.assertIn("https://site.example.test/sitemap-b.xml", child_locs)


# ---------------------------------------------------------------------------
# _parse_feed_root — RSS and Atom branches
# ---------------------------------------------------------------------------

class TestParseFeedRoot(unittest.TestCase):
    """_parse_feed_root extracts items from RSS and Atom feeds."""

    def test_rss_two_items(self):
        root = ET.fromstring(_RSS_FEED)
        items = _parse_feed_root(root)
        self.assertEqual(len(items), 2)

    def test_rss_item_fields(self):
        root = ET.fromstring(_RSS_FEED)
        items = _parse_feed_root(root)
        item_one = next(i for i in items if i.get("link", "").endswith("item-one"))
        self.assertEqual(item_one["title"], "Item One")
        self.assertEqual(item_one["link"], "https://rss.example.test/item-one")
        self.assertIsNotNone(item_one["date"])
        self.assertIsNotNone(item_one["summary"])

    def test_rss_item_without_optional_fields(self):
        root = ET.fromstring(_RSS_FEED)
        items = _parse_feed_root(root)
        item_two = next(i for i in items if i.get("link", "").endswith("item-two"))
        # date and summary are absent from fixture
        self.assertIsNone(item_two["date"])

    def test_atom_two_entries(self):
        root = ET.fromstring(_ATOM_FEED)
        items = _parse_feed_root(root)
        self.assertEqual(len(items), 2)

    def test_atom_entry_fields(self):
        root = ET.fromstring(_ATOM_FEED)
        items = _parse_feed_root(root)
        entry_one = next(i for i in items if (i.get("link") or "").endswith("entry-one"))
        self.assertEqual(entry_one["title"], "Atom Entry One")
        self.assertEqual(entry_one["link"], "https://atom.example.test/entry-one")
        # updated takes priority over published
        self.assertEqual(entry_one["date"], "2026-01-02T00:00:00Z")
        self.assertIsNotNone(entry_one["summary"])

    def test_atom_entry_link_without_rel(self):
        """<link href="..."> without rel attribute should be accepted."""
        root = ET.fromstring(_ATOM_FEED)
        items = _parse_feed_root(root)
        entry_two = next(i for i in items if (i.get("link") or "").endswith("entry-two"))
        self.assertEqual(entry_two["link"], "https://atom.example.test/entry-two")


# ---------------------------------------------------------------------------
# discover_sitemap — budget caps and cycle guard
# ---------------------------------------------------------------------------

class TestDiscoverSitemapBudget(unittest.TestCase):
    """discover_sitemap respects wall-clock budget, child cap, and cycle guard."""

    def _make_fake_fetch(self, responses: dict):
        """Return a _safe_fetch replacement that serves from `responses` dict.

        Keys are URLs; values are body strings (or None to simulate failure).
        """
        def fake(url: str, timeout: int) -> str | None:
            return responses.get(url)
        return fake

    def test_urlset_returned(self):
        """Basic sitemap discovery returns URL entries from a urlset."""
        responses = {
            "https://site.example.test/robots.txt": _ROBOTS_WITH_SITEMAP,
            "https://site.example.test/sitemap.xml": _SITEMAP_URLSET,
        }
        with mock.patch("plus.crawl._safe_fetch", side_effect=self._make_fake_fetch(responses)):
            entries = discover_sitemap("https://site.example.test/", timeout=5)
        locs = [e["loc"] for e in entries]
        self.assertIn("https://site.example.test/page-one", locs)
        self.assertIn("https://site.example.test/page-two", locs)
        self.assertEqual(len(entries), 3)

    def test_cycle_guard_prevents_revisit(self):
        """A sitemap that lists itself as a child must not be fetched twice."""
        # sitemapindex pointing back at itself
        self_ref_index = """\
<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://site.example.test/sitemap.xml</loc></sitemap>
</sitemapindex>
"""
        fetch_count: dict[str, int] = {}

        def counting_fetch(url: str, timeout: int) -> str | None:
            fetch_count[url] = fetch_count.get(url, 0) + 1
            if "robots" in url:
                return _ROBOTS_WITH_SITEMAP
            if "sitemap.xml" in url:
                return self_ref_index
            return None

        with mock.patch("plus.crawl._safe_fetch", side_effect=counting_fetch):
            discover_sitemap("https://site.example.test/", timeout=5)

        sitemap_fetches = fetch_count.get("https://site.example.test/sitemap.xml", 0)
        self.assertEqual(sitemap_fetches, 1, "Self-referencing sitemap must only be fetched once")

    def test_child_sitemap_cap(self):
        """Child sitemaps beyond _MAX_CHILD_SITEMAPS are not followed."""
        # Build a sitemapindex with _MAX_CHILD_SITEMAPS + 5 children
        n = _MAX_CHILD_SITEMAPS + 5
        children_xml = "\n".join(
            f"  <sitemap><loc>https://site.example.test/child-{i}.xml</loc></sitemap>"
            for i in range(n)
        )
        big_index = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            + children_xml + "\n"
            "</sitemapindex>\n"
        )
        child_urlset = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            "  <url><loc>https://site.example.test/p</loc></url>\n"
            "</urlset>\n"
        )
        fetched_children: list[str] = []

        def counting_fetch(url: str, timeout: int) -> str | None:
            if "robots" in url:
                return _ROBOTS_WITH_SITEMAP
            if url.endswith("sitemap.xml"):
                return big_index
            if "child-" in url:
                fetched_children.append(url)
                return child_urlset
            return None

        with mock.patch("plus.crawl._safe_fetch", side_effect=counting_fetch):
            discover_sitemap("https://site.example.test/", timeout=5)

        self.assertLessEqual(
            len(fetched_children), _MAX_CHILD_SITEMAPS,
            f"Must not follow more than {_MAX_CHILD_SITEMAPS} child sitemaps",
        )

    def test_wall_clock_budget_triggers_partial_return(self):
        """When wall-clock budget is exhausted, partial results are returned without crashing."""
        # Simulate slow fetches by patching time.monotonic to expire immediately
        call_count = [0]

        def slow_fetch(url: str, timeout: int) -> str | None:
            call_count[0] += 1
            if "robots" in url:
                return _ROBOTS_WITH_SITEMAP
            return _SITEMAP_URLSET

        # Use a near-zero budget so first or second fetch exhausts it
        with mock.patch("plus.crawl._MAX_CRAWL_SECONDS", 0):
            with mock.patch("plus.crawl._safe_fetch", side_effect=slow_fetch):
                entries = discover_sitemap("https://site.example.test/", timeout=5)
        # Must not raise; may return empty or partial list
        self.assertIsInstance(entries, list)

    def test_dedup_by_loc(self):
        """Duplicate <loc> values across multiple sitemaps are deduplicated."""
        # Two urlsets with overlapping locs
        urlset_a = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<url><loc>https://site.example.test/shared</loc></url>'
            '<url><loc>https://site.example.test/unique-a</loc></url>'
            "</urlset>"
        )
        urlset_b = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<url><loc>https://site.example.test/shared</loc></url>'
            '<url><loc>https://site.example.test/unique-b</loc></url>'
            "</urlset>"
        )
        index_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<sitemap><loc>https://site.example.test/sitemap-a.xml</loc></sitemap>'
            '<sitemap><loc>https://site.example.test/sitemap-b.xml</loc></sitemap>'
            "</sitemapindex>"
        )

        def dup_fetch(url: str, timeout: int) -> str | None:
            if "robots" in url:
                return _ROBOTS_WITH_SITEMAP
            if url.endswith("sitemap.xml"):
                return index_xml
            if url.endswith("sitemap-a.xml"):
                return urlset_a
            if url.endswith("sitemap-b.xml"):
                return urlset_b
            return None

        with mock.patch("plus.crawl._safe_fetch", side_effect=dup_fetch):
            entries = discover_sitemap("https://site.example.test/", timeout=5)

        locs = [e["loc"] for e in entries]
        shared_count = locs.count("https://site.example.test/shared")
        self.assertEqual(shared_count, 1, "Shared loc must not be duplicated")
        self.assertEqual(len(locs), len(set(locs)), "All locs must be unique")

    def test_no_robots_falls_back_to_sitemap_xml(self):
        """When robots.txt is absent, /sitemap.xml is tried as fallback."""
        fetched: list[str] = []

        def fallback_fetch(url: str, timeout: int) -> str | None:
            fetched.append(url)
            if url.endswith("robots.txt"):
                return None  # simulate 404/failure
            if url.endswith("sitemap.xml"):
                return _SITEMAP_URLSET
            return None

        with mock.patch("plus.crawl._safe_fetch", side_effect=fallback_fetch):
            entries = discover_sitemap("https://site.example.test/", timeout=5)

        self.assertTrue(
            any("sitemap.xml" in u for u in fetched),
            "Fallback /sitemap.xml must be attempted when robots.txt has no Sitemap: line",
        )
        self.assertGreater(len(entries), 0)


# ---------------------------------------------------------------------------
# P20: discover_rss feed fan-out wall-clock cap
# ---------------------------------------------------------------------------

_HTML_WITH_TWO_FEEDS = """\
<html><head>
  <link rel="alternate" type="application/rss+xml" href="/feed-a.xml"/>
  <link rel="alternate" type="application/rss+xml" href="/feed-b.xml"/>
</head><body></body></html>
"""


class TestDiscoverRssBudget(unittest.TestCase):
    """P20 (2026-06-12): discover_rss respects the wall-clock deadline on fan-out.

    Previously discover_rss had no deadline — an HTML page linking many feeds
    could stall the crawler indefinitely (W31). The deadline parameter is now
    reused from discover_sitemap's _over_budget pattern.
    """

    def test_expired_deadline_stops_fan_out(self):
        """When the deadline has already passed, feed fan-out is skipped."""
        fetch_count = {"n": 0}

        def slow_fetch(url: str, timeout: int) -> str | None:
            fetch_count["n"] += 1
            if "feed" not in url:
                # Return the HTML page with feed links
                return _HTML_WITH_TWO_FEEDS
            return _RSS_FEED

        # Deadline already expired
        expired = time.monotonic() - 1.0
        with mock.patch("plus.crawl._safe_fetch", side_effect=slow_fetch):
            items = discover_rss(
                "https://site.example.test/page", timeout=5, deadline=expired
            )

        # The HTML page fetch itself happens (1 fetch) before the budget check
        # in the fan-out loop; no feed fetch should happen after deadline.
        feed_fetches = fetch_count["n"] - 1  # subtract the HTML page fetch
        self.assertEqual(
            feed_fetches, 0,
            "No feed fan-out fetches should happen after an expired deadline",
        )
        self.assertIsInstance(items, list)

    def test_fresh_deadline_allows_fan_out(self):
        """A generous deadline allows normal feed fan-out."""
        def feed_fetch(url: str, timeout: int) -> str | None:
            if "feed" not in url:
                return _HTML_WITH_TWO_FEEDS
            return _RSS_FEED

        # Deadline far in the future
        future = time.monotonic() + 3600.0
        with mock.patch("plus.crawl._safe_fetch", side_effect=feed_fetch):
            items = discover_rss(
                "https://site.example.test/page", timeout=5, deadline=future
            )

        # Should have parsed items from at least one feed
        self.assertIsInstance(items, list)
        self.assertGreater(len(items), 0)

    def test_direct_feed_url_unaffected_by_budget(self):
        """A URL that is already a feed is parsed without entering the fan-out loop."""
        with mock.patch("plus.crawl._safe_fetch", return_value=_RSS_FEED):
            # Even an expired deadline is fine — no fan-out occurs for direct feeds.
            expired = time.monotonic() - 1.0
            items = discover_rss(
                "https://rss.example.test/feed.xml", timeout=5, deadline=expired
            )
        self.assertGreater(len(items), 0)


# ---------------------------------------------------------------------------
# P20: paginate wall-clock cap
# ---------------------------------------------------------------------------

class TestPaginateDeadline(unittest.TestCase):
    """P20 (2026-06-12): paginate() respects the wall-clock deadline (W31).

    Previously paginate had only a max_pages cap. An expired deadline must
    stop pagination immediately and return partial results.
    """

    def _make_result_with_next(self, page_num: int):
        fr = mock.MagicMock()
        fr.ok = True
        fr.content = f'<a rel="next" href="/page{page_num + 1}">next</a>'
        fr.verdict = "strong_ok"
        fr.final_url = None
        att = mock.MagicMock()
        att.status = 200
        fr.trace = [att]
        return fr

    def test_expired_deadline_stops_immediately(self):
        """An already-expired deadline stops pagination before visiting any page."""
        call_count = {"n": 0}

        def fake_fetch(url, timeout):
            call_count["n"] += 1
            return self._make_result_with_next(call_count["n"])

        expired = time.monotonic() - 1.0
        with mock.patch("plus.crawl._safe_fetch_with_result", side_effect=fake_fetch):
            visited = paginate(
                "https://example.test/page1",
                max_pages=10,
                timeout=5,
                deadline=expired,
            )

        self.assertEqual(visited, [], "Expired deadline must produce empty visited list")

    def test_generous_deadline_allows_pagination(self):
        """A generous deadline allows normal pagination up to max_pages."""
        pages = []
        for i in range(1, 4):
            fr = mock.MagicMock()
            fr.ok = True
            fr.content = (
                f'<a rel="next" href="/page{i+1}">next</a>' if i < 3 else "<html/>"
            )
            fr.verdict = "strong_ok"
            fr.final_url = None
            att = mock.MagicMock()
            att.status = 200
            fr.trace = [att]
            pages.append(fr)

        idx = {"i": 0}

        def fake_fetch(url, timeout):
            r = pages[idx["i"]]
            idx["i"] += 1
            return r

        future = time.monotonic() + 3600.0
        with mock.patch("plus.crawl._safe_fetch_with_result", side_effect=fake_fetch):
            with mock.patch("plus.crawl._politeness_delay"):
                visited = paginate(
                    "https://example.test/page1",
                    max_pages=10,
                    timeout=5,
                    deadline=future,
                )

        self.assertEqual(len(visited), 3)


# ---------------------------------------------------------------------------
# P20: _safe_fetch max_attempts clamp
# ---------------------------------------------------------------------------

class TestCrawlSafeFetchAttempts(unittest.TestCase):
    """P20 (2026-06-12): crawl._safe_fetch clamps max_attempts (W31).

    The clamp is _CRAWL_MAX_ATTEMPTS (default 3), matching search.py's
    _SEARCH_MAX_ATTEMPTS pattern so a WAF'd crawl URL can't burn the engine's
    full 12-attempt budget.
    """

    def test_max_attempts_clamped(self):
        """_safe_fetch passes max_attempts=_CRAWL_MAX_ATTEMPTS to engine_fetch."""
        import plus.crawl as crawl_mod

        captured = {}

        def fake_engine_fetch(url, timeout, max_attempts=12):
            captured["max_attempts"] = max_attempts
            fr = mock.MagicMock()
            fr.ok = True
            fr.content = "<html/>"
            fr.verdict = "strong_ok"
            return fr

        with mock.patch("plus.crawl.engine_fetch", side_effect=fake_engine_fetch):
            crawl_mod._safe_fetch("https://example.test/page", timeout=10)

        self.assertEqual(
            captured.get("max_attempts"),
            _CRAWL_MAX_ATTEMPTS,
            f"_safe_fetch must pass max_attempts={_CRAWL_MAX_ATTEMPTS} to engine_fetch",
        )

    def test_crawl_max_attempts_constant(self):
        """_CRAWL_MAX_ATTEMPTS is positive and ≤ engine default of 12."""
        self.assertGreater(_CRAWL_MAX_ATTEMPTS, 0)
        self.assertLessEqual(_CRAWL_MAX_ATTEMPTS, 12)


# ===========================================================================
# P37 (2026-06-12): discovery layer expansion — llms.txt, sitemap GUESSES/TXT/
# gzip/plausibility/nested-queue, JSON Feed, gnews probe. Offline fixtures only.
# ===========================================================================

import json as _json  # noqa: E402

_JSON_FEED = _json.dumps({
    "version": "https://jsonfeed.org/version/1.1",
    "title": "Synthetic JSON Feed",
    "items": [
        {
            "title": "JF One",
            "url": "https://jf.example.test/one",
            "date_published": "2026-01-01T00:00:00Z",
            "content_text": "First item.",
        },
        {
            "title": "JF Two",
            "external_url": "https://jf.example.test/two",
            "date_modified": "2026-01-02T00:00:00Z",
            "summary": "Second item.",
        },
    ],
})

_LLMS_TXT = """\
# Example Docs

> The docs index for example.test.

## Guides
- [Getting Started](https://docs.example.test/start): intro guide
- [API Reference](https://docs.example.test/api)

https://docs.example.test/bare-link
"""

_WAF_BLOCK_HTML = (
    "<!DOCTYPE html><html><head><title>Access Denied</title></head>"
    "<body>You are blocked.</body></html>"
)

_SITEMAP_TXT = (
    "https://txt.example.test/page-a\n"
    "https://txt.example.test/page-b\n"
    "not-a-url\n"
    "\n"
    "https://txt.example.test/page-a\n"  # duplicate
)

_HTML_WITH_JSON_FEED = """\
<html><head>
  <link rel="alternate" type="application/feed+json" href="/feed.json"/>
</head><body></body></html>
"""


class TestLlmsLinkExtraction(unittest.TestCase):
    """_extract_llms_links parses Markdown links and bare URLs."""

    def test_markdown_links_extracted(self):
        pairs = _extract_llms_links(_LLMS_TXT)
        urls = [u for u, _ in pairs]
        self.assertIn("https://docs.example.test/start", urls)
        self.assertIn("https://docs.example.test/api", urls)

    def test_markdown_title_captured(self):
        pairs = dict((u, t) for u, t in _extract_llms_links(_LLMS_TXT))
        self.assertEqual(pairs["https://docs.example.test/start"], "Getting Started")

    def test_bare_url_extracted(self):
        urls = [u for u, _ in _extract_llms_links(_LLMS_TXT)]
        self.assertIn("https://docs.example.test/bare-link", urls)

    def test_non_http_url_skipped(self):
        pairs = _extract_llms_links("[x](ftp://example.test/file)\n")
        self.assertEqual(pairs, [])


class TestDiscoverLlmsTxt(unittest.TestCase):
    """discover_llms_txt probes /llms.txt and rejects HTML block pages."""

    def test_llms_txt_returns_entries(self):
        responses = {
            "https://docs.example.test/llms.txt": _LLMS_TXT,
        }

        def fake(url, timeout):
            return responses.get(url)

        with mock.patch("plus.crawl._safe_fetch", side_effect=fake):
            entries = discover_llms_txt("https://docs.example.test/", timeout=5)
        locs = [e["loc"] for e in entries]
        self.assertIn("https://docs.example.test/start", locs)
        self.assertIn("https://docs.example.test/api", locs)

    def test_entry_shape_has_title(self):
        with mock.patch("plus.crawl._safe_fetch", return_value=_LLMS_TXT):
            entries = discover_llms_txt("https://docs.example.test/", timeout=5)
        start = next(e for e in entries if e["loc"].endswith("/start"))
        self.assertEqual(start["title"], "Getting Started")
        self.assertIsNone(start["lastmod"])

    def test_html_block_page_rejected(self):
        """A 200 HTML/WAF page at /llms.txt must not be parsed as an index."""
        with mock.patch("plus.crawl._safe_fetch", return_value=_WAF_BLOCK_HTML):
            entries = discover_llms_txt("https://docs.example.test/", timeout=5)
        self.assertEqual(entries, [])

    def test_no_llms_txt_returns_empty(self):
        with mock.patch("plus.crawl._safe_fetch", return_value=None):
            entries = discover_llms_txt("https://docs.example.test/", timeout=5)
        self.assertEqual(entries, [])


class TestSitemapPlausibilityGuard(unittest.TestCase):
    """_looks_like_sitemap rejects HTML, accepts urlset/sitemapindex."""

    def test_urlset_is_plausible(self):
        self.assertTrue(_looks_like_sitemap(_SITEMAP_URLSET))

    def test_sitemapindex_is_plausible(self):
        self.assertTrue(_looks_like_sitemap(_SITEMAP_INDEX))

    def test_html_block_page_not_plausible(self):
        self.assertFalse(_looks_like_sitemap(_WAF_BLOCK_HTML))

    def test_empty_not_plausible(self):
        self.assertFalse(_looks_like_sitemap(""))
        self.assertFalse(_looks_like_sitemap(None))


class TestTxtSitemap(unittest.TestCase):
    """_parse_txt_sitemap handles newline-delimited URL lists."""

    def test_parses_urls(self):
        entries = _parse_txt_sitemap(_SITEMAP_TXT)
        locs = [e["loc"] for e in entries]
        self.assertIn("https://txt.example.test/page-a", locs)
        self.assertIn("https://txt.example.test/page-b", locs)

    def test_non_url_lines_skipped(self):
        entries = _parse_txt_sitemap(_SITEMAP_TXT)
        self.assertNotIn("not-a-url", [e["loc"] for e in entries])

    def test_dedup(self):
        entries = _parse_txt_sitemap(_SITEMAP_TXT)
        locs = [e["loc"] for e in entries]
        self.assertEqual(len(locs), len(set(locs)))

    def test_lastmod_is_none(self):
        entries = _parse_txt_sitemap(_SITEMAP_TXT)
        self.assertTrue(all(e["lastmod"] is None for e in entries))


class TestMaybeGunzip(unittest.TestCase):
    """_maybe_gunzip decompresses .gz bodies, passes others through."""

    def test_non_gz_passthrough(self):
        self.assertEqual(
            _maybe_gunzip("<urlset/>", "https://x.test/sitemap.xml"),
            "<urlset/>",
        )

    def test_gz_decompressed(self):
        import gzip
        payload = b"<urlset><url><loc>https://x.test/g</loc></url></urlset>"
        gz_str = gzip.compress(payload).decode("latin-1")
        out = _maybe_gunzip(gz_str, "https://x.test/sitemap.xml.gz")
        self.assertIn("https://x.test/g", out)

    def test_corrupt_gz_returns_original_no_raise(self):
        out = _maybe_gunzip("not actually gzip", "https://x.test/sitemap.xml.gz")
        # Best-effort: returns the original text, never raises.
        self.assertEqual(out, "not actually gzip")

    def test_none_input(self):
        self.assertIsNone(_maybe_gunzip(None, "https://x.test/sitemap.xml.gz"))


class TestSitemapGuessesAndPlausibility(unittest.TestCase):
    """discover_sitemap tries GUESSES and skips implausible bodies."""

    def test_guess_path_used_when_sitemap_xml_missing(self):
        """When /sitemap.xml 404s, a guess path that returns a urlset works."""
        def fake(url, timeout):
            if "robots" in url:
                return None
            if url.endswith("/sitemap_index.xml"):
                return _SITEMAP_URLSET
            return None

        with mock.patch("plus.crawl._safe_fetch", side_effect=fake):
            entries = discover_sitemap("https://site.example.test/", timeout=5)
        self.assertGreater(len(entries), 0)

    def test_html_block_page_at_sitemap_xml_skipped(self):
        """A 200 HTML block page at /sitemap.xml must not produce entries."""
        def fake(url, timeout):
            if "robots" in url:
                return None
            # Every sitemap candidate returns an HTML block page.
            return _WAF_BLOCK_HTML

        with mock.patch("plus.crawl._safe_fetch", side_effect=fake):
            entries = discover_sitemap("https://site.example.test/", timeout=5)
        self.assertEqual(entries, [])

    def test_txt_sitemap_branch(self):
        """A .txt sitemap (from robots Sitemap: line) is parsed as URL list."""
        robots = "Sitemap: https://site.example.test/sitemap.txt\n"

        def fake(url, timeout):
            if "robots" in url:
                return robots
            if url.endswith("sitemap.txt"):
                return _SITEMAP_TXT
            return None

        with mock.patch("plus.crawl._safe_fetch", side_effect=fake):
            entries = discover_sitemap("https://site.example.test/", timeout=5)
        locs = [e["loc"] for e in entries]
        self.assertIn("https://txt.example.test/page-a", locs)


class TestJsonFeed(unittest.TestCase):
    """_parse_json_feed and discover_rss JSON Feed branch."""

    def test_parse_json_feed_items(self):
        items = _parse_json_feed(_JSON_FEED)
        self.assertIsNotNone(items)
        self.assertEqual(len(items), 2)

    def test_json_feed_item_fields(self):
        items = _parse_json_feed(_JSON_FEED)
        one = next(i for i in items if (i["link"] or "").endswith("/one"))
        self.assertEqual(one["title"], "JF One")
        self.assertEqual(one["date"], "2026-01-01T00:00:00Z")
        self.assertEqual(one["summary"], "First item.")

    def test_external_url_fallback(self):
        items = _parse_json_feed(_JSON_FEED)
        two = next(i for i in items if (i["link"] or "").endswith("/two"))
        self.assertEqual(two["link"], "https://jf.example.test/two")

    def test_non_json_feed_returns_none(self):
        self.assertIsNone(_parse_json_feed('{"a": 1}'))
        self.assertIsNone(_parse_json_feed("<rss></rss>"))
        self.assertIsNone(_parse_json_feed(None))

    def test_discover_rss_direct_json_feed(self):
        with mock.patch("plus.crawl._safe_fetch", return_value=_JSON_FEED):
            items = discover_rss("https://jf.example.test/feed.json", timeout=5)
        self.assertEqual(len(items), 2)

    def test_discover_rss_linked_json_feed(self):
        def fake(url, timeout):
            if url.endswith("feed.json"):
                return _JSON_FEED
            return _HTML_WITH_JSON_FEED

        with mock.patch("plus.crawl._safe_fetch", side_effect=fake):
            items = discover_rss("https://jf.example.test/page", timeout=5)
        self.assertEqual(len(items), 2)


class TestGnewsSearchUrl(unittest.TestCase):
    """gnews_search_url builds a percent-encoded Google News RSS URL."""

    def test_basic_url(self):
        url = gnews_search_url("python")
        self.assertTrue(url.startswith("https://news.google.com/rss/search?q=python"))
        self.assertIn("hl=ko", url)
        self.assertIn("gl=KR", url)

    def test_query_percent_encoded(self):
        url = gnews_search_url("hello world")
        self.assertIn("q=hello+world", url)
        self.assertNotIn(" ", url)

    def test_locale_override(self):
        url = gnews_search_url("news", hl="en", gl="US", ceid="US:en")
        self.assertIn("hl=en", url)
        self.assertIn("gl=US", url)


if __name__ == "__main__":
    unittest.main()
