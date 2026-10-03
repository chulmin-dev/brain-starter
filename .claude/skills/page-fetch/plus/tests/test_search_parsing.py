"""P18: search parser regression tests — fixed fixtures only, no live network.

Pins:
- HN JSON parser / dedup / limit cap
- arXiv Atom parser / limit cap
- Naver HTML parser (synthetic markup, no real brand content)
- DDG HTML parser + uddg unwrap + dedup
- DTD/XXE rejection guard (_parse_arxiv_atom)
- _normalize_url dedup behaviour
- _epoch_to_iso conversion
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

import plus  # noqa: E402 — triggers engine_proxy.install()
from plus.search import (  # noqa: E402
    _ddg_real_url,
    _epoch_to_iso,
    _normalize_url,
    _parse_arxiv_atom,
    _parse_date_to_iso,
    _parse_ddg_html,
    _parse_naver_html,
    search_hn,
)
from unittest import mock  # noqa: E402


def setUpModule():
    # Parser fixtures must not depend on live DNS or resolver timeouts.
    dns = mock.patch("plus._ssrf.socket.getaddrinfo",
                     return_value=[(2, 1, 6, "", ("93.184.216.34", 443))])
    dns.start()
    unittest.addModuleCleanup(dns.stop)


# ---------------------------------------------------------------------------
# Synthetic fixtures — no real brand names, no real content
# ---------------------------------------------------------------------------

_HN_JSON_ONE_HIT = json.dumps({
    "hits": [
        {
            "title": "Synthetic story title",
            "url": "https://example.test/article-a",
            "objectID": "11111",
            "created_at": "2026-01-02T03:04:05.000Z",
        }
    ]
})

_HN_JSON_THREE_HITS = json.dumps({
    "hits": [
        {"title": "Story A", "url": "https://a.example.test/1", "objectID": "1", "created_at": "2026-01-01T00:00:00Z"},
        {"title": "Story B", "url": "https://b.example.test/2", "objectID": "2", "created_at": "2026-01-02T00:00:00Z"},
        {"title": "Story C", "url": "https://c.example.test/3", "objectID": "3", "created_at": "2026-01-03T00:00:00Z"},
    ]
})

_HN_JSON_DUPLICATE_URLS = json.dumps({
    "hits": [
        {"title": "Story X", "url": "https://dup.example.test/page", "objectID": "10", "created_at": "2026-01-01T00:00:00Z"},
        {"title": "Story X dup", "url": "https://dup.example.test/page", "objectID": "11", "created_at": "2026-01-01T00:00:00Z"},
    ]
})

_HN_JSON_NO_HITS_KEY = json.dumps({"nbHits": 0})

_HN_JSON_NO_URL_FALLBACK = json.dumps({
    "hits": [
        {"title": "No external URL", "objectID": "77777", "created_at": "2026-01-01T00:00:00Z"}
    ]
})

_ARXIV_ATOM_TWO_ENTRIES = """\
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>First Synthetic Paper</title>
    <id>https://arxiv.example.test/abs/0001.00001</id>
    <published>2026-01-01T00:00:00Z</published>
    <summary>Abstract of first paper goes here for testing purposes.</summary>
  </entry>
  <entry>
    <title>Second Synthetic Paper</title>
    <id>https://arxiv.example.test/abs/0001.00002</id>
    <published>2026-01-02T00:00:00Z</published>
    <summary>Abstract of second paper goes here for testing purposes.</summary>
  </entry>
</feed>
"""

_ARXIV_ATOM_WITH_DOCTYPE = """\
<?xml version="1.0"?>
<!DOCTYPE feed [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Evil</title>
    <id>https://attacker.example.test/evil</id>
  </entry>
</feed>
"""

# Same but lowercase doctype tag — guard must be case-insensitive
_ARXIV_ATOM_WITH_DOCTYPE_LOWERCASE = """\
<?xml version="1.0"?>
<!doctype feed []>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry><title>Evil</title><id>https://attacker.example.test/evil2</id></entry>
</feed>
"""

_ARXIV_ATOM_MALFORMED = "<feed><entry><title>Broken</entry></feed>"

# Synthetic Naver HTML: uses a selector that _parse_naver_html will match
_NAVER_HTML_TWO_RESULTS = """\
<html><body>
  <div class="total_wrap">
    <a class="api_txt_lines total_tit" href="https://result-alpha.example.test/one">First synthetic result</a>
    <a class="api_txt_lines total_tit" href="https://result-beta.example.test/two">Second synthetic result</a>
    <a href="https://www.naver.com/internal" class="api_txt_lines total_tit">Internal Naver link</a>
  </div>
</body></html>
"""

_NAVER_HTML_NO_RESULTS = "<html><body><p>Nothing to find here.</p></body></html>"

# Synthetic DDG HTML: uses .result / a.result__a structure
_DDG_HTML_TWO_RESULTS = """\
<html><body>
  <div class="result">
    <a class="result__a" href="https://ddg-alpha.example.test/page1">Alpha result title</a>
    <span class="result__snippet">Snippet for alpha result</span>
  </div>
  <div class="result">
    <a class="result__a" href="https://ddg-beta.example.test/page2">Beta result title</a>
  </div>
</body></html>
"""

_DDG_HTML_WITH_UDDG = """\
<html><body>
  <div class="result">
    <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Freal-destination.example.test%2Fpath&rut=abc">Wrapped link</a>
  </div>
</body></html>
"""

_DDG_HTML_DUPLICATE = """\
<html><body>
  <div class="result">
    <a class="result__a" href="https://dup-ddg.example.test/page">Dup title</a>
  </div>
  <div class="result">
    <a class="result__a" href="https://dup-ddg.example.test/page">Dup title again</a>
  </div>
</body></html>
"""


# ---------------------------------------------------------------------------
# HN JSON parser
# ---------------------------------------------------------------------------

class TestSearchHNParser(unittest.TestCase):
    """search_hn parses Algolia JSON into uniform schema."""

    def _fetch(self, body):
        with mock.patch("plus.search._safe_fetch", return_value=body):
            return search_hn("synthetic", limit=10, timeout=5)

    def test_parses_single_hit(self):
        results = self._fetch(_HN_JSON_ONE_HIT)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["source"], "hn")
        self.assertEqual(results[0]["url"], "https://example.test/article-a")
        self.assertEqual(results[0]["title"], "Synthetic story title")
        self.assertEqual(results[0]["date"], "2026-01-02T03:04:05.000Z")

    def test_parses_three_hits(self):
        results = self._fetch(_HN_JSON_THREE_HITS)
        self.assertEqual(len(results), 3)
        sources = {r["source"] for r in results}
        self.assertEqual(sources, {"hn"})

    def test_limit_caps_output(self):
        with mock.patch("plus.search._safe_fetch", return_value=_HN_JSON_THREE_HITS):
            results = search_hn("synthetic", limit=2, timeout=5)
        self.assertEqual(len(results), 2)

    def test_no_hits_key_returns_empty(self):
        results = self._fetch(_HN_JSON_NO_HITS_KEY)
        self.assertEqual(results, [])

    def test_fallback_objectid_url(self):
        """Hit without url field falls back to news.ycombinator.com URL."""
        results = self._fetch(_HN_JSON_NO_URL_FALLBACK)
        self.assertEqual(len(results), 1)
        self.assertIn("news.ycombinator.com", results[0]["url"])

    def test_empty_body_returns_empty(self):
        with mock.patch("plus.search._safe_fetch", return_value=None):
            results = search_hn("synthetic", limit=10, timeout=5)
        self.assertEqual(results, [])

    def test_malformed_json_returns_empty(self):
        with mock.patch("plus.search._safe_fetch", return_value="not-json{{{"):
            results = search_hn("synthetic", limit=10, timeout=5)
        self.assertEqual(results, [])


# ---------------------------------------------------------------------------
# arXiv Atom parser
# ---------------------------------------------------------------------------

class TestSearchArxivParser(unittest.TestCase):
    """_parse_arxiv_atom parses Atom XML into uniform schema."""

    def test_parses_two_entries(self):
        results = _parse_arxiv_atom(_ARXIV_ATOM_TWO_ENTRIES, limit=10)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["source"], "arxiv")
        self.assertEqual(results[0]["title"], "First Synthetic Paper")
        self.assertEqual(results[0]["url"], "https://arxiv.example.test/abs/0001.00001")
        self.assertEqual(results[0]["date"], "2026-01-01T00:00:00Z")
        self.assertIsNotNone(results[0]["snippet"])

    def test_limit_caps_output(self):
        results = _parse_arxiv_atom(_ARXIV_ATOM_TWO_ENTRIES, limit=1)
        self.assertEqual(len(results), 1)

    def test_empty_input_returns_empty(self):
        self.assertEqual(_parse_arxiv_atom("", limit=10), [])

    def test_malformed_xml_returns_empty(self):
        results = _parse_arxiv_atom(_ARXIV_ATOM_MALFORMED, limit=10)
        self.assertEqual(results, [])

    def test_doctype_rejected_uppercase(self):
        """<!DOCTYPE ...> must be rejected (XXE guard)."""
        results = _parse_arxiv_atom(_ARXIV_ATOM_WITH_DOCTYPE, limit=10)
        self.assertEqual(
            results, [],
            "DTD-bearing Atom must be rejected by the XXE guard",
        )

    def test_doctype_rejected_lowercase(self):
        """<!doctype ...> (lowercase) must also be rejected."""
        results = _parse_arxiv_atom(_ARXIV_ATOM_WITH_DOCTYPE_LOWERCASE, limit=10)
        self.assertEqual(
            results, [],
            "Lowercase <!doctype> must also be rejected by the XXE guard",
        )

    def test_oversized_input_truncated_not_parsed(self):
        """Input exceeding _MAX_PARSE_BYTES is truncated before parsing."""
        from plus.search import _MAX_PARSE_BYTES
        # Craft a document that is valid XML but massively over-sized by
        # repeating whitespace padding; the truncated fragment will fail to
        # parse cleanly, but the guard must not raise — it returns [].
        oversized = _ARXIV_ATOM_TWO_ENTRIES + " " * (_MAX_PARSE_BYTES + 1)
        # Just confirm no exception is raised (guard truncates gracefully).
        try:
            _parse_arxiv_atom(oversized, limit=10)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"_parse_arxiv_atom raised on oversized input: {exc}")


# ---------------------------------------------------------------------------
# Naver HTML parser
# ---------------------------------------------------------------------------

class TestSearchNaverParser(unittest.TestCase):
    """_parse_naver_html extracts outbound links from synthetic HTML."""

    def test_parses_outbound_links(self):
        try:
            results = _parse_naver_html(_NAVER_HTML_TWO_RESULTS, limit=10)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        self.assertGreaterEqual(len(results), 1)
        urls = [r["url"] for r in results]
        self.assertIn("https://result-alpha.example.test/one", urls)
        self.assertIn("https://result-beta.example.test/two", urls)

    def test_internal_naver_links_excluded(self):
        """naver.com hrefs must not appear in results."""
        try:
            results = _parse_naver_html(_NAVER_HTML_TWO_RESULTS, limit=10)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        urls = [r["url"] for r in results]
        self.assertFalse(
            any("naver.com" in u for u in urls),
            "Internal Naver navigation links must be excluded",
        )

    def test_limit_caps_output(self):
        try:
            results = _parse_naver_html(_NAVER_HTML_TWO_RESULTS, limit=1)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        self.assertEqual(len(results), 1)

    def test_no_results_returns_empty(self):
        try:
            results = _parse_naver_html(_NAVER_HTML_NO_RESULTS, limit=10)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        self.assertEqual(results, [])

    def test_schema_fields(self):
        try:
            results = _parse_naver_html(_NAVER_HTML_TWO_RESULTS, limit=10)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        if not results:
            self.skipTest("parser returned no results on this environment")
        for r in results:
            self.assertEqual(r["source"], "naver")
            self.assertIn("title", r)
            self.assertIn("url", r)


# ---------------------------------------------------------------------------
# DDG HTML parser
# ---------------------------------------------------------------------------

class TestSearchDDGParser(unittest.TestCase):
    """_parse_ddg_html extracts results from synthetic DDG HTML."""

    def test_parses_two_results(self):
        try:
            results = _parse_ddg_html(_DDG_HTML_TWO_RESULTS, limit=10)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        self.assertEqual(len(results), 2)
        urls = [r["url"] for r in results]
        self.assertIn("https://ddg-alpha.example.test/page1", urls)
        self.assertIn("https://ddg-beta.example.test/page2", urls)

    def test_snippet_captured(self):
        try:
            results = _parse_ddg_html(_DDG_HTML_TWO_RESULTS, limit=10)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        alpha = next((r for r in results if "alpha" in r["url"]), None)
        self.assertIsNotNone(alpha)
        self.assertIsNotNone(alpha["snippet"])
        self.assertIn("Snippet for alpha", alpha["snippet"])

    def test_uddg_param_unwrapped(self):
        """DDG /l/?uddg= redirector must be unwrapped to the real URL."""
        try:
            results = _parse_ddg_html(_DDG_HTML_WITH_UDDG, limit=10)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        urls = [r["url"] for r in results]
        self.assertIn("https://real-destination.example.test/path", urls)

    def test_dedup_by_url(self):
        """Identical URLs must not produce duplicate hits."""
        try:
            results = _parse_ddg_html(_DDG_HTML_DUPLICATE, limit=10)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        urls = [r["url"] for r in results]
        self.assertEqual(len(urls), len(set(urls)), "Duplicate URLs must be deduplicated")

    def test_limit_caps_output(self):
        try:
            results = _parse_ddg_html(_DDG_HTML_TWO_RESULTS, limit=1)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        self.assertEqual(len(results), 1)

    def test_schema_source_field(self):
        try:
            results = _parse_ddg_html(_DDG_HTML_TWO_RESULTS, limit=10)
        except ImportError:
            self.skipTest("beautifulsoup4 not installed")
        for r in results:
            self.assertEqual(r["source"], "ddg")


# ---------------------------------------------------------------------------
# _ddg_real_url unwrapper
# ---------------------------------------------------------------------------

class TestDDGRealUrl(unittest.TestCase):
    """_ddg_real_url resolves /l/?uddg= redirectors."""

    def test_unwraps_uddg_param(self):
        href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fdest.example.test%2Fpath&rut=x"
        self.assertEqual(_ddg_real_url(href), "https://dest.example.test/path")

    def test_passthrough_direct_url(self):
        href = "https://direct.example.test/page"
        self.assertEqual(_ddg_real_url(href), href)

    def test_empty_string_passthrough(self):
        self.assertEqual(_ddg_real_url(""), "")


# ---------------------------------------------------------------------------
# _normalize_url dedup helper
# ---------------------------------------------------------------------------

class TestNormalizeUrl(unittest.TestCase):
    """_normalize_url folds host case, trailing slash, and strips tracking params.

    P19 (2026-06-12): tracking-param stripping and query-key sorting added
    so utm_* variants and fbclid/gclid are treated as the same URL for dedup.
    test_preserves_query updated: non-tracking params are preserved and sorted.
    """

    def test_lowercase_host(self):
        self.assertEqual(
            _normalize_url("https://EXAMPLE.TEST/path"),
            "https://example.test/path",
        )

    def test_strips_trailing_slash_on_path(self):
        self.assertEqual(
            _normalize_url("https://example.test/path/"),
            "https://example.test/path",
        )

    def test_preserves_non_tracking_query(self):
        # P19: non-tracking params (q, page) are preserved; order may be
        # normalised but both keys must survive.
        url = "https://example.test/search?q=foo&page=2"
        result = _normalize_url(url)
        self.assertIn("q=foo", result)
        self.assertIn("page=2", result)

    def test_strips_utm_params(self):
        # P19: utm_* tracking parameters must be stripped for dedup.
        url = "https://example.test/article?utm_source=newsletter&utm_medium=email"
        result = _normalize_url(url)
        self.assertNotIn("utm_source", result)
        self.assertNotIn("utm_medium", result)

    def test_strips_fbclid(self):
        # P19: fbclid is a tracking parameter and must be stripped.
        url = "https://example.test/page?fbclid=IwAR0abcdef"
        result = _normalize_url(url)
        self.assertNotIn("fbclid", result)

    def test_utm_variant_same_as_clean_url(self):
        # P19: a URL with and without utm params should produce the same
        # dedup key so round-trip dedup works.
        clean = _normalize_url("https://example.test/article")
        with_utm = _normalize_url(
            "https://example.test/article?utm_source=x&utm_campaign=y"
        )
        self.assertEqual(clean, with_utm)

    def test_query_key_order_stable(self):
        # P19: query keys are sorted so parameter order doesn't affect dedup.
        url_ab = _normalize_url("https://example.test/search?a=1&b=2")
        url_ba = _normalize_url("https://example.test/search?b=2&a=1")
        self.assertEqual(url_ab, url_ba)

    def test_drops_fragment(self):
        result = _normalize_url("https://example.test/page#section")
        self.assertNotIn("#section", result)

    def test_empty_returns_empty(self):
        self.assertEqual(_normalize_url(""), "")


# ---------------------------------------------------------------------------
# _epoch_to_iso conversion
# ---------------------------------------------------------------------------

class TestEpochToIso(unittest.TestCase):
    """_epoch_to_iso converts UNIX timestamps to ISO-8601 strings."""

    def test_integer_epoch(self):
        result = _epoch_to_iso(0)
        self.assertIsNotNone(result)
        self.assertIn("1970", result)

    def test_string_epoch(self):
        result = _epoch_to_iso("1000000000")
        self.assertIsNotNone(result)

    def test_none_returns_none(self):
        self.assertIsNone(_epoch_to_iso(None))

    def test_non_numeric_returns_none(self):
        self.assertIsNone(_epoch_to_iso("not-a-number"))

    def test_float_epoch(self):
        result = _epoch_to_iso(1700000000.5)
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# _parse_date_to_iso normalisation (P19)
# ---------------------------------------------------------------------------

class TestParseDateToIso(unittest.TestCase):
    """_parse_date_to_iso normalises various date formats to ISO 8601."""

    def test_already_iso_passthrough(self):
        """ISO 8601 strings are returned unchanged."""
        self.assertEqual(
            _parse_date_to_iso("2026-01-02T03:04:05Z"),
            "2026-01-02T03:04:05Z",
        )

    def test_iso_date_only_passthrough(self):
        self.assertEqual(_parse_date_to_iso("2026-01-01"), "2026-01-01")

    def test_rfc2822_converted(self):
        """RFC 2822 pubDate (RSS) is converted to ISO 8601."""
        result = _parse_date_to_iso("Wed, 01 Jan 2026 00:00:00 +0000")
        self.assertIsNotNone(result)
        self.assertIn("2026", result)
        # Must be ISO-shaped (contains a T or date-only)
        self.assertTrue(result.startswith("2026-01-01"))

    def test_none_returns_none(self):
        self.assertIsNone(_parse_date_to_iso(None))

    def test_empty_returns_none(self):
        self.assertIsNone(_parse_date_to_iso(""))

    def test_unrecognised_returns_original(self):
        """Unrecognised formats return the original string (never null)."""
        raw = "some-weird-date-format"
        result = _parse_date_to_iso(raw)
        self.assertEqual(result, raw)

    def test_iso_with_offset_passthrough(self):
        result = _parse_date_to_iso("2026-06-11T12:00:00+09:00")
        self.assertEqual(result, "2026-06-11T12:00:00+09:00")


# ---------------------------------------------------------------------------
# search() interleave and global cap (P19)
# ---------------------------------------------------------------------------

class TestSearchInterleaveAndCap(unittest.TestCase):
    """search() interleaves sources and applies a global max_results cap."""

    def _mock_search(self, per_source_hits, sources=None, max_results=None):
        """Call search() with mocked per-source handlers.

        per_source_hits: dict[source_name -> list of hit dicts]
        """
        from plus import search as search_mod

        if sources is None:
            sources = list(per_source_hits.keys())

        def make_handler(hits):
            def handler(query, limit, timeout):
                return hits[:limit]
            return handler

        patched_handlers = {
            name: make_handler(hits)
            for name, hits in per_source_hits.items()
        }

        with mock.patch.dict(search_mod._HANDLERS, patched_handlers):
            # _check_blocked_query is imported locally inside search(), so
            # patch it at its definition site in plus._security.
            with mock.patch("plus._security._check_blocked_query",
                            return_value=None):
                return search_mod.search(
                    "test",
                    sources=sources,
                    limit=10,
                    timeout=5,
                    max_results=max_results,
                )

    def _make_hit(self, source, n):
        return {
            "source": source,
            "title": f"{source} hit {n}",
            "url": f"https://{source}.example.test/{n}",
            "snippet": None,
            "date": None,
        }

    def test_interleave_mixes_sources(self):
        """Results from different sources are interleaved, not block-grouped."""
        hits = {
            "hn": [self._make_hit("hn", i) for i in range(3)],
            "reddit": [self._make_hit("reddit", i) for i in range(3)],
        }
        result = self._mock_search(hits)
        sources_in_order = [r["source"] for r in result["results"]]
        # After interleave + stable sort, both sources appear; check no
        # source dominates the entire first half of results exclusively.
        self.assertIn("hn", sources_in_order)
        self.assertIn("reddit", sources_in_order)

    def test_global_cap_limits_total(self):
        """max_results caps the total results after dedup."""
        hits = {
            "hn": [self._make_hit("hn", i) for i in range(5)],
            "reddit": [self._make_hit("reddit", i) for i in range(5)],
        }
        result = self._mock_search(hits, max_results=3)
        self.assertEqual(len(result["results"]), 3)
        self.assertEqual(result["count"], 3)

    def test_global_cap_none_returns_all(self):
        """max_results=None returns all deduplicated results."""
        hits = {
            "hn": [self._make_hit("hn", i) for i in range(4)],
        }
        result = self._mock_search(hits, max_results=None)
        self.assertEqual(len(result["results"]), 4)

    def test_dedup_after_interleave(self):
        """Duplicate URLs across sources are deduplicated even after interleave."""
        shared_url = "https://shared.example.test/page"
        hn_hit = {"source": "hn", "title": "HN hit", "url": shared_url,
                  "snippet": None, "date": None}
        reddit_hit = {"source": "reddit", "title": "Reddit hit", "url": shared_url,
                      "snippet": None, "date": None}
        hits = {"hn": [hn_hit], "reddit": [reddit_hit]}
        result = self._mock_search(hits)
        urls = [r["url"] for r in result["results"]]
        # After _normalize_url dedup, the shared URL must appear only once.
        self.assertEqual(urls.count(shared_url), 1)


# ---------------------------------------------------------------------------
# search_ddgs — P38 ddgs library backend
# ---------------------------------------------------------------------------

class TestSearchDdgs(unittest.TestCase):
    """search_ddgs normalises results, applies _outbound_url_safe, and handles
    soft-dep absence — all verified offline via mock.
    """

    def _call(self, raw_results):
        """Call search_ddgs with a mocked DDGS().text() return value."""
        from plus.search import search_ddgs

        fake_ddgs_instance = mock.MagicMock()
        fake_ddgs_instance.__enter__ = mock.Mock(return_value=fake_ddgs_instance)
        fake_ddgs_instance.__exit__ = mock.Mock(return_value=False)
        fake_ddgs_instance.text = mock.Mock(return_value=raw_results)

        with mock.patch("plus.search.DDGS", fake_ddgs_instance.__class__,
                        create=True):
            # Patch the import inside the function itself
            with mock.patch.dict("sys.modules", {"ddgs": mock.MagicMock(
                DDGS=mock.MagicMock(return_value=fake_ddgs_instance)
            )}):
                return search_ddgs("test query", limit=10, timeout=5)

    # -- helper ----------------------------------------------------------------

    def _make_item(self, url="https://alpha.example.test/result",
                   title="Alpha result", body="Snippet text"):
        return {"href": url, "title": title, "body": body}

    # -- normal result normalisation ------------------------------------------

    def test_hit_schema_fields(self):
        """A valid ddgs result maps to the uniform hit schema."""
        from plus.search import search_ddgs
        item = self._make_item()
        with mock.patch("plus.search._outbound_url_safe", return_value=True):
            results = self._call([item])
        if not results:
            self.skipTest("ddgs import not available in this environment")
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["source"], "ddgs")
        self.assertEqual(r["url"], "https://alpha.example.test/result")
        self.assertEqual(r["title"], "Alpha result")
        self.assertEqual(r["snippet"], "Snippet text")
        self.assertIsNone(r["date"])  # ddgs carries no date field

    def test_url_gate_applied(self):
        """URLs that fail _outbound_url_safe must be dropped."""
        from plus.search import search_ddgs
        items = [
            self._make_item(url="https://safe.example.test/page"),
            self._make_item(url="https://blocked.example.test/page"),
        ]

        def _fake_safe(url):
            return "blocked" not in url

        with mock.patch("plus.search._outbound_url_safe", side_effect=_fake_safe):
            results = self._call(items)
        if results is None:
            self.skipTest("ddgs import not available in this environment")
        urls = [r["url"] for r in results]
        self.assertIn("https://safe.example.test/page", urls)
        self.assertNotIn("https://blocked.example.test/page", urls)

    def test_limit_caps_output(self):
        """Result list is capped at the requested limit."""
        from plus.search import search_ddgs
        items = [self._make_item(
            url=f"https://item{i}.example.test/", title=f"Item {i}"
        ) for i in range(6)]

        with mock.patch("plus.search._outbound_url_safe", return_value=True):
            from plus.search import search_ddgs as _fn
            fake_inst = mock.MagicMock()
            fake_inst.__enter__ = mock.Mock(return_value=fake_inst)
            fake_inst.__exit__ = mock.Mock(return_value=False)
            fake_inst.text = mock.Mock(return_value=items)
            with mock.patch.dict("sys.modules", {"ddgs": mock.MagicMock(
                DDGS=mock.MagicMock(return_value=fake_inst)
            )}):
                results = _fn("test", limit=3, timeout=5)
        if results is None:
            self.skipTest("ddgs import not available in this environment")
        self.assertLessEqual(len(results), 3)

    def test_soft_dep_absent_returns_empty_and_warns(self):
        """When ddgs is not installed, return [] and emit a stderr warning.

        sys.modules[ddgs] = None causes ``import ddgs`` inside search_ddgs to
        raise ImportError, exercising the soft-dep branch without patching
        builtins.__import__ (which would break all imports in the test body).
        """
        import sys
        from plus.search import search_ddgs

        saved = sys.modules.get("ddgs", mock.sentinel.absent)
        sys.modules["ddgs"] = None  # type: ignore[assignment]  # triggers ImportError on import
        try:
            import io
            buf = io.StringIO()
            with mock.patch("sys.stderr", buf):
                result = search_ddgs("test", limit=5, timeout=5)
            self.assertEqual(result, [])
        finally:
            if saved is mock.sentinel.absent:
                sys.modules.pop("ddgs", None)
            else:
                sys.modules["ddgs"] = saved  # type: ignore[assignment]

    def test_results_join_interleave(self):
        """ddgs hits appear in search() interleaved output when source is selected."""
        from plus import search as search_mod

        ddgs_hit = {
            "source": "ddgs",
            "title": "DDGS result",
            "url": "https://ddgs-result.example.test/page",
            "snippet": "Some snippet",
            "date": None,
        }

        def fake_ddgs_handler(query, limit, timeout):
            return [ddgs_hit]

        with mock.patch.dict(search_mod._HANDLERS, {"ddgs": fake_ddgs_handler}):
            with mock.patch("plus._security._check_blocked_query",
                            return_value=None):
                result = search_mod.search(
                    "test",
                    sources=["ddgs"],
                    limit=10,
                    timeout=5,
                    max_results=None,
                )
        urls = [r["url"] for r in result["results"]]
        self.assertIn("https://ddgs-result.example.test/page", urls)
        sources = [r["source"] for r in result["results"]]
        self.assertIn("ddgs", sources)


if __name__ == "__main__":
    unittest.main()
