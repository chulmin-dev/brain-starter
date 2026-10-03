"""Tests for P29 — content_filter (PruningContentFilter + inline BM25).

Covers:
  * prune_html removes nav/footer/ads chrome, keeps dense article content
  * prune_html never returns an empty document for a non-empty page
  * bm25_filter selects query-relevant blocks in document order
  * bm25_filter returns the best block when nothing clears the threshold
  * bm25_filter passes the full text through on an empty query
  * pure-Python: importing content_filter does not import crawl4ai

beautifulsoup4 is the only hard requirement and is gated with skipIf so
offline regression checks stays green on a bare environment.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest


def _has(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


_HAS_BS4 = _has("bs4")


class TestNoCrawl4aiDependency(unittest.TestCase):
    """The whole point of P29 is to avoid the crawl4ai package."""

    def test_importing_content_filter_does_not_import_crawl4ai(self):
        # Drop any cached import, then import fresh and assert crawl4ai absent.
        sys.modules.pop("plus.content_filter", None)
        import plus.content_filter  # noqa: F401
        self.assertNotIn("crawl4ai", sys.modules)


@unittest.skipUnless(_HAS_BS4, "beautifulsoup4 not installed")
class TestPruneHtml(unittest.TestCase):

    def setUp(self):
        from plus.content_filter import prune_html
        self.prune = prune_html

    def test_removes_nav_and_footer_keeps_article(self):
        html = """
        <html><body>
          <nav class="nav"><a href="/a">Home</a> <a href="/b">About</a>
             <a href="/c">Contact</a> <a href="/d">More</a></nav>
          <div class="sidebar"><a href="/ads">Buy now</a>
             <a href="/promo">Sale</a></div>
          <article>
            <p>This is the real article body with a meaningful amount of prose
               text that should comfortably survive the density-based pruning
               filter because it is dense, link-free content.</p>
            <p>A second real paragraph adds even more substantive text so the
               article block scores well above the pruning threshold.</p>
          </article>
          <footer class="footer"><a href="/x">Terms</a>
             <a href="/y">Privacy</a></footer>
        </body></html>
        """
        out = self.prune(html)
        self.assertIn("real article body", out)
        # Navigation / footer link text should be gone.
        self.assertNotIn("Privacy", out)
        self.assertNotIn("Buy now", out)

    def test_non_empty_page_never_returns_empty(self):
        # A page that is almost all chrome must still return *something*.
        html = "<html><body><div class='nav'>menu</div></body></html>"
        out = self.prune(html)
        self.assertTrue(out.strip())

    def test_strips_script_and_style(self):
        html = (
            "<html><body><script>evil()</script>"
            "<style>.x{}</style>"
            "<article><p>Visible content paragraph that is long enough to be "
            "kept by the pruning filter on its own merits here.</p></article>"
            "</body></html>"
        )
        out = self.prune(html)
        self.assertNotIn("evil()", out)
        self.assertNotIn(".x{}", out)
        self.assertIn("Visible content paragraph", out)


@unittest.skipUnless(_HAS_BS4, "beautifulsoup4 not installed")
class TestBm25Filter(unittest.TestCase):

    def setUp(self):
        from plus.content_filter import bm25_filter
        self.bm25 = bm25_filter

    _DOC = """
    <html><body>
      <p>The quick brown fox jumps over the lazy dog in the meadow.</p>
      <p>Photosynthesis converts sunlight into chemical energy in plants.</p>
      <p>The dog barked at the fox near the river bank all afternoon.</p>
      <p>Stock markets fluctuated wildly amid economic uncertainty today.</p>
    </body></html>
    """

    def test_selects_query_relevant_blocks(self):
        out = self.bm25(self._DOC, "fox dog", threshold=0.1)
        self.assertIn("brown fox", out)
        self.assertIn("dog barked", out)
        # Unrelated blocks should be filtered out.
        self.assertNotIn("Photosynthesis", out)
        self.assertNotIn("Stock markets", out)

    def test_preserves_document_order(self):
        out = self.bm25(self._DOC, "fox dog", threshold=0.1)
        self.assertLess(out.index("brown fox"), out.index("dog barked"))

    def test_empty_query_returns_full_text(self):
        out = self.bm25(self._DOC, "")
        self.assertIn("Photosynthesis", out)
        self.assertIn("Stock markets", out)

    def test_no_match_returns_best_block_not_empty(self):
        # A query term present in exactly one block; high threshold forces the
        # "best block" fallback rather than an empty result.
        out = self.bm25(self._DOC, "photosynthesis", threshold=1000.0)
        self.assertIn("Photosynthesis", out)

    def test_query_with_zero_overlap_returns_empty(self):
        # No query term appears anywhere → genuinely nothing relevant.
        out = self.bm25(self._DOC, "zzzznonexistentterm", threshold=0.1)
        self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
