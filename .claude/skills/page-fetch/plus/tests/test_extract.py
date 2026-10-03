"""Tests for P14 — extract pipeline upgrade.

Covers:
  * normalized metadata merge (trafilatura bare_extraction) — soft-gated
  * htmldate publish-date fill — soft-gated
  * baseline rescue ahead of the bs4 get_text fallback — soft-gated
  * --recall / --precision threading into trafilatura.extract
  * lenient JSON-LD parsing (comment strip + strict=False) — bs4-gated
  * extruct soft-dep behavior + explicit extruct_available flag — bs4-gated
  * raw format never imports the extraction stack (lazy-import design)

Soft dependencies (trafilatura, htmldate, extruct, bs4) are gated with
skipIf so offline regression checks stays green on a bare environment.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from unittest.mock import patch

from plus import extract as extract_mod
from plus.extract import extract


def _has(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


_HAS_TRAFILATURA = _has("trafilatura")
_HAS_HTMLDATE = _has("htmldate")
_HAS_EXTRUCT = _has("extruct")
_HAS_BS4 = _has("bs4")


_ARTICLE_HTML = """
<html><head>
  <title>Great Article | Example Site</title>
  <meta name="author" content="Jane Doe">
  <meta property="og:title" content="Great Article">
  <meta name="twitter:card" content="summary">
  <meta name="description" content="A short description of the article.">
</head><body>
  <article>
    <h1>Great Article</h1>
    <p>This is the first paragraph of the body with enough words to be
       reliably extracted by the trafilatura content cascade here.</p>
    <p>A second substantial paragraph follows with more than enough text
       content to clear the minimum-output gate inside trafilatura cleanly.</p>
  </article>
</body></html>
"""


class TestRawNeverImportsStack(unittest.TestCase):
    """raw format must short-circuit before touching trafilatura/bs4."""

    def test_raw_returns_input_unchanged(self):
        self.assertEqual(extract("<html>x</html>", "raw"), "<html>x</html>")

    def test_raw_does_not_call_importers(self):
        with patch.object(extract_mod, "_import_trafilatura") as t, \
             patch.object(extract_mod, "_import_bs4") as b:
            out = extract("<html>x</html>", "raw")
        self.assertEqual(out, "<html>x</html>")
        t.assert_not_called()
        b.assert_not_called()


@unittest.skipUnless(_HAS_BS4, "beautifulsoup4 not installed")
class TestLenientJsonLd(unittest.TestCase):

    def test_trailing_comment_jsonld_rescued(self):
        html = """
        <html><head><script type="application/ld+json">
        // leading comment that the strict parser used to choke on
        {"@type": "Article", "headline": "Hello"}
        </script></head><body><p>x</p></body></html>
        """
        out = json.loads(extract(html, "metadata"))
        jsonld = out["jsonld"]
        self.assertTrue(jsonld, "expected at least one JSON-LD entry")
        # The block must be parsed, not stubbed as a _parse_error.
        self.assertFalse(
            any(isinstance(e, dict) and e.get("_parse_error") for e in jsonld),
            f"comment-prefixed JSON-LD should parse leniently, got {jsonld}",
        )
        self.assertTrue(
            any(isinstance(e, dict) and e.get("headline") == "Hello"
                for e in jsonld)
        )

    def test_truly_broken_jsonld_still_flags_parse_error(self):
        html = """
        <html><head><script type="application/ld+json">
        {this is not json at all <<<}
        </script></head><body><p>x</p></body></html>
        """
        out = json.loads(extract(html, "metadata"))
        self.assertTrue(
            any(isinstance(e, dict) and e.get("_parse_error")
                for e in out["jsonld"])
        )

    def test_twitter_card_preserved(self):
        out = json.loads(extract(_ARTICLE_HTML, "metadata"))
        self.assertEqual(out["twitter"].get("twitter:card"), "summary")
        self.assertEqual(out["ogp"].get("og:title"), "Great Article")

    def test_extruct_available_flag_present(self):
        out = json.loads(extract(_ARTICLE_HTML, "metadata"))
        self.assertIn("extruct_available", out)
        self.assertEqual(out["extruct_available"], _HAS_EXTRUCT)


@unittest.skipUnless(_HAS_TRAFILATURA, "trafilatura not installed")
class TestNormalizedMetadata(unittest.TestCase):

    def test_normalized_author_merged(self):
        out = json.loads(extract(_ARTICLE_HTML, "metadata", url="http://e.example.org/a"))
        self.assertIn("normalized", out)
        # trafilatura should normalize the author from the meta tag.
        self.assertEqual(out["normalized"].get("author"), "Jane Doe")

    def test_raw_ogp_still_present_alongside_normalized(self):
        out = json.loads(extract(_ARTICLE_HTML, "metadata", url="http://e.example.org/a"))
        # raw bs4 path is preserved (complementary, not replaced).
        self.assertEqual(out["ogp"].get("og:title"), "Great Article")
        self.assertIn("normalized", out)


@unittest.skipUnless(_HAS_TRAFILATURA and _HAS_HTMLDATE, "trafilatura/htmldate")
class TestHtmldateFill(unittest.TestCase):

    def test_publish_date_extracted(self):
        html = _ARTICLE_HTML.replace(
            "</head>",
            '<meta property="article:published_time" '
            'content="2024-03-15T10:00:00Z"></head>',
        )
        out = json.loads(extract(html, "metadata", url="http://e.example.org/a"))
        date = out.get("normalized", {}).get("date")
        self.assertTrue(date, "expected a normalized publish date")
        self.assertIn("2024-03-15", date)


@unittest.skipUnless(_HAS_TRAFILATURA, "trafilatura not installed")
class TestRecallPrecisionThreading(unittest.TestCase):

    def test_recall_flag_forwarded_to_trafilatura(self):
        captured = {}

        def fake_extract(html, **kw):
            captured.update(kw)
            return "extracted body"

        import trafilatura as _traf
        with patch.object(_traf, "extract", side_effect=fake_extract):
            out = extract(_ARTICLE_HTML, "markdown", favor_recall=True)
        self.assertEqual(out, "extracted body")
        self.assertTrue(captured.get("favor_recall"))
        self.assertFalse(captured.get("favor_precision"))

    def test_precision_flag_forwarded(self):
        captured = {}

        def fake_extract(html, **kw):
            captured.update(kw)
            return "clean body"

        import trafilatura as _traf
        with patch.object(_traf, "extract", side_effect=fake_extract):
            extract(_ARTICLE_HTML, "text", favor_precision=True)
        self.assertTrue(captured.get("favor_precision"))


@unittest.skipUnless(_HAS_TRAFILATURA and _HAS_BS4, "trafilatura/bs4")
class TestBaselineRescue(unittest.TestCase):

    def test_baseline_runs_before_bs4_when_trafilatura_empty(self):
        # Force trafilatura.extract to yield nothing so the rescue ladder runs.
        import trafilatura as _traf
        html = (
            "<html><body><article>"
            "<p>Rescue paragraph with sufficient words to be picked up by the "
            "baseline structured extraction ladder when extract returns none.</p>"
            "</article></body></html>"
        )
        with patch.object(_traf, "extract", return_value=None):
            with patch.object(_traf, "baseline",
                              wraps=_traf.baseline) as spy_baseline:
                out = extract(html, "text")
        spy_baseline.assert_called()  # baseline tried ahead of bs4
        self.assertIn("Rescue paragraph", out)

    def test_bs4_fallback_when_baseline_also_empty(self):
        import trafilatura as _traf
        html = "<html><body><div>only chrome text</div></body></html>"
        with patch.object(_traf, "extract", return_value=None):
            with patch.object(_traf, "baseline", return_value=(None, "", 0)):
                out = extract(html, "text")
        self.assertIn("only chrome text", out)


@unittest.skipUnless(_HAS_EXTRUCT and _HAS_BS4, "extruct/bs4")
class TestExtructMicrodata(unittest.TestCase):

    def test_microdata_price_extracted(self):
        html = """
        <html><body>
        <div itemscope itemtype="https://schema.org/Product">
          <span itemprop="name">Widget</span>
          <div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
            <meta itemprop="price" content="19900">
          </div>
        </div>
        </body></html>
        """
        out = json.loads(extract(html, "metadata", url="http://shop.example/p"))
        self.assertTrue(out["extruct_available"])
        self.assertIn("microdata", out)
        blob = json.dumps(out["microdata"])
        self.assertIn("19900", blob)


if __name__ == "__main__":
    unittest.main()
