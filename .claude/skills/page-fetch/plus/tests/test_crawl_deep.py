"""P34 deep-crawl + P36 crawl-dedup regression tests — offline, deterministic.

P34 — best-first link-following crawl:
  - KeywordRelevanceScorer: keyword overlap scoring, no-query FIFO degrade
  - FilterChain: same-registrable-domain default, allow/deny, deny-wins
  - _extract_links: <a href> extraction, fragment/scheme filtering
  - discover_deep: frontier best-first order, depth cap, page cap, budget,
    same-domain scope, checkpoint resume
  - _checkpoint_key: scope-bound stability (different scope → different key)

P36 — crawl --fetch near-duplicate skip:
  - _cmd_crawl marks a body whose Simhash similarity to a kept body is >= 0.9
    as duplicate_of_kept and clears its content

All fetches faked via mock.patch on plus.crawl._safe_fetch / engine_fetch — no
network, no real DNS.
"""
from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

import plus  # noqa: E402 — triggers engine_proxy.install()
import plus.crawl as crawl_mod  # noqa: E402
from plus.crawl_filters import FilterChain  # noqa: E402
from plus.crawl_scoring import KeywordRelevanceScorer  # noqa: E402


# ---------------------------------------------------------------------------
# KeywordRelevanceScorer
# ---------------------------------------------------------------------------

class TestKeywordScorer(unittest.TestCase):
    def test_keyword_overlap_scored(self):
        s = KeywordRelevanceScorer(["widget", "gadget"])
        # One of two keywords present as an exact token → 0.5. (No stemming:
        # "widgets" would NOT match "widget" — documented in crawl_scoring.)
        self.assertAlmostEqual(s.score("https://example.org/widget/list"), 0.5)

    def test_all_keywords_present(self):
        s = KeywordRelevanceScorer(["widget", "gadget"])
        self.assertAlmostEqual(s.score("https://example.org/widget/gadget"), 1.0)

    def test_no_keyword_match_zero(self):
        s = KeywordRelevanceScorer(["widget"])
        self.assertEqual(s.score("https://example.org/about"), 0.0)

    def test_no_query_is_constant_fifo(self):
        """No keywords → constant score so the frontier degrades to FIFO."""
        s = KeywordRelevanceScorer()
        self.assertEqual(s.score("https://example.org/a"), s.score("https://example.org/b"))

    def test_weight_scales_score(self):
        s = KeywordRelevanceScorer(["widget"], weight=2.0)
        self.assertAlmostEqual(s.score("https://example.org/widget"), 2.0)


# ---------------------------------------------------------------------------
# FilterChain
# ---------------------------------------------------------------------------

class TestFilterChain(unittest.TestCase):
    def test_same_registrable_domain_default(self):
        fc = FilterChain(start_url="https://docs.example.com/start")
        # Sub-domain of the same registrable domain is allowed.
        self.assertTrue(fc.allowed("https://api.example.com/page"))
        # Different registrable domain is blocked.
        self.assertFalse(fc.allowed("https://example.net/page"))

    def test_same_domain_off_allows_cross_domain(self):
        fc = FilterChain(start_url="https://example.com/start", same_domain=False)
        self.assertTrue(fc.allowed("https://example.net/page"))

    def test_deny_blocks(self):
        fc = FilterChain(start_url="https://example.com/", deny=["logout"])
        self.assertFalse(fc.allowed("https://example.com/user/logout"))
        self.assertTrue(fc.allowed("https://example.com/user/profile"))

    def test_allow_requires_match(self):
        fc = FilterChain(start_url="https://example.com/", allow=["/docs"])
        self.assertTrue(fc.allowed("https://example.com/docs/intro"))
        self.assertFalse(fc.allowed("https://example.com/blog/post"))

    def test_deny_wins_over_allow(self):
        fc = FilterChain(start_url="https://example.com/",
                         allow=["/docs"], deny=["draft"])
        self.assertFalse(fc.allowed("https://example.com/docs/draft-page"))

    def test_invalid_regex_falls_back_to_substring(self):
        """A non-regex pattern (unbalanced bracket) is treated as a literal."""
        buf = io.StringIO()
        with mock.patch("sys.stderr", buf):
            fc = FilterChain(start_url="https://example.com/", deny=["[unclosed"])
        # Must not raise; the literal substring still matches.
        self.assertFalse(fc.allowed("https://example.com/[unclosed/path"))

    def test_empty_url_rejected(self):
        fc = FilterChain(start_url="https://example.com/")
        self.assertFalse(fc.allowed(""))


# ---------------------------------------------------------------------------
# _extract_links
# ---------------------------------------------------------------------------

class TestExtractLinks(unittest.TestCase):
    def test_relative_and_absolute(self):
        html = ('<a href="/rel">r</a>'
                '<a href="https://example.org/abs">a</a>')
        links = crawl_mod._extract_links(html, "https://example.org/start")
        self.assertIn("https://example.org/rel", links)
        self.assertIn("https://example.org/abs", links)

    def test_non_http_schemes_dropped(self):
        html = ('<a href="mailto:recipient">m</a>'
                '<a href="javascript:void(0)">j</a>'
                '<a href="tel:123">t</a>')
        links = crawl_mod._extract_links(html, "https://example.org/")
        self.assertEqual(links, [])

    def test_fragment_stripped(self):
        html = '<a href="/page#section">p</a>'
        links = crawl_mod._extract_links(html, "https://example.org/")
        self.assertEqual(links, ["https://example.org/page"])

    def test_dedup(self):
        html = '<a href="/p">1</a><a href="/p">2</a>'
        links = crawl_mod._extract_links(html, "https://example.org/")
        self.assertEqual(links, ["https://example.org/p"])


# ---------------------------------------------------------------------------
# discover_deep — frontier behaviour
# ---------------------------------------------------------------------------

_DEEP_PAGES = {
    "https://example.org/start": '<a href="/widget">w</a><a href="/about">a</a>',
    "https://example.org/widget": '<a href="/widget/deep">wd</a>',
    "https://example.org/about": "no links here",
    "https://example.org/widget/deep": "leaf",
}


def _deep_fetch(url, timeout):
    return _DEEP_PAGES.get(url)


class TestDiscoverDeep(unittest.TestCase):
    def test_best_first_order(self):
        """A higher-scored link is fetched before a lower-scored sibling."""
        with mock.patch("plus.crawl._safe_fetch", side_effect=_deep_fetch), \
             mock.patch("plus.crawl._politeness_delay"):
            res = crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=2,
                scorer=KeywordRelevanceScorer(["widget"]),
                filter_chain=FilterChain(start_url="https://example.org/start"),
            )
        locs = [r["loc"] for r in res]
        # widget (score 1.0) must come before about (score 0.0).
        self.assertLess(locs.index("https://example.org/widget"),
                        locs.index("https://example.org/about"))

    def test_depth_cap(self):
        """max_depth=1 must not fetch the depth-2 page."""
        with mock.patch("plus.crawl._safe_fetch", side_effect=_deep_fetch), \
             mock.patch("plus.crawl._politeness_delay"):
            res = crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=1,
                filter_chain=FilterChain(start_url="https://example.org/start"),
            )
        locs = [r["loc"] for r in res]
        self.assertNotIn("https://example.org/widget/deep", locs)

    def test_page_cap(self):
        """max_pages bounds the number of fetched pages."""
        with mock.patch("plus.crawl._safe_fetch", side_effect=_deep_fetch), \
             mock.patch("plus.crawl._politeness_delay"):
            res = crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=5, max_pages=2,
                filter_chain=FilterChain(start_url="https://example.org/start"),
            )
        self.assertLessEqual(len(res), 2)

    def test_same_domain_scope_blocks_offsite(self):
        pages = {
            "https://example.org/start": '<a href="https://example.net/x">e</a>'
                                    '<a href="/inside">i</a>',
            "https://example.org/inside": "leaf",
        }

        def fetch(url, timeout):
            return pages.get(url)

        with mock.patch("plus.crawl._safe_fetch", side_effect=fetch), \
             mock.patch("plus.crawl._politeness_delay"):
            res = crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=2,
                filter_chain=FilterChain(start_url="https://example.org/start",
                                         same_domain=True),
            )
        locs = [r["loc"] for r in res]
        self.assertNotIn("https://example.net/x", locs)
        self.assertIn("https://example.org/inside", locs)

    def test_expired_budget_partial(self):
        """An expired deadline returns partial results without raising."""
        import time
        with mock.patch("plus.crawl._safe_fetch", side_effect=_deep_fetch), \
             mock.patch("plus.crawl._politeness_delay"):
            res = crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=2,
                deadline=time.monotonic() - 1.0,
                filter_chain=FilterChain(start_url="https://example.org/start"),
            )
        self.assertIsInstance(res, list)


# ---------------------------------------------------------------------------
# discover_deep — checkpoint resume
# ---------------------------------------------------------------------------

class TestDeepResume(unittest.TestCase):
    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._orig_ckpt = crawl_mod._CHECKPOINT_DIR
        crawl_mod._CHECKPOINT_DIR = self._tmpdir / "ckpt"

    def tearDown(self):
        crawl_mod._CHECKPOINT_DIR = self._orig_ckpt
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_checkpoint_persists_after_page_cap(self):
        key = crawl_mod._checkpoint_key("https://example.org/start", 2, "sig")
        with mock.patch("plus.crawl._safe_fetch", side_effect=_deep_fetch), \
             mock.patch("plus.crawl._politeness_delay"):
            crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=2, max_pages=1,
                filter_chain=FilterChain(start_url="https://example.org/start"),
                checkpoint_key=key,
            )
        ck = crawl_mod._load_checkpoint(key)
        self.assertIsNotNone(ck, "checkpoint must persist when frontier remains")
        self.assertGreater(len(ck["frontier"]), 0)

    def test_resume_does_not_refetch_visited(self):
        key = crawl_mod._checkpoint_key("https://example.org/start", 2, "sig")
        with mock.patch("plus.crawl._safe_fetch", side_effect=_deep_fetch), \
             mock.patch("plus.crawl._politeness_delay"):
            crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=2, max_pages=1,
                filter_chain=FilterChain(start_url="https://example.org/start"),
                checkpoint_key=key,
            )

        calls: list[str] = []

        def counting_fetch(url, timeout):
            calls.append(url)
            return _deep_fetch(url, timeout)

        with mock.patch("plus.crawl._safe_fetch", side_effect=counting_fetch), \
             mock.patch("plus.crawl._politeness_delay"):
            crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=2, max_pages=10,
                filter_chain=FilterChain(start_url="https://example.org/start"),
                resume=True, checkpoint_key=key,
            )
        self.assertNotIn("https://example.org/start", calls,
                         "resume must not re-fetch an already-visited page")

    def test_checkpoint_cleared_after_full_drain(self):
        key = crawl_mod._checkpoint_key("https://example.org/start", 2, "sig")
        with mock.patch("plus.crawl._safe_fetch", side_effect=_deep_fetch), \
             mock.patch("plus.crawl._politeness_delay"):
            crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=2, max_pages=100,
                filter_chain=FilterChain(start_url="https://example.org/start"),
                checkpoint_key=key,
            )
        self.assertIsNone(crawl_mod._load_checkpoint(key),
                          "checkpoint must be cleared on clean completion")

    def test_different_scope_different_key(self):
        """A different filter signature/depth produces a different key."""
        k1 = crawl_mod._checkpoint_key("https://example.org/", 2, "sig-a")
        k2 = crawl_mod._checkpoint_key("https://example.org/", 2, "sig-b")
        k3 = crawl_mod._checkpoint_key("https://example.org/", 3, "sig-a")
        self.assertNotEqual(k1, k2)
        self.assertNotEqual(k1, k3)

    def test_resume_refilters_out_of_scope_frontier(self):
        """A tampered (out-of-scope) frontier URL is dropped on resume.

        CR-L/S39: checkpoints live on disk; an edited frontier entry that is
        off the start registrable domain must be re-rejected by the live
        filter on resume, never fetched.
        """
        key = crawl_mod._checkpoint_key("https://example.org/start", 2, "sig")
        # Hand-write a checkpoint whose frontier contains an off-domain URL.
        crawl_mod._save_checkpoint(key, {
            "start_url": "https://example.org/start",
            "visited": ["https://example.org/start"],
            "results": [{"loc": "https://example.org/start", "depth": 0, "score": 0.0}],
            "frontier": [
                [-1.0, 1, "https://example.net/injected", 1],
                [-0.5, 2, "https://example.org/inside", 1],
            ],
        })
        pages = {"https://example.org/inside": "leaf"}
        calls: list[str] = []

        def fetch(url, timeout):
            calls.append(url)
            return pages.get(url)

        with mock.patch("plus.crawl._safe_fetch", side_effect=fetch), \
             mock.patch("plus.crawl._politeness_delay"):
            crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=2, max_pages=10,
                filter_chain=FilterChain(start_url="https://example.org/start",
                                         same_domain=True),
                resume=True, checkpoint_key=key,
            )
        self.assertNotIn("https://example.net/injected", calls,
                         "out-of-scope frontier URL must be dropped on resume")

    def test_frontier_heap_is_bounded(self):
        """A wide site cannot blow the frontier past the top-N cap."""
        # One page links to 500 distinct children; with max_pages=2 the cap is
        # 2 * _FRONTIER_CAP_FACTOR. Drive a single expand and assert the heap
        # never exceeds it.
        links = "".join(f'<a href="/p{i}">p{i}</a>' for i in range(500))
        pages = {"https://example.org/start": links}
        for i in range(500):
            pages[f"https://example.org/p{i}"] = "leaf"

        def fetch(url, timeout):
            return pages.get(url)

        # Run with a tiny cap factor and assert the persisted frontier size is
        # bounded by the top-N cap rather than growing to the full fan-out.
        key = crawl_mod._checkpoint_key("https://example.org/start", 2, "capsig")
        with mock.patch("plus.crawl._safe_fetch", side_effect=fetch), \
             mock.patch("plus.crawl._politeness_delay"), \
             mock.patch.object(crawl_mod, "_FRONTIER_CAP_FACTOR", 5):
            crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=1, max_pages=2,
                filter_chain=FilterChain(start_url="https://example.org/start"),
                checkpoint_key=key,
            )
        ck = crawl_mod._load_checkpoint(key)
        if ck is not None:  # partial stop persists a frontier
            # cap = max(1, max_pages * factor) = max(1, 2*5) = 10
            self.assertLessEqual(len(ck["frontier"]), 10,
                                 "frontier heap must be trimmed to the top-N cap")

    def test_checkpoint_writes_are_throttled(self):
        """_save_checkpoint is called far fewer times than pages fetched."""
        # 12 chained pages, throttle = every 10 pages / 5s. Without throttling
        # the old code wrote once per page (12+). With it: at most a couple.
        pages = {f"https://example.org/p{i}": f'<a href="/p{i+1}">n</a>'
                 for i in range(20)}
        pages["https://example.org/start"] = '<a href="/p0">n</a>'

        def fetch(url, timeout):
            return pages.get(url)

        key = crawl_mod._checkpoint_key("https://example.org/start", 5, "throttlesig")
        with mock.patch("plus.crawl._safe_fetch", side_effect=fetch), \
             mock.patch("plus.crawl._politeness_delay"), \
             mock.patch.object(crawl_mod, "_save_checkpoint",
                               wraps=crawl_mod._save_checkpoint) as spy:
            crawl_mod.discover_deep(
                "https://example.org/start", timeout=5, max_depth=10, max_pages=12,
                filter_chain=FilterChain(start_url="https://example.org/start"),
                checkpoint_key=key,
            )
        # 12 pages fetched; throttled writes (~every 10 pages) + 1 forced final
        # must be well under one-write-per-page.
        self.assertLessEqual(spy.call_count, 4,
                             f"expected throttled writes, got {spy.call_count}")
        self.assertGreaterEqual(spy.call_count, 1,
                                "at least the forced final write must happen")


# ---------------------------------------------------------------------------
# run(mode="deep") integration
# ---------------------------------------------------------------------------

class TestRunDeepMode(unittest.TestCase):
    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._orig_ckpt = crawl_mod._CHECKPOINT_DIR
        crawl_mod._CHECKPOINT_DIR = self._tmpdir / "ckpt"

    def tearDown(self):
        crawl_mod._CHECKPOINT_DIR = self._orig_ckpt
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_run_deep_envelope(self):
        # _fetch_robots and discover_deep both route through _safe_fetch.
        def fetch(url, timeout):
            if "robots" in url:
                return None
            return _deep_fetch(url, timeout)

        with mock.patch("plus.crawl._safe_fetch", side_effect=fetch), \
             mock.patch("plus.crawl._politeness_delay"), \
             mock.patch("plus.crawl._fetch_robots", return_value=(None, None, [])):
            result = crawl_mod.run(
                "https://example.org/start", mode="deep", limit=50, max_pages=5,
                timeout=5, deep_opts={"query": ["widget"], "max_depth": 2},
            )
        self.assertEqual(result["mode"], "deep")
        self.assertGreater(result["count"], 0)
        # Deep items carry loc/depth/score.
        first = result["items"][0]
        self.assertIn("loc", first)
        self.assertIn("depth", first)
        self.assertIn("score", first)


# ---------------------------------------------------------------------------
# P36 — crawl --fetch near-duplicate skip (via _cmd_crawl)
# ---------------------------------------------------------------------------

class TestCrawlFetchDedup(unittest.TestCase):
    """_cmd_crawl marks a near-duplicate fetched body as duplicate_of_kept."""

    def _run_cmd_crawl_with_items(self, items, bodies):
        """Drive _cmd_crawl with a stubbed discovery + per-URL engine fetch.

        `items` = discovery items (each a dict with 'loc'); `bodies` = mapping
        url -> body string returned by the faked engine_fetch.
        """
        import argparse
        from plus import __main__ as m

        args = argparse.Namespace(
            url="https://example.org/start", mode="deep", limit=50, fetch=True,
            fmt="raw", max_pages=5, cache=False, cache_weak=False,
            doh="off", timeout=5, json=True,
            query=None, depth=None, allow=None, deny=None,
            same_domain=True, resume=False,
        )

        fake_run_result = {
            "mode": "deep", "source_url": args.url,
            "count": len(items), "items": [dict(it) for it in items],
            "_crawl_delay_s": None,
        }

        def fake_engine_fetch(target, timeout=25, max_attempts=12):
            fr = mock.MagicMock()
            fr.ok = True
            fr.content = bodies.get(target, "")
            fr.verdict = "strong_ok"
            fr.final_url = target
            fr.trace = []
            return fr

        # extract returns the body unchanged for fmt=raw.
        def fake_extract(content, fmt, url=None, **kw):
            return content

        buf = io.StringIO()
        with mock.patch.object(m, "_configure_streams"), \
             mock.patch("plus.crawl.run", return_value=fake_run_result), \
             mock.patch("plus.doh.setup", return_value="doh=off"), \
             mock.patch("engine.fetch", side_effect=fake_engine_fetch), \
             mock.patch("plus.extract.extract", side_effect=fake_extract), \
             mock.patch("plus.crawl._politeness_delay"), \
             mock.patch("sys.stdout", buf):
            code = m._cmd_crawl(args)
        return code, fake_run_result["items"]

    def test_near_duplicate_marked_and_cleared(self):
        boiler = "Shared site boilerplate header and footer text repeated. " * 30
        unique = "A genuinely unique article about deep-sea exploration today. " * 30
        items = [
            {"loc": "https://example.org/page-1"},
            {"loc": "https://example.org/page-2"},  # near-duplicate of page-1
            {"loc": "https://example.org/page-3"},  # unique
        ]
        bodies = {
            "https://example.org/page-1": boiler,
            "https://example.org/page-2": boiler + " minor tail difference.",
            "https://example.org/page-3": unique,
        }
        code, out_items = self._run_cmd_crawl_with_items(items, bodies)
        self.assertEqual(code, 0)
        by_loc = {it["loc"]: it for it in out_items}
        # page-1 kept (first occurrence), page-2 marked duplicate.
        self.assertTrue(by_loc["https://example.org/page-2"].get("duplicate_of_kept"))
        self.assertIsNone(by_loc["https://example.org/page-2"]["content"])
        # page-1 and page-3 keep their content.
        self.assertIsNotNone(by_loc["https://example.org/page-1"]["content"])
        self.assertIsNotNone(by_loc["https://example.org/page-3"]["content"])
        self.assertNotIn("duplicate_of_kept", {k: v for k, v in
                         by_loc["https://example.org/page-3"].items()
                         if k == "duplicate_of_kept" and v})


if __name__ == "__main__":
    unittest.main()
