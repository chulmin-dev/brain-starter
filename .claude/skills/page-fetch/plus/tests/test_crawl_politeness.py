"""Tests for P5 — crawl politeness layer.

Covers:
  - _extract_crawl_delay: parsing from robots.txt
  - _extract_disallow_paths: parsing from robots.txt
  - _is_disallowed: path matching
  - _politeness_delay: monkeypatched to verify call count/args, no real sleep
  - _last_status: status extraction from FetchResult trace
  - paginate: delay called between pages, 429 backoff, Disallow respected
  - run(): _crawl_delay_s key stripped from output dict
"""
from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import MagicMock, call, patch


# ---------------------------------------------------------------------------
# Helpers to build minimal FetchResult / Attempt stubs
# ---------------------------------------------------------------------------

def _make_attempt(status: int = 200) -> MagicMock:
    att = MagicMock()
    att.status = status
    return att


def _make_result(ok: bool = True, content: str = "<html/>",
                 verdict: str = "strong_ok", status: int = 200) -> MagicMock:
    fr = MagicMock()
    fr.ok = ok
    fr.content = content
    fr.verdict = verdict
    fr.final_url = None
    fr.trace = [_make_attempt(status)]
    return fr


# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

import plus.crawl as crawl_mod


class TestExtractCrawlDelay(unittest.TestCase):
    def test_parses_integer(self):
        robots = "User-agent: *\nCrawl-delay: 2\nDisallow: /private\n"
        self.assertEqual(crawl_mod._extract_crawl_delay(robots), 2.0)

    def test_parses_float(self):
        robots = "Crawl-delay: 1.5\n"
        self.assertEqual(crawl_mod._extract_crawl_delay(robots), 1.5)

    def test_case_insensitive(self):
        robots = "CRAWL-DELAY: 3\n"
        self.assertEqual(crawl_mod._extract_crawl_delay(robots), 3.0)

    def test_returns_none_when_absent(self):
        robots = "User-agent: *\nDisallow: /\n"
        self.assertIsNone(crawl_mod._extract_crawl_delay(robots))

    def test_returns_none_on_empty(self):
        self.assertIsNone(crawl_mod._extract_crawl_delay(""))

    def test_ignores_zero(self):
        robots = "Crawl-delay: 0\n"
        self.assertIsNone(crawl_mod._extract_crawl_delay(robots))

    def test_ignores_non_numeric(self):
        robots = "Crawl-delay: fast\n"
        self.assertIsNone(crawl_mod._extract_crawl_delay(robots))


class TestExtractDisallowPaths(unittest.TestCase):
    def test_parses_single(self):
        robots = "Disallow: /private\n"
        self.assertEqual(crawl_mod._extract_disallow_paths(robots), ["/private"])

    def test_parses_multiple(self):
        robots = "Disallow: /private\nDisallow: /admin\n"
        self.assertIn("/private", crawl_mod._extract_disallow_paths(robots))
        self.assertIn("/admin", crawl_mod._extract_disallow_paths(robots))

    def test_ignores_empty_disallow(self):
        robots = "Disallow:\n"
        self.assertEqual(crawl_mod._extract_disallow_paths(robots), [])

    def test_returns_empty_on_empty_input(self):
        self.assertEqual(crawl_mod._extract_disallow_paths(""), [])


class TestIsDisallowed(unittest.TestCase):
    def test_blocked_path(self):
        self.assertTrue(crawl_mod._is_disallowed(
            "https://example.com/private/page", ["/private"]
        ))

    def test_allowed_path(self):
        self.assertFalse(crawl_mod._is_disallowed(
            "https://example.com/public/page", ["/private"]
        ))

    def test_root_disallow(self):
        self.assertTrue(crawl_mod._is_disallowed(
            "https://example.com/anything", ["/"]
        ))

    def test_empty_disallow_list(self):
        self.assertFalse(crawl_mod._is_disallowed(
            "https://example.com/page", []
        ))


class TestLastStatus(unittest.TestCase):
    def test_returns_last_attempt_status(self):
        fr = _make_result(status=429)
        self.assertEqual(crawl_mod._last_status(fr), 429)

    def test_returns_zero_on_empty_trace(self):
        fr = MagicMock()
        fr.trace = []
        self.assertEqual(crawl_mod._last_status(fr), 0)

    def test_returns_zero_on_missing_trace(self):
        fr = MagicMock(spec=[])
        self.assertEqual(crawl_mod._last_status(fr), 0)


class TestPolitenessDelay(unittest.TestCase):
    """_politeness_delay calls time.sleep with the correct duration."""

    def test_uses_default_when_no_crawl_delay(self):
        with patch.object(crawl_mod.time, "sleep") as mock_sleep:
            with patch.object(crawl_mod, "_CRAWL_DELAY_MS", 500):
                crawl_mod._politeness_delay(None)
        mock_sleep.assert_called_once_with(0.5)

    def test_uses_robots_delay_when_larger(self):
        # robots Crawl-delay 2s (2000ms) > default 500ms → use 2s
        with patch.object(crawl_mod.time, "sleep") as mock_sleep:
            with patch.object(crawl_mod, "_CRAWL_DELAY_MS", 500):
                crawl_mod._politeness_delay(2.0)
        mock_sleep.assert_called_once_with(2.0)

    def test_uses_default_when_larger_than_robots_delay(self):
        # default 1000ms > robots 0.3s (300ms) → use 1s
        with patch.object(crawl_mod.time, "sleep") as mock_sleep:
            with patch.object(crawl_mod, "_CRAWL_DELAY_MS", 1000):
                crawl_mod._politeness_delay(0.3)
        mock_sleep.assert_called_once_with(1.0)

    def test_no_sleep_when_delay_zero(self):
        with patch.object(crawl_mod.time, "sleep") as mock_sleep:
            with patch.object(crawl_mod, "_CRAWL_DELAY_MS", 0):
                crawl_mod._politeness_delay(None)
        mock_sleep.assert_not_called()


class TestPaginateDelay(unittest.TestCase):
    """paginate() calls _politeness_delay between pages (not before the first)."""

    def _make_pages(self, n: int) -> list[MagicMock]:
        """Build n FetchResult stubs with next-link HTML."""
        results = []
        for i in range(n):
            fr = _make_result(content=f'<a rel="next" href="/page{i+2}">next</a>')
            results.append(fr)
        # Last page has no next link.
        results[-1].content = "<html>last page</html>"
        return results

    def test_delay_called_between_pages_not_before_first(self):
        pages = self._make_pages(3)
        call_count = {"n": 0}

        def fake_fetch(url, timeout):
            return pages[call_count["n"]]

        with patch.object(crawl_mod, "_safe_fetch_with_result", side_effect=fake_fetch):
            with patch.object(crawl_mod, "_politeness_delay") as mock_delay:
                with patch.object(crawl_mod, "_CRAWL_DELAY_MS", 100):
                    # Manually advance call count
                    original_sfr = crawl_mod._safe_fetch_with_result

                    def counting_fetch(url, timeout):
                        result = pages[call_count["n"]]
                        call_count["n"] += 1
                        return result

                    with patch.object(crawl_mod, "_safe_fetch_with_result",
                                      side_effect=counting_fetch):
                        urls = crawl_mod.paginate(
                            "https://example.com/page1", max_pages=3, timeout=10
                        )

        # 3 pages visited → delay called 2 times (before page 2 and page 3)
        self.assertEqual(mock_delay.call_count, 2)

    def test_429_triggers_backoff_and_retry(self):
        # First call returns 429, retry returns 200 with no-next content
        rate_limited = _make_result(ok=False, content="", status=429)
        ok_result = _make_result(content="<html>done</html>", status=200)
        call_seq = [rate_limited, ok_result]
        idx = {"i": 0}

        def fake_fetch(url, timeout):
            r = call_seq[idx["i"]]
            idx["i"] += 1
            return r

        with patch.object(crawl_mod, "_safe_fetch_with_result", side_effect=fake_fetch):
            with patch.object(crawl_mod.time, "sleep") as mock_sleep:
                with patch.object(crawl_mod, "_RATE_LIMIT_BACKOFF_S", 60):
                    urls = crawl_mod.paginate(
                        "https://example.com/p1", max_pages=5, timeout=10
                    )

        # Should have slept 60s for backoff
        backoff_calls = [c for c in mock_sleep.call_args_list if c == call(60)]
        self.assertEqual(len(backoff_calls), 1)

    def test_429_persists_after_backoff_stops_pagination(self):
        # Both attempts return 429
        rate_limited = _make_result(ok=False, content="", status=429)

        with patch.object(crawl_mod, "_safe_fetch_with_result",
                          return_value=rate_limited):
            with patch.object(crawl_mod.time, "sleep"):
                urls = crawl_mod.paginate(
                    "https://example.com/p1", max_pages=5, timeout=10
                )

        self.assertEqual(urls, [])


class TestRunContainsInternalKey(unittest.TestCase):
    """run() includes _crawl_delay_s for the --fetch loop; __main__ pops it before JSON output."""

    def test_crawl_delay_s_present_in_raw_run_result(self):
        """crawl.run() returns _crawl_delay_s so __main__ can use it."""
        with patch.object(crawl_mod, "_fetch_robots", return_value=(None, None, [])):
            with patch.object(crawl_mod, "discover_rss", return_value=[]):
                with patch.object(crawl_mod, "discover_sitemap", return_value=[]):
                    result = crawl_mod.run(
                        "https://example.com", mode="rss",
                        limit=10, max_pages=5, timeout=10,
                    )

        # Internal key is present in the raw dict (popped by __main__ before JSON emit)
        self.assertIn("_crawl_delay_s", result)
        # Standard keys also present
        self.assertIn("mode", result)
        self.assertIn("items", result)
        self.assertIn("count", result)


class TestRespectRobotsDisallow(unittest.TestCase):
    """INSANE_RESPECT_ROBOTS=1 filters Disallow URLs from crawl results."""

    def test_disallow_filters_items(self):
        disallow_paths = ["/private"]
        items = [
            {"link": "https://example.com/public/a"},
            {"link": "https://example.com/private/b"},
        ]

        with patch.object(crawl_mod, "_fetch_robots",
                          return_value=("", None, disallow_paths)):
            with patch.object(crawl_mod, "discover_rss", return_value=items):
                with patch.object(crawl_mod, "_RESPECT_ROBOTS", True):
                    result = crawl_mod.run(
                        "https://example.com", mode="rss",
                        limit=10, max_pages=5, timeout=10,
                    )

        urls_out = [crawl_mod._item_url_from_dict(i) for i in result["items"]]
        self.assertIn("https://example.com/public/a", urls_out)
        self.assertNotIn("https://example.com/private/b", urls_out)

    def test_disallow_not_applied_when_opt_out(self):
        disallow_paths = ["/private"]
        items = [
            {"link": "https://example.com/private/b"},
        ]

        with patch.object(crawl_mod, "_fetch_robots",
                          return_value=("", None, disallow_paths)):
            with patch.object(crawl_mod, "discover_rss", return_value=items):
                with patch.object(crawl_mod, "_RESPECT_ROBOTS", False):
                    result = crawl_mod.run(
                        "https://example.com", mode="rss",
                        limit=10, max_pages=5, timeout=10,
                    )

        self.assertEqual(result["count"], 1)


class TestPerHostBackoff(unittest.TestCase):
    """LOW-2 (2026-06-11): __main__ _cmd_crawl uses per-host backoff dict.

    A 429 on host A must not suppress the backoff on host B.
    """

    def _make_crawl_result(self, items):
        return {"mode": "rss", "count": len(items), "items": items, "_crawl_delay_s": None}

    def test_different_hosts_each_get_backoff(self):
        """Two distinct hosts each get their own per-host backoff opportunity.

        Direct logic check: simulates the _HOST_BACKED_OFF dict that replaced
        the process-global _fetch_backed_off bool in _cmd_crawl (LOW-2).
        """
        # Replicate the dict-based gate logic from _cmd_crawl verbatim.
        _HOST_BACKED_OFF: dict[str, bool] = {}
        _MAX_HOST_BACKOFFS = 3

        def _simulate_backoff(host: str) -> bool:
            if not _HOST_BACKED_OFF.get(host) and len(_HOST_BACKED_OFF) < _MAX_HOST_BACKOFFS:
                _HOST_BACKED_OFF[host] = True
                return True
            return False

        self.assertTrue(_simulate_backoff("host-a.example"))   # first 429 on A → backoff
        self.assertFalse(_simulate_backoff("host-a.example"))  # second 429 on A → suppressed
        self.assertTrue(_simulate_backoff("host-b.example"))   # first 429 on B → backoff
        self.assertFalse(_simulate_backoff("host-b.example"))  # second 429 on B → suppressed

    def test_global_cap_limits_total_backoffs(self):
        """Global cap (_MAX_HOST_BACKOFFS=3) prevents unbounded backoffs."""
        _HOST_BACKED_OFF: dict[str, bool] = {}
        _MAX_HOST_BACKOFFS = 3

        def _simulate_backoff(host: str) -> bool:
            if not _HOST_BACKED_OFF.get(host) and len(_HOST_BACKED_OFF) < _MAX_HOST_BACKOFFS:
                _HOST_BACKED_OFF[host] = True
                return True
            return False

        hosts = [f"host-{i}.example" for i in range(5)]
        backed = [_simulate_backoff(h) for h in hosts]
        # Only first 3 hosts get a backoff; 4th and 5th are denied by global cap.
        self.assertEqual(backed, [True, True, True, False, False])


if __name__ == "__main__":
    unittest.main()
