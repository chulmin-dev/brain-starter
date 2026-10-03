"""P3 (2026-06-11): search security regression tests.

Covers:
- BlockedQueryError does NOT subclass ValueError (contract test, W38-1).
- BlockedQueryError message does NOT echo the matched term (output-0 policy, W11).
- arxiv URL uses https (W32).
- search_hn applies _outbound_url_safe to hit.get("url") (W33).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

import plus  # noqa: E402 — triggers install()
from plus._security import BlockedQueryError  # noqa: E402
from plus.search import search_arxiv, search_hn  # noqa: E402


class TestBlockedQueryErrorContract(unittest.TestCase):
    """BlockedQueryError must NOT be a ValueError subclass (D7 / W38-1)."""

    def test_not_subclass_of_value_error(self):
        self.assertFalse(
            issubclass(BlockedQueryError, ValueError),
            "BlockedQueryError must not subclass ValueError — "
            "a generic except ValueError: must not silently swallow it.",
        )

    def test_is_exception_subclass(self):
        self.assertTrue(issubclass(BlockedQueryError, Exception))


class TestBlockedTermMasking(unittest.TestCase):
    """BlockedQueryError message must not echo the matched term (W11)."""

    def test_message_does_not_echo_term(self):
        """The error message must not contain the actual blocked term."""
        from plus.search import search
        fake_term = "xyzzy_test_blocked_term_do_not_echo"

        with mock.patch(
            "plus._security._read_blocked_terms",
            return_value=(fake_term,),
        ):
            with self.assertRaises(BlockedQueryError) as cm:
                search(
                    query=f"something about {fake_term}",
                    sources=[],
                    limit=5,
                    timeout=10,
                )
        msg = str(cm.exception)
        self.assertNotIn(
            fake_term, msg,
            f"Blocked term {fake_term!r} must not appear in the error message.",
        )



class TestArxivHttps(unittest.TestCase):
    """search_arxiv must use https, not http (W32)."""

    def test_arxiv_url_uses_https(self):
        fetched_urls: list[str] = []

        def _fake_safe_fetch(url: str, timeout: int):
            fetched_urls.append(url)
            return None  # empty body → returns []

        with mock.patch("plus.search._safe_fetch", side_effect=_fake_safe_fetch):
            search_arxiv("test query", limit=5, timeout=10)

        self.assertTrue(fetched_urls, "Expected at least one fetch call")
        for url in fetched_urls:
            self.assertTrue(
                url.startswith("https://"),
                f"arxiv URL must use https, got: {url!r}",
            )


class TestHNOutboundGuard(unittest.TestCase):
    """search_hn must apply _outbound_url_safe to hit.get('url') (W33)."""

    def setUp(self):
        dns = mock.patch("plus._ssrf.socket.getaddrinfo",
                         return_value=[(2, 1, 6, "", ("93.184.216.34", 443))])
        dns.start()
        self.addCleanup(dns.stop)

    def _make_hn_body(self, url: str) -> str:
        """Minimal Algolia response JSON with one hit."""
        import json
        return json.dumps({
            "hits": [
                {
                    "title": "Test Story",
                    "url": url,
                    "objectID": "12345",
                    "created_at": "2026-01-01T00:00:00Z",
                }
            ]
        })

    def test_internal_url_in_hit_is_dropped(self):
        """A hit pointing at a private IP must be silently dropped."""
        body = self._make_hn_body("http://192.168.1.1/internal")
        with mock.patch("plus.search._safe_fetch", return_value=body):
            results = search_hn("test", limit=10, timeout=10)
        urls = [r["url"] for r in results]
        self.assertNotIn(
            "http://192.168.1.1/internal", urls,
            "Private-IP hit URL must be filtered by _outbound_url_safe",
        )

    def test_public_url_in_hit_is_kept(self):
        """A hit with a normal public URL must pass through."""
        body = self._make_hn_body("https://example.com/article")
        with mock.patch("plus.search._safe_fetch", return_value=body):
            results = search_hn("test", limit=10, timeout=10)
        urls = [r["url"] for r in results]
        self.assertIn("https://example.com/article", urls)

    def test_fallback_hn_url_is_not_guarded(self):
        """Fallback news.ycombinator.com URL (no hit.url) must always appear."""
        import json
        body = json.dumps({
            "hits": [
                {
                    "title": "No External URL",
                    "objectID": "99999",
                    "created_at": "2026-01-01T00:00:00Z",
                    # no "url" key — will generate hn.algolia fallback
                }
            ]
        })
        with mock.patch("plus.search._safe_fetch", return_value=body):
            results = search_hn("test", limit=10, timeout=10)
        urls = [r["url"] for r in results]
        self.assertTrue(
            any("news.ycombinator.com" in u for u in urls),
            "Fallback HN item URL must still be included",
        )


if __name__ == "__main__":
    unittest.main()
