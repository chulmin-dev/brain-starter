"""Cookie-jar persistence across curl attempts within a single fetch() call.

Patch queue item #5 (UPSTREAM.md): a Cloudflare-style clearance cookie set on
attempt N must be re-sent on attempt N+1 instead of being thrown away. The
engine achieves this by sharing one `curl_cffi.requests.Session` across every
`_curl_probe` invocation that happens during a single `fetch()`. These tests
pin that behaviour without touching the network.

Strategy: inject a fake `curl_cffi` module via `sys.modules` so that the lazy
`from curl_cffi import requests as cffi_requests` in `engine.fetch_chain`
returns our stub. Then reload `engine.fetch_chain` so the freshly-imported
module sees the fake.
"""
from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))


# ---------------------------------------------------------------------------
# Fake curl_cffi.requests
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal duck-typed response: only what fetch_chain + validators read."""

    def __init__(self, *, status_code: int, text: str, url: str,
                 headers: dict | None = None, cookies: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.content = text.encode("utf-8", errors="replace")


class _FakeSession:
    """Records every .get() call and accumulates a cookie jar like requests."""

    def __init__(self):
        self.cookies: dict[str, str] = {}
        self.calls: list[dict] = []
        self.closed = False

    def get(self, url, *, impersonate=None, headers=None, timeout=None,
            allow_redirects=True, **_extra):
        # Real requests/curl_cffi would auto-attach session cookies as a
        # Cookie header. Mirror that so the test can assert on the outgoing
        # headers exactly the way a server would observe them.
        outgoing_headers = dict(headers or {})
        if self.cookies and "Cookie" not in outgoing_headers:
            outgoing_headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in self.cookies.items()
            )

        self.calls.append({
            "url": url,
            "impersonate": impersonate,
            "headers": outgoing_headers,
            "timeout": timeout,
            "allow_redirects": allow_redirects,
        })

        call_idx = len(self.calls)
        if call_idx == 1:
            # Attempt 1: WAF challenge sets cf_clearance and returns a body
            # that validates to CHALLENGE so fetch() proceeds to phase 2.
            self.cookies["cf_clearance"] = "AAA"
            return _FakeResponse(
                status_code=403,
                text="<html><body>Just a moment...</body></html>",
                url=url,
                headers={"set-cookie": "cf_clearance=AAA; path=/"},
                cookies={"cf_clearance": "AAA"},
            )
        # Subsequent calls: return cheap CHALLENGE responses so the grid
        # keeps spinning long enough for the cookie to be carried.
        return _FakeResponse(
            status_code=403,
            text="<html><body>Just a moment...</body></html>",
            url=url,
        )

    def close(self):
        self.closed = True


_LAST_FAKE_SESSION: _FakeSession | None = None


def _install_fake_curl_cffi():
    """Insert a fake curl_cffi tree into sys.modules; return the module."""
    global _LAST_FAKE_SESSION

    fake_requests = types.ModuleType("curl_cffi.requests")

    def _session_factory():
        global _LAST_FAKE_SESSION
        _LAST_FAKE_SESSION = _FakeSession()
        return _LAST_FAKE_SESSION

    def _module_level_get(*_args, **_kwargs):  # pragma: no cover
        raise AssertionError(
            "cffi_requests.get() should not be called when a Session is in use"
        )

    fake_requests.Session = _session_factory  # type: ignore[attr-defined]
    fake_requests.get = _module_level_get  # type: ignore[attr-defined]

    fake_pkg = types.ModuleType("curl_cffi")
    fake_pkg.requests = fake_requests  # type: ignore[attr-defined]

    sys.modules["curl_cffi"] = fake_pkg
    sys.modules["curl_cffi.requests"] = fake_requests
    return fake_pkg


def _reload_fetch_chain():
    """Force re-import so cached lazy imports re-bind to the fake module."""
    # Drop the cached module so the next import re-executes the file with
    # the fake curl_cffi visible.
    for name in list(sys.modules):
        if name == "engine.fetch_chain" or name.startswith("engine.fetch_chain."):
            del sys.modules[name]
    fc = importlib.import_module("engine.fetch_chain")
    # Keep the `engine` package's `fetch_chain` attribute in sync with the
    # freshly-loaded module so `from engine import fetch_chain` returns it.
    import engine as _engine_root
    _engine_root.fetch_chain = fc
    return fc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCookiePersistence(unittest.TestCase):
    """A single fetch() must reuse one Session across all curl attempts."""

    def setUp(self):
        # addCleanup registers rollbacks immediately so a raise mid-setUp still
        # rolls back what we touched (tearDown would not run in that case).
        from plus.tests._engine_fake_helper import install_fake_curl_cffi_isolation
        install_fake_curl_cffi_isolation(self)
        _install_fake_curl_cffi()
        self.fetch_chain = _reload_fetch_chain()

    def test_single_session_shared_across_attempts(self):
        """All attempts within one fetch() share one Session instance."""
        result = self.fetch_chain.fetch(
            "https://example.com/",
            success_selectors=["article.never-matches"],
            timeout=1,
            max_attempts=5,
            enable_playwright=False,
        )
        self.assertIsNotNone(_LAST_FAKE_SESSION)
        # At minimum the phase-1 probe + a couple of grid attempts ran.
        self.assertGreaterEqual(len(_LAST_FAKE_SESSION.calls), 2,
                                "expected probe + grid attempts to share session")
        # Session was closed in the finally block of fetch().
        self.assertTrue(_LAST_FAKE_SESSION.closed,
                        "session.close() must run on fetch() exit")
        # fetch() returned cleanly even though all attempts were CHALLENGEs.
        self.assertFalse(result.ok)

    def test_cf_clearance_cookie_attached_on_attempt_two(self):
        """Cookie set on attempt 1 reappears as a Cookie header on attempt 2."""
        self.fetch_chain.fetch(
            "https://example.com/",
            success_selectors=["article.never-matches"],
            timeout=1,
            max_attempts=5,
            enable_playwright=False,
        )
        self.assertIsNotNone(_LAST_FAKE_SESSION)
        self.assertGreaterEqual(len(_LAST_FAKE_SESSION.calls), 2)
        first_call = _LAST_FAKE_SESSION.calls[0]
        second_call = _LAST_FAKE_SESSION.calls[1]
        # First call: no Cookie header yet (jar empty).
        self.assertNotIn("Cookie", first_call["headers"])
        # Second call: the cf_clearance set on call 1 has been auto-attached.
        self.assertIn("Cookie", second_call["headers"])
        self.assertIn("cf_clearance=AAA", second_call["headers"]["Cookie"])
        # Jar accumulated.
        self.assertEqual(_LAST_FAKE_SESSION.cookies.get("cf_clearance"), "AAA")


if __name__ == "__main__":
    unittest.main()
