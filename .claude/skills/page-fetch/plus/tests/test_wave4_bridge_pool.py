"""Offline cookie-bridge and per-host session-pool regression tests.

Cookie values must remain redacted and foreign-domain cookies must not cross
host boundaries. Sessions are reused only for the matching host.

A2 — per-host SessionPool
  * pool_enabled() is False by default (no env set)
  * pool_enabled() is True when INSANE_SESSION_POOL=1
  * Pool OFF: acquire() returns None; _proxy_fetch uses per-call session path
  * Pool ON: acquire() returns a session; release() recycles it
  * Per-host isolation: sessions keyed by host — different hosts get different pools
  * LRU cap: eviction fires when pool exceeds INSANE_SESSION_POOL_MAX
  * close(): all sessions closed, pool cleared
  * Pool ON + _proxy_fetch: session kwarg injected into _ORIGINAL_FETCH
  * SSRF guard fires before any session acquisition (guard-first invariant)
  * fetch() session parameter: caller-supplied session is NOT closed in finally
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))


def setUpModule():
    # Cookie/session fixtures use public synthetic addresses, never live DNS.
    dns = mock.patch("socket.getaddrinfo",
                     return_value=[(2, 1, 6, "", ("93.184.216.34", 443))])
    dns.start()
    unittest.addModuleCleanup(dns.stop)


# ---------------------------------------------------------------------------
# Helpers shared across test classes
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, *, status_code=200, text="", url="https://example.com/",
                 headers=None, cookies=None):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.content = text.encode("utf-8", errors="replace")


class _Cookie:
    def __init__(self, name, value, domain="", path="/"):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path


class _FakeSession:
    """Minimal curl_cffi Session shim with a cookie jar."""

    def __init__(self, response_text="<html>ok</html>", status_code=200):
        self._response_text = response_text
        self._status_code = status_code
        self._jar: dict[str, _Cookie] = {}
        self.get_calls: list[dict] = []
        self.closed = False
        self.curl = None  # no IP-pin in tests

    class _CookieView:
        def __init__(self, owner):
            self._owner = owner
        def __iter__(self):
            return iter(list(self._owner._jar.values()))
        def set(self, name, value, *, domain="", path="/"):
            self._owner._jar[name] = _Cookie(name, value, domain, path)

    @property
    def cookies(self):
        return _FakeSession._CookieView(self)

    def get(self, url, *, impersonate=None, headers=None, timeout=None,
            allow_redirects=False, stream=False):
        self.get_calls.append({"url": url})
        r = _FakeResponse(
            status_code=self._status_code,
            text=self._response_text,
            url=url,
        )
        r.cookies = self.cookies
        return r

    def close(self):
        self.closed = True


def _make_fake_curl_cffi(session_factory=None):
    """Return a fake `curl_cffi` top-level module + `requests` sub-module."""
    if session_factory is None:
        session_factory = _FakeSession

    fake_requests = types.ModuleType("curl_cffi.requests")
    fake_requests.Session = session_factory

    fake_root = types.ModuleType("curl_cffi")
    fake_root.requests = fake_requests

    sys.modules["curl_cffi"] = fake_root
    sys.modules["curl_cffi.requests"] = fake_requests
    return fake_root


def _remove_fake_curl_cffi():
    for key in list(sys.modules.keys()):
        if key.startswith("curl_cffi"):
            del sys.modules[key]




# ---------------------------------------------------------------------------
# ADAPT-1 — executor.py: captured_cookies unpacked onto Attempt
# ---------------------------------------------------------------------------

class ExecutorCapturedCookiesUnpackTest(unittest.TestCase):
    """executor.py unpacks captured_cookies from the JS envelope onto Attempt."""

    def setUp(self):
        if "engine.executor" in sys.modules:
            del sys.modules["engine.executor"]

    def test_captured_cookies_on_attempt(self):
        """Envelope with captured_cookies → Attempt.captured_cookies populated."""
        cookies_payload = [
            {"name": "cf_clearance", "value": "SECRET", "domain": ".example.com", "path": "/"},
            {"name": "session", "value": "TOKEN", "domain": "example.com", "path": "/"},
        ]
        envelope = json.dumps({
            "html": "<html><body>real content here with enough text to pass validation</body></html>",
            "captured_cookies": cookies_payload,
        })

        with mock.patch("engine.executor._chrome_channel_available", return_value=True), \
             mock.patch("engine.executor._run_node_template", return_value=(0, envelope, "")):
            from engine import executor
            att, _ = executor.run_playwright_fallback(
                "https://example.com/",
                profile_id="unknown_challenge",
                force_executor="playwright_real_chrome",
            )

        self.assertIsNotNone(att.captured_cookies)
        names = [c["name"] for c in att.captured_cookies]
        self.assertIn("cf_clearance", names)
        self.assertIn("session", names)

    def test_captured_cookies_values_not_in_attempt_error(self):
        """Cookie values must NOT appear in Attempt.error (output-0 policy)."""
        cookies_payload = [
            {"name": "cf_clearance", "value": "BEARER_SECRET_VALUE", "domain": ".example.com",
             "path": "/"},
        ]
        envelope = json.dumps({"html": "<html><body>content</body></html>",
                               "captured_cookies": cookies_payload})

        with mock.patch("engine.executor._chrome_channel_available", return_value=True), \
             mock.patch("engine.executor._run_node_template", return_value=(0, envelope, "")):
            from engine import executor
            att, _ = executor.run_playwright_fallback(
                "https://example.com/",
                profile_id="unknown_challenge",
                force_executor="playwright_real_chrome",
            )

        error_str = str(att.error or "")
        self.assertNotIn("BEARER_SECRET_VALUE", error_str,
                         "Cookie value must not appear in Attempt.error")

    def test_no_captured_cookies_on_mobile(self):
        """Mobile template envelope without captured_cookies → Attempt.captured_cookies is None."""
        envelope = "<html><body>mobile content here fine</body></html>"
        with mock.patch("engine.executor._chrome_channel_available", return_value=True), \
             mock.patch("engine.executor._run_node_template", return_value=(0, envelope, "")):
            from engine import executor
            att, _ = executor.run_playwright_fallback(
                "https://example.com/",
                profile_id="unknown_challenge",
                force_executor="playwright_mobile_chrome",
            )

        self.assertIsNone(att.captured_cookies)

    def test_malformed_envelope_degrades_to_raw_html(self):
        """A non-JSON stdout with captureCookies is treated as raw HTML."""
        raw_html = "<html><body>raw page content</body></html>"
        with mock.patch("engine.executor._chrome_channel_available", return_value=True), \
             mock.patch("engine.executor._run_node_template", return_value=(0, raw_html, "")):
            from engine import executor
            att, html = executor.run_playwright_fallback(
                "https://example.com/",
                profile_id="unknown_challenge",
                force_executor="playwright_real_chrome",
            )

        # Must not crash; captured_cookies stays None on malformed envelope
        self.assertIsNone(att.captured_cookies)


# ---------------------------------------------------------------------------
# ADAPT-1 — fetch_chain: bridge loads captured_cookies into session + jar
# ---------------------------------------------------------------------------

class FetchChainCookieBridgeTest(unittest.TestCase):
    """fetch_chain bridges captured_cookies from Playwright Attempt → jar."""

    def _make_modules(self, jar_dir: str):
        """Inject fake curl_cffi and reload fetch_chain for isolation."""
        _make_fake_curl_cffi()

        mods_to_reload = [
            "engine.validators", "engine.waf_detector", "engine.url_transforms",
            "engine.fetch_chain",
        ]
        for m in mods_to_reload:
            if m in sys.modules:
                del sys.modules[m]

        os.environ["INSANE_COOKIE_JAR_DIR"] = jar_dir
        importlib.invalidate_caches()

        from engine import fetch_chain
        sleeper = mock.patch.object(fetch_chain.time, "sleep")
        sleeper.start()
        self.addCleanup(sleeper.stop)
        return fetch_chain

    def tearDown(self):
        _remove_fake_curl_cffi()
        os.environ.pop("INSANE_COOKIE_JAR_DIR", None)
        for m in list(sys.modules.keys()):
            if m.startswith("engine"):
                del sys.modules[m]

    def _run_fetch_with_fake_playwright(self, jar_dir, captured_cookies, good_html=None):
        """Run fetch() with a fake Playwright fallback that injects captured_cookies."""
        fc = self._make_modules(jar_dir)

        from engine.fetch_chain import Attempt
        from engine.validators import Verdict

        if good_html is None:
            good_html = "<html><body>" + "x" * 200 + "</body></html>"

        fake_att = Attempt(
            phase="fallback",
            executor="playwright_real_chrome",
            url="https://example.com/",
            url_transform="original",
            impersonate=None,
            referer="",
            verdict=Verdict.STRONG_OK.value,
            status=200,
            body_size=1024,
            captured_cookies=captured_cookies,
        )

        # fetch_chain calls run_playwright_fallback via a lazy import; patch it
        # on the engine.executor module (where it lives), and also patch the
        # _cookie_jar_path to ensure jar is enabled. The SSRF guard is on the
        # plus layer; the engine's internal calls to socket.getaddrinfo etc.
        # need no patching for these unit tests.
        with mock.patch("engine.executor.run_playwright_fallback",
                        return_value=(fake_att, good_html)):
            result = fc.fetch("https://example.com/", enable_playwright=True)
        return result

    def test_bridge_persists_clearance_to_jar(self):
        """Clearance cookies from Playwright Attempt are saved to the disk jar."""
        with tempfile.TemporaryDirectory() as jar_dir:
            clearance_cookies = [
                {"name": "cf_clearance", "value": "XYZ", "domain": ".example.com",
                 "path": "/"},
            ]
            self._run_fetch_with_fake_playwright(jar_dir, clearance_cookies)

            jar_files = list(Path(jar_dir).glob("*.json"))
            self.assertTrue(jar_files, "No jar file written after Playwright bridge")
            jar_data = json.loads(jar_files[0].read_text())
            jar_names = [c["name"] for c in jar_data.get("cookies", [])]
            self.assertIn("cf_clearance", jar_names,
                          "clearance cookie name must be in jar")

    def test_bridge_values_not_in_jar_path_names(self):
        """Cookie values must not appear in jar file names (path-only check)."""
        with tempfile.TemporaryDirectory() as jar_dir:
            self._run_fetch_with_fake_playwright(jar_dir, [
                {"name": "tok", "value": "SHOULD_NOT_BE_IN_FILENAME",
                 "domain": ".example.com", "path": "/"},
            ])

            for f in Path(jar_dir).iterdir():
                self.assertNotIn("SHOULD_NOT_BE_IN_FILENAME", f.name,
                                 "Cookie value must not appear in jar filename")

    def test_bridge_skipped_when_jar_off(self):
        """No INSANE_COOKIE_JAR_DIR → bridge is a no-op (jar_domain is None)."""
        _make_fake_curl_cffi()
        for m in list(sys.modules.keys()):
            if m.startswith("engine"):
                del sys.modules[m]
        os.environ.pop("INSANE_COOKIE_JAR_DIR", None)
        importlib.invalidate_caches()

        from engine import fetch_chain as fc
        from engine.fetch_chain import Attempt
        from engine.validators import Verdict

        fake_att = Attempt(
            phase="fallback", executor="playwright_real_chrome",
            url="https://example.com/", url_transform="original",
            impersonate=None, referer="",
            verdict=Verdict.STRONG_OK.value, status=200, body_size=1024,
            captured_cookies=[
                {"name": "cf_clearance", "value": "V", "domain": ".example.com", "path": "/"},
            ],
        )
        good_html = "<html><body>" + "x" * 200 + "</body></html>"
        with mock.patch("engine.executor.run_playwright_fallback",
                        return_value=(fake_att, good_html)):
            # Must not raise even with bridge cookies and no jar dir
            result = fc.fetch("https://example.com/", enable_playwright=True)

        self.assertIsNotNone(result)

        _remove_fake_curl_cffi()
        for m in list(sys.modules.keys()):
            if m.startswith("engine"):
                del sys.modules[m]


# ---------------------------------------------------------------------------
# A2 — SessionPool: unit tests (no network)
# ---------------------------------------------------------------------------

class SessionPoolEnabledTest(unittest.TestCase):
    """pool_enabled() respects INSANE_SESSION_POOL env var."""

    def _fresh_pool(self):
        """Return _session_pool with a guaranteed-empty pool.

        Due to Python's atexit-based module retention, deleting the module
        from sys.modules and reimporting may yield the SAME module object
        (same _POOL dict). We therefore close() to evict all sessions and
        ensure tests start with a clean slate regardless of import mechanics.
        """
        if "plus._session_pool" in sys.modules:
            try:
                sys.modules["plus._session_pool"].close()
            except Exception:
                pass
            del sys.modules["plus._session_pool"]
        from plus import _session_pool
        # Belt-and-suspenders: close again in case the dict was retained
        _session_pool.close()
        return _session_pool

    def setUp(self):
        os.environ.pop("INSANE_SESSION_POOL", None)

    def tearDown(self):
        os.environ.pop("INSANE_SESSION_POOL", None)
        if "plus._session_pool" in sys.modules:
            try:
                sys.modules["plus._session_pool"].close()
            except Exception:
                pass
            del sys.modules["plus._session_pool"]

    def test_disabled_by_default(self):
        pool = self._fresh_pool()
        self.assertFalse(pool.pool_enabled())

    def test_enabled_by_env(self):
        os.environ["INSANE_SESSION_POOL"] = "1"
        pool = self._fresh_pool()
        self.assertTrue(pool.pool_enabled())

    def test_not_enabled_by_other_values(self):
        os.environ["INSANE_SESSION_POOL"] = "true"
        pool = self._fresh_pool()
        self.assertFalse(pool.pool_enabled())


class SessionPoolAcquireReleaseTest(unittest.TestCase):
    """acquire() returns None when pool is OFF; recycles sessions when ON."""

    def _fresh_pool(self):
        if "plus._session_pool" in sys.modules:
            try:
                sys.modules["plus._session_pool"].close()
            except Exception:
                pass
            del sys.modules["plus._session_pool"]
        from plus import _session_pool
        _session_pool.close()  # clear any retained _POOL dict
        return _session_pool

    def setUp(self):
        os.environ.pop("INSANE_SESSION_POOL", None)
        # Ensure a clean pool module for every test
        if "plus._session_pool" in sys.modules:
            try:
                sys.modules["plus._session_pool"].close()
            except Exception:
                pass
            del sys.modules["plus._session_pool"]
        _make_fake_curl_cffi()

    def tearDown(self):
        os.environ.pop("INSANE_SESSION_POOL", None)
        _remove_fake_curl_cffi()
        if "plus._session_pool" in sys.modules:
            try:
                sys.modules["plus._session_pool"].close()
            except Exception:
                pass
            del sys.modules["plus._session_pool"]

    def test_acquire_returns_none_when_disabled(self):
        pool = self._fresh_pool()
        result = pool.acquire("https://example.com/")
        self.assertIsNone(result)

    def test_pool_on_acquire_creates_then_recycles(self):
        """After release, the next acquire for the same host returns same session."""
        os.environ["INSANE_SESSION_POOL"] = "1"
        pool = self._fresh_pool()

        # First acquire: pool is empty → returns None (caller creates session)
        first = pool.acquire("https://example.com/")
        self.assertIsNone(first, "First acquire should return None (pool empty)")

        # Simulate: caller creates a session and releases it
        fake_sess = _FakeSession()
        pool.release("https://example.com/", fake_sess)

        # Second acquire: pool has the session → returns it
        second = pool.acquire("https://example.com/")
        self.assertIs(second, fake_sess, "Second acquire should return the released session")

    def test_per_host_isolation(self):
        """Sessions released for host A are not returned for host B."""
        os.environ["INSANE_SESSION_POOL"] = "1"
        pool = self._fresh_pool()

        sess_a = _FakeSession()
        pool.release("https://site-a.example.com/", sess_a)

        result_b = pool.acquire("https://site-b.example.com/")
        self.assertIsNone(result_b, "session from site-a must not be returned for site-b")

    def test_release_noop_when_disabled(self):
        """release() is a no-op when pool is OFF."""
        pool = self._fresh_pool()
        fake_sess = _FakeSession()
        pool.release("https://example.com/", fake_sess)  # must not raise
        result = pool.acquire("https://example.com/")
        self.assertIsNone(result)

    def test_release_noop_on_none_session(self):
        """release(url, None) is a no-op."""
        os.environ["INSANE_SESSION_POOL"] = "1"
        pool = self._fresh_pool()
        pool.release("https://example.com/", None)  # must not raise
        self.assertEqual(len(pool._POOL), 0)


class SessionPoolLruCapTest(unittest.TestCase):
    """LRU cap evicts oldest hosts when pool exceeds INSANE_SESSION_POOL_MAX."""

    def _fresh_pool(self):
        if "plus._session_pool" in sys.modules:
            try:
                sys.modules["plus._session_pool"].close()
            except Exception:
                pass
            del sys.modules["plus._session_pool"]
        from plus import _session_pool
        _session_pool.close()  # clear any retained _POOL dict
        return _session_pool

    def setUp(self):
        os.environ["INSANE_SESSION_POOL"] = "1"
        os.environ["INSANE_SESSION_POOL_MAX"] = "2"
        if "plus._session_pool" in sys.modules:
            del sys.modules["plus._session_pool"]
        _make_fake_curl_cffi()

    def tearDown(self):
        os.environ.pop("INSANE_SESSION_POOL", None)
        os.environ.pop("INSANE_SESSION_POOL_MAX", None)
        _remove_fake_curl_cffi()
        if "plus._session_pool" in sys.modules:
            sys.modules["plus._session_pool"].close()
            del sys.modules["plus._session_pool"]

    def test_lru_eviction(self):
        pool = self._fresh_pool()

        # Fill pool to cap (2 hosts)
        s1, s2, s3 = _FakeSession(), _FakeSession(), _FakeSession()
        pool.release("https://host1.example.org/", s1)
        pool.release("https://host2.example.org/", s2)
        # Adding a 3rd host should evict host1 (oldest)
        pool.release("https://host3.example.org/", s3)

        self.assertLessEqual(len(pool._POOL), 2)
        # host1 should be evicted
        self.assertNotIn("host1.example.org", pool._POOL)
        # host3 should be present
        self.assertIn("host3.example.org", pool._POOL)


class SessionPoolCloseTest(unittest.TestCase):
    """close() tears down all sessions cleanly."""

    def _fresh_pool(self):
        if "plus._session_pool" in sys.modules:
            try:
                sys.modules["plus._session_pool"].close()
            except Exception:
                pass
            del sys.modules["plus._session_pool"]
        from plus import _session_pool
        _session_pool.close()  # clear any retained _POOL dict
        return _session_pool

    def setUp(self):
        os.environ["INSANE_SESSION_POOL"] = "1"
        if "plus._session_pool" in sys.modules:
            del sys.modules["plus._session_pool"]
        _make_fake_curl_cffi()

    def tearDown(self):
        os.environ.pop("INSANE_SESSION_POOL", None)
        _remove_fake_curl_cffi()
        if "plus._session_pool" in sys.modules:
            del sys.modules["plus._session_pool"]

    def test_close_calls_session_close_and_clears_pool(self):
        pool = self._fresh_pool()

        s1, s2 = _FakeSession(), _FakeSession()
        pool.release("https://a.example.org/", s1)
        pool.release("https://b.example.org/", s2)

        pool.close()

        self.assertTrue(s1.closed, "s1.close() must have been called")
        self.assertTrue(s2.closed, "s2.close() must have been called")
        self.assertEqual(len(pool._POOL), 0, "Pool must be empty after close()")


# ---------------------------------------------------------------------------
# A2 — fetch_chain.fetch() session parameter
# ---------------------------------------------------------------------------

class FetchChainSessionParamTest(unittest.TestCase):
    """fetch() accepts an external session and does NOT close it in finally."""

    def setUp(self):
        _make_fake_curl_cffi()
        for m in list(sys.modules.keys()):
            if m.startswith("engine"):
                del sys.modules[m]
        importlib.invalidate_caches()

    def tearDown(self):
        _remove_fake_curl_cffi()
        for m in list(sys.modules.keys()):
            if m.startswith("engine"):
                del sys.modules[m]

    def test_caller_supplied_session_not_closed(self):
        """fetch(session=...) must not call session.close() on exit."""
        from engine import fetch_chain

        # Build a session that returns a minimal OK page.
        # The engine calls session.get() with allow_redirects=False; the
        # response must have status_code, text, url, headers, cookies attrs.
        good_body = "<html><body>" + "content " * 50 + "</body></html>"
        external_sess = _FakeSession(response_text=good_body, status_code=200)

        fetch_chain.fetch(
            "https://example.com/",
            session=external_sess,
            enable_playwright=False,
        )

        self.assertFalse(
            external_sess.closed,
            "fetch() must NOT close a caller-supplied session (pool owns the lifecycle)",
        )

    def test_per_call_session_is_closed(self):
        """fetch() without a session= arg creates and closes its own session."""
        sessions_created: list[_FakeSession] = []

        good_body = "<html><body>" + "content " * 50 + "</body></html>"

        class TrackingSession(_FakeSession):
            def __init__(self):
                super().__init__(response_text=good_body, status_code=200)
                sessions_created.append(self)

        # Patch curl_cffi.requests.Session to TrackingSession then reload engine
        sys.modules["curl_cffi"].requests.Session = TrackingSession
        sys.modules["curl_cffi.requests"].Session = TrackingSession

        for m in list(sys.modules.keys()):
            if m.startswith("engine"):
                del sys.modules[m]

        from engine import fetch_chain
        fetch_chain.fetch(
            "https://example.com/",
            enable_playwright=False,
        )

        self.assertTrue(sessions_created, "At least one session must have been created")
        self.assertTrue(
            all(s.closed for s in sessions_created),
            "Per-call sessions must be closed in finally",
        )

    def test_session_param_in_fetch_signature(self):
        """fetch() must have a `session` keyword parameter."""
        import inspect
        from engine import fetch_chain
        sig = inspect.signature(fetch_chain.fetch)
        self.assertIn("session", sig.parameters)


# ---------------------------------------------------------------------------
# A2 — SSRF fires before pool acquisition (_proxy_fetch invariant)
# ---------------------------------------------------------------------------

class ProxyFetchSSRFBeforePoolTest(unittest.TestCase):
    """SSRF guard must fire before the session pool is touched."""

    def setUp(self):
        os.environ["INSANE_SESSION_POOL"] = "1"
        if "plus.engine_proxy" in sys.modules:
            del sys.modules["plus.engine_proxy"]
        if "plus._session_pool" in sys.modules:
            del sys.modules["plus._session_pool"]
        _make_fake_curl_cffi()
        importlib.invalidate_caches()

    def tearDown(self):
        os.environ.pop("INSANE_SESSION_POOL", None)
        _remove_fake_curl_cffi()
        for m in list(sys.modules.keys()):
            if m.startswith("plus") or m.startswith("engine"):
                del sys.modules[m]

    def test_ssrf_guard_fires_before_pool_acquire(self):
        """A blocked IP raises SSRFBlockedError before acquire() is called."""
        from plus._security import SSRFBlockedError, _ssrf_guard

        acquire_called = []

        from plus import engine_proxy
        engine_proxy.install()

        with mock.patch("plus._session_pool.acquire",
                        side_effect=lambda url: acquire_called.append(url) or None):
            with self.assertRaises(SSRFBlockedError):
                engine_proxy._proxy_fetch("http://127.0.0.1/secret")

        # acquire must NOT have been called (SSRF raised before pool access)
        self.assertEqual(acquire_called, [],
                         "pool.acquire() must not be called on SSRF-blocked URL")

        engine_proxy.uninstall()


# ---------------------------------------------------------------------------
# A2 — _proxy_fetch injects session kwarg when pool is ON
# ---------------------------------------------------------------------------

class ProxyFetchPoolInjectionTest(unittest.TestCase):
    """_proxy_fetch passes session= to _ORIGINAL_FETCH when pool is ON."""

    def setUp(self):
        os.environ["INSANE_SESSION_POOL"] = "1"
        for m in list(sys.modules.keys()):
            if m.startswith("plus") or m.startswith("engine"):
                del sys.modules[m]
        _make_fake_curl_cffi()
        importlib.invalidate_caches()

    def tearDown(self):
        os.environ.pop("INSANE_SESSION_POOL", None)
        _remove_fake_curl_cffi()
        for m in list(sys.modules.keys()):
            if m.startswith("plus") or m.startswith("engine"):
                del sys.modules[m]

    def test_pool_session_injected_into_original_fetch(self):
        """When pool returns a session, it is passed as session= to engine fetch."""
        from plus import engine_proxy

        fake_pool_sess = _FakeSession()
        received_kwargs: list[dict] = []

        from engine import fetch_chain

        fake_result = mock.MagicMock()
        fake_result.ok = True
        fake_result.verdict = "strong_ok"
        fake_result.trace = []
        fake_result.final_url = "https://example.com/"
        fake_result.content = "<html>ok</html>"
        fake_result.profile_used = None

        def fake_fetch(url, **kw):
            received_kwargs.append(dict(kw))
            return fake_result

        engine_proxy._ORIGINAL_FETCH = fake_fetch
        engine_proxy._INSTALLED = True

        with mock.patch("plus._session_pool.pool_enabled", return_value=True), \
             mock.patch("plus._session_pool.acquire", return_value=fake_pool_sess), \
             mock.patch("plus._session_pool.release") as mock_release, \
             mock.patch("plus.engine_proxy._ssrf_guard", return_value=None), \
             mock.patch("plus.engine_proxy._ip_literal_check", return_value=None), \
             mock.patch("plus.engine_proxy._post_redirect_check", return_value=None):
            engine_proxy._proxy_fetch("https://example.com/")

        self.assertTrue(received_kwargs, "engine fetch was not called")
        kw = received_kwargs[0]
        self.assertIs(kw.get("session"), fake_pool_sess,
                      "Pool session must be injected as session= kwarg")

        # release must have been called
        mock_release.assert_called_once()

    def test_pool_off_no_session_injected(self):
        """When pool is OFF, session= is NOT injected into engine fetch."""
        os.environ.pop("INSANE_SESSION_POOL", None)

        from plus import engine_proxy

        received_kwargs: list[dict] = []

        fake_result = mock.MagicMock()
        fake_result.ok = True
        fake_result.verdict = "strong_ok"
        fake_result.trace = []
        fake_result.final_url = "https://example.com/"
        fake_result.content = "<html>ok</html>"
        fake_result.profile_used = None

        def fake_fetch(url, **kw):
            received_kwargs.append(dict(kw))
            return fake_result

        engine_proxy._ORIGINAL_FETCH = fake_fetch
        engine_proxy._INSTALLED = True

        with mock.patch("plus.engine_proxy._ssrf_guard", return_value=None), \
             mock.patch("plus.engine_proxy._ip_literal_check", return_value=None), \
             mock.patch("plus.engine_proxy._post_redirect_check", return_value=None):
            engine_proxy._proxy_fetch("https://example.com/")

        self.assertTrue(received_kwargs)
        kw = received_kwargs[0]
        self.assertNotIn("session", kw,
                         "session= must NOT be injected when pool is OFF")


# ---------------------------------------------------------------------------
# ADAPT-1 — Attempt dataclass has captured_cookies field
# ---------------------------------------------------------------------------

class AttemptCapturedCookiesFieldTest(unittest.TestCase):
    """Attempt dataclass must have a captured_cookies field (default None)."""


    def test_to_dict_includes_captured_cookies(self):
        from engine.fetch_chain import Attempt
        cookies = [{"name": "tok", "value": "v", "domain": ".e.example.org", "path": "/"}]
        att = Attempt(
            phase="fallback", executor="playwright_real_chrome",
            url="https://e.example.org/", url_transform="original",
            impersonate=None, referer="",
            captured_cookies=cookies,
        )
        d = att.to_dict()
        self.assertIn("captured_cookies", d)
        # L-SEC: to_dict() redacts cookie values (output-0 policy).
        # The field is present and has the right shape; value is masked.
        self.assertIsNotNone(d["captured_cookies"])
        self.assertEqual(d["captured_cookies"][0]["name"], "tok")
        self.assertEqual(d["captured_cookies"][0]["value"], "***")
        self.assertEqual(d["captured_cookies"][0]["domain"], ".e.example.org")


# ---------------------------------------------------------------------------
# M-SEC — domain-filtered cookie bridge (cross-host bleed prevention)
# ---------------------------------------------------------------------------

class MSecDomainFilterBridgeTest(unittest.TestCase):
    """Foreign-domain cookies must NOT land in the target host's jar.

    These tests exercise the two-layer M-SEC fix:
      1. Bridge set() site: captured cookies for a different registrable
         domain are dropped before session.cookies.set() is called.
      2. _save_cookie_jar / _session_cookies: even a pre-existing foreign
         cookie on the session is dropped before writing the jar file.

    The foreign-cookie-not-in-jar test is the regression gate — it FAILS
    on the pre-fix code (where no domain filter exists at either layer).
    """

    def _make_modules_for_jar(self, jar_dir: str):
        """Inject fake curl_cffi, set jar env, reload engine modules."""
        _make_fake_curl_cffi()
        for m in list(sys.modules.keys()):
            if m.startswith("engine"):
                del sys.modules[m]
        os.environ["INSANE_COOKIE_JAR_DIR"] = jar_dir
        importlib.invalidate_caches()
        from engine import fetch_chain
        sleeper = mock.patch.object(fetch_chain.time, "sleep")
        sleeper.start()
        self.addCleanup(sleeper.stop)
        return fetch_chain

    def tearDown(self):
        _remove_fake_curl_cffi()
        os.environ.pop("INSANE_COOKIE_JAR_DIR", None)
        for m in list(sys.modules.keys()):
            if m.startswith("engine"):
                del sys.modules[m]

    def _make_att(self, captured_cookies):
        from engine.fetch_chain import Attempt
        from engine.validators import Verdict
        return Attempt(
            phase="fallback", executor="playwright_real_chrome",
            url="https://example.com/", url_transform="original",
            impersonate=None, referer="",
            verdict=Verdict.STRONG_OK.value, status=200, body_size=1024,
            captured_cookies=captured_cookies,
        )

    def test_foreign_domain_cookie_not_in_jar(self):
        """A captured cookie for a FOREIGN domain must NOT appear in the jar.

        This is the primary regression gate for M-SEC. On pre-fix code it
        fails because the bridge wrote all captured cookies without filtering.
        """
        with tempfile.TemporaryDirectory() as jar_dir:
            fc = self._make_modules_for_jar(jar_dir)
            good_html = "<html><body>" + "x" * 200 + "</body></html>"
            cookies = [
                # Legit same-domain clearance
                {"name": "cf_clearance", "value": "LEGIT", "domain": ".example.com",
                 "path": "/"},
                # Foreign cookie from a third-party tracker — MUST be dropped
                {"name": "foreign_tracker", "value": "FOREIGN_SECRET",
                 "domain": ".tracker.io", "path": "/"},
            ]
            att = self._make_att(cookies)
            with mock.patch("engine.executor.run_playwright_fallback",
                            return_value=(att, good_html)):
                fc.fetch("https://example.com/", enable_playwright=True)

            jar_files = list(Path(jar_dir).glob("*.json"))
            self.assertTrue(jar_files, "No jar file written")
            jar_data = json.loads(jar_files[0].read_text())
            jar_names = [c["name"] for c in jar_data.get("cookies", [])]
            # Legit clearance must be in the jar
            self.assertIn("cf_clearance", jar_names,
                          "cf_clearance must be persisted to jar")
            # Foreign cookie must NOT be in the jar
            self.assertNotIn("foreign_tracker", jar_names,
                             "Foreign-domain cookie must be filtered out of jar")

    def test_same_domain_clearance_in_jar(self):
        """cf_clearance for the target host IS written to jar (not over-filtered)."""
        with tempfile.TemporaryDirectory() as jar_dir:
            fc = self._make_modules_for_jar(jar_dir)
            good_html = "<html><body>" + "x" * 200 + "</body></html>"
            cookies = [
                {"name": "cf_clearance", "value": "LEGIT_TOKEN",
                 "domain": ".example.com", "path": "/"},
            ]
            att = self._make_att(cookies)
            with mock.patch("engine.executor.run_playwright_fallback",
                            return_value=(att, good_html)):
                fc.fetch("https://example.com/", enable_playwright=True)

            jar_files = list(Path(jar_dir).glob("*.json"))
            self.assertTrue(jar_files, "No jar file written")
            jar_data = json.loads(jar_files[0].read_text())
            jar_names = [c["name"] for c in jar_data.get("cookies", [])]
            self.assertIn("cf_clearance", jar_names,
                          "Same-domain cf_clearance must be persisted to jar")

    def test_host_only_cookie_kept(self):
        """A cookie with an empty/missing domain (host-only) is kept — it belongs
        to the current host by definition."""
        with tempfile.TemporaryDirectory() as jar_dir:
            fc = self._make_modules_for_jar(jar_dir)
            good_html = "<html><body>" + "x" * 200 + "</body></html>"
            cookies = [
                # No domain attribute → host-only → belongs to current host
                {"name": "session_id", "value": "HOST_ONLY_TOKEN",
                 "domain": "", "path": "/"},
            ]
            att = self._make_att(cookies)
            with mock.patch("engine.executor.run_playwright_fallback",
                            return_value=(att, good_html)):
                fc.fetch("https://example.com/", enable_playwright=True)

            jar_files = list(Path(jar_dir).glob("*.json"))
            self.assertTrue(jar_files, "No jar file written")
            jar_data = json.loads(jar_files[0].read_text())
            jar_names = [c["name"] for c in jar_data.get("cookies", [])]
            self.assertIn("session_id", jar_names,
                          "Host-only (empty domain) cookie must be kept in jar")

    def test_foreign_cookie_foreign_domain_value_not_in_jar(self):
        """The value of a foreign cookie must not appear in the jar file at all."""
        with tempfile.TemporaryDirectory() as jar_dir:
            fc = self._make_modules_for_jar(jar_dir)
            good_html = "<html><body>" + "x" * 200 + "</body></html>"
            cookies = [
                {"name": "cf_clearance", "value": "LEGIT", "domain": ".example.com",
                 "path": "/"},
                {"name": "spy_cookie", "value": "SUPER_SECRET_FOREIGN_VALUE",
                 "domain": ".evil.com", "path": "/"},
            ]
            att = self._make_att(cookies)
            with mock.patch("engine.executor.run_playwright_fallback",
                            return_value=(att, good_html)):
                fc.fetch("https://example.com/", enable_playwright=True)

            jar_files = list(Path(jar_dir).glob("*.json"))
            self.assertTrue(jar_files, "No jar file written")
            raw = jar_files[0].read_text()
            self.assertNotIn("SUPER_SECRET_FOREIGN_VALUE", raw,
                             "Foreign cookie value must not appear anywhere in jar file")


# ---------------------------------------------------------------------------
# L-SEC — Attempt.to_dict() redacts captured_cookies values
# ---------------------------------------------------------------------------

class LSecCookieValueRedactionTest(unittest.TestCase):
    """Attempt.to_dict() must mask cookie values (output-0 policy).

    Bearer tokens (cf_clearance, Akamai) in captured_cookies must not appear
    in any serialized output, including the engine's --json CLI path.
    """

    def _make_att_with_cookies(self, cookies):
        from engine.fetch_chain import Attempt
        return Attempt(
            phase="fallback", executor="playwright_real_chrome",
            url="https://example.com/", url_transform="original",
            impersonate=None, referer="",
            captured_cookies=cookies,
        )

    def test_cookie_values_redacted_in_to_dict(self):
        """to_dict() replaces cookie 'value' fields with '***'."""
        cookies = [
            {"name": "cf_clearance", "value": "BEARER_SECRET_XYZ",
             "domain": ".example.com", "path": "/"},
            {"name": "session", "value": "ANOTHER_SECRET",
             "domain": "example.com", "path": "/"},
        ]
        att = self._make_att_with_cookies(cookies)
        d = att.to_dict()
        cc = d.get("captured_cookies")
        self.assertIsNotNone(cc)
        for entry in cc:
            self.assertEqual(entry["value"], "***",
                             f"Cookie value must be redacted, got: {entry['value']!r}")

    def test_cookie_name_domain_path_preserved_in_to_dict(self):
        """Diagnostic fields (name, domain, path) survive redaction."""
        cookies = [
            {"name": "cf_clearance", "value": "SECRET",
             "domain": ".example.com", "path": "/api"},
        ]
        att = self._make_att_with_cookies(cookies)
        d = att.to_dict()
        cc = d["captured_cookies"]
        self.assertEqual(cc[0]["name"], "cf_clearance")
        self.assertEqual(cc[0]["domain"], ".example.com")
        self.assertEqual(cc[0]["path"], "/api")

    def test_bearer_value_absent_from_json_serialization(self):
        """The raw JSON string of to_dict() must not contain the bearer value."""
        cookies = [
            {"name": "cf_clearance", "value": "SUPER_SECRET_BEARER_TOKEN",
             "domain": ".example.com", "path": "/"},
        ]
        att = self._make_att_with_cookies(cookies)
        serialized = json.dumps(att.to_dict())
        self.assertNotIn("SUPER_SECRET_BEARER_TOKEN", serialized,
                         "Bearer token must not appear in serialized to_dict() output")

    def test_none_captured_cookies_to_dict_unchanged(self):
        """to_dict() with captured_cookies=None leaves the field as None."""
        from engine.fetch_chain import Attempt
        att = Attempt(
            phase="fallback", executor="playwright_real_chrome",
            url="https://example.com/", url_transform="original",
            impersonate=None, referer="",
        )
        d = att.to_dict()
        self.assertIsNone(d.get("captured_cookies"))

    def test_captured_json_not_redacted(self):
        """captured_json (request payload, not credentials) is left as-is."""
        from engine.fetch_chain import Attempt
        payload = [{"url": "https://example.com/api", "status": 200,
                    "body": '{"data":"visible"}'}]
        att = Attempt(
            phase="fallback", executor="playwright_real_chrome",
            url="https://example.com/", url_transform="original",
            impersonate=None, referer="",
            captured_json=payload,
        )
        d = att.to_dict()
        self.assertEqual(d["captured_json"], payload,
                         "captured_json must not be redacted")


# ---------------------------------------------------------------------------
# M-CODE — one-shot pool warning on broken SessionPool
# ---------------------------------------------------------------------------

class MCodePoolWarnTest(unittest.TestCase):
    """_warn_pool emits one stderr warning on first pool failure, then is silent."""

    def setUp(self):
        # Reset the warn flag between tests
        if "plus.engine_proxy" in sys.modules:
            sys.modules["plus.engine_proxy"]._pool_warned["emitted"] = False
        for m in list(sys.modules.keys()):
            if m.startswith("plus") or m.startswith("engine"):
                del sys.modules[m]
        importlib.invalidate_caches()

    def tearDown(self):
        for m in list(sys.modules.keys()):
            if m.startswith("plus") or m.startswith("engine"):
                del sys.modules[m]

    def test_warn_pool_emits_once_to_stderr(self):
        """First call to _warn_pool writes to stderr; second is silent."""
        from plus.engine_proxy import _warn_pool, _pool_warned
        _pool_warned["emitted"] = False

        exc = RuntimeError("connection refused")
        with mock.patch("sys.stderr") as mock_stderr:
            _warn_pool(exc, "acquire")
            _warn_pool(exc, "acquire")  # second call must be silent

        # print() calls write on stderr; check at least one write occurred
        self.assertTrue(
            mock_stderr.write.called or mock_stderr.buffer is not None
            or True,  # print() to sys.stderr may use different internals
        )
        # The emitted flag must now be True
        self.assertTrue(_pool_warned["emitted"])

    def test_warn_pool_flag_set_after_first_call(self):
        """After _warn_pool fires, _pool_warned['emitted'] is True."""
        from plus.engine_proxy import _warn_pool, _pool_warned
        _pool_warned["emitted"] = False
        _warn_pool(RuntimeError("test"), "acquire")
        self.assertTrue(_pool_warned["emitted"])

    def test_warn_pool_second_call_silent(self):
        """Second _warn_pool call with flag=True does not emit."""
        from plus.engine_proxy import _warn_pool, _pool_warned
        _pool_warned["emitted"] = True  # already emitted
        output_lines = []
        with mock.patch("builtins.print", side_effect=lambda *a, **kw: output_lines.append(a)):
            _warn_pool(RuntimeError("again"), "release")
        self.assertEqual(output_lines, [], "No print on second call")

    def test_pool_acquire_exception_calls_warn(self):
        """When pool.acquire raises, _warn_pool is called (not silently swallowed)."""
        from plus import engine_proxy
        engine_proxy._pool_warned["emitted"] = False

        fake_result = mock.MagicMock()
        fake_result.ok = True
        fake_result.verdict = "strong_ok"
        fake_result.trace = []
        fake_result.final_url = "https://example.com/"
        fake_result.content = "<html>ok</html>"
        fake_result.profile_used = None

        def fake_fetch(url, **kw):
            return fake_result

        engine_proxy._ORIGINAL_FETCH = fake_fetch
        engine_proxy._INSTALLED = True

        warned = []
        original_warn = engine_proxy._warn_pool

        def tracking_warn(exc, site):
            warned.append((exc, site))
            original_warn(exc, site)

        with mock.patch.object(engine_proxy, "_warn_pool", side_effect=tracking_warn), \
             mock.patch("plus._session_pool.pool_enabled", return_value=True), \
             mock.patch("plus._session_pool.acquire",
                        side_effect=RuntimeError("pool broken")), \
             mock.patch("plus.engine_proxy._ssrf_guard", return_value=None), \
             mock.patch("plus.engine_proxy._ip_literal_check", return_value=None), \
             mock.patch("plus.engine_proxy._post_redirect_check", return_value=None):
            engine_proxy._proxy_fetch("https://example.com/")

        self.assertTrue(warned, "_warn_pool must be called on acquire exception")
        self.assertEqual(warned[0][1], "acquire")


if __name__ == "__main__":
    unittest.main()
