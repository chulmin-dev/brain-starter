"""P21 clearance persistence (opt-in cookie jar) + Playwright handoff.

Offline / deterministic. Same fake-curl_cffi-injection strategy as the
other engine tests; the jar directory is a per-test tmpdir set via
`INSANE_COOKIE_JAR_DIR`.

Pins:
  * Jar OFF by default — no env → no jar file written, behaviour unchanged.
  * Jar roundtrip — a cookie set during fetch() #1 is persisted (0600 file
    under a 0700 dir) and re-loaded into the session for fetch() #2.
  * Registrable-domain keying — www.example.com and example.com share one jar.
  * Playwright handoff — fetch() invokes run_playwright_fallback with the
    *winning* transform URL and the harvested curl cookies (curl→Chrome replay).
  * No secret leak — cookie *values* never appear in the FetchResult trace.
"""
from __future__ import annotations

import importlib
import os
import stat
import sys
import types
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))


# ---------------------------------------------------------------------------
# Fake curl_cffi.requests with a cookie-jar-bearing Session
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, *, status_code, text, url, headers=None, cookies=None):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.content = text.encode("utf-8", errors="replace")


class _Cookie:
    """Minimal cookielib-style cookie for the session jar."""
    def __init__(self, name, value, domain="", path="/"):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path


class _JarSession:
    """Session whose `.cookies` is an iterable jar supporting `.set()`.

    Records every GET. On the first GET it sets a `cf_clearance` cookie so
    the jar-save path has something to persist. `set()` is also what
    `_load_cookie_jar` calls when re-hydrating a saved jar.
    """

    def __init__(self):
        self._jar: dict[str, _Cookie] = {}
        self.calls: list[dict] = []
        self.closed = False

    # cookielib-ish API used by _session_cookies (iterate) + _load_cookie_jar (set)
    class _CookieView:
        def __init__(self, owner):
            self._owner = owner

        def __iter__(self):
            return iter(list(self._owner._jar.values()))

        def set(self, name, value, *, domain="", path="/"):
            self._owner._jar[name] = _Cookie(name, value, domain, path)

    @property
    def cookies(self):
        return _JarSession._CookieView(self)

    def get(self, url, *, impersonate=None, headers=None, timeout=None,
            allow_redirects=True, **_extra):
        self.calls.append({"url": url, "impersonate": impersonate})
        # First call sets a clearance cookie directly in the jar (mimics a
        # Set-Cookie the real session would have absorbed).
        if len(self.calls) == 1 and "cf_clearance" not in self._jar:
            self._jar["cf_clearance"] = _Cookie("cf_clearance", "SECRET_TOKEN",
                                                domain=".example.com", path="/")
        # Always a CHALLENGE-class small body so the grid keeps spinning and
        # eventually falls through to the Playwright handoff.
        return _FakeResponse(
            status_code=200,
            text="<html><body>Just a moment...</body></html>",
            url=url,
        )

    def close(self):
        self.closed = True


_LAST_SESSION: _JarSession | None = None


def _install_fake_curl_cffi():
    global _LAST_SESSION

    fake_requests = types.ModuleType("curl_cffi.requests")

    def _session_factory():
        global _LAST_SESSION
        _LAST_SESSION = _JarSession()
        return _LAST_SESSION

    def _module_level_get(*_a, **_k):  # pragma: no cover
        raise AssertionError("Session path is in use")

    fake_requests.Session = _session_factory  # type: ignore[attr-defined]
    fake_requests.get = _module_level_get  # type: ignore[attr-defined]

    fake_pkg = types.ModuleType("curl_cffi")
    fake_pkg.requests = fake_requests  # type: ignore[attr-defined]

    sys.modules["curl_cffi"] = fake_pkg
    sys.modules["curl_cffi.requests"] = fake_requests
    return fake_pkg


def _reload_fetch_chain():
    for name in list(sys.modules):
        if name == "engine.fetch_chain" or name.startswith("engine.fetch_chain."):
            del sys.modules[name]
    fc = importlib.import_module("engine.fetch_chain")
    import engine as _engine_root
    _engine_root.fetch_chain = fc
    return fc


class _Base(unittest.TestCase):
    def setUp(self):
        from plus.tests._engine_fake_helper import install_fake_curl_cffi_isolation
        install_fake_curl_cffi_isolation(self)
        _install_fake_curl_cffi()
        self.fetch_chain = _reload_fetch_chain()
        # Ensure no stray jar env leaks between tests.
        os.environ.pop("INSANE_COOKIE_JAR_DIR", None)
        self.addCleanup(os.environ.pop, "INSANE_COOKIE_JAR_DIR", None)


# ---------------------------------------------------------------------------
# Jar OFF by default
# ---------------------------------------------------------------------------

class TestJarOffByDefault(_Base):
    def test_no_jar_dir_no_file_no_trace(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            # env intentionally NOT set
            result = self.fetch_chain.fetch(
                "https://example.com/",
                success_selectors=["article.never"],
                timeout=1,
                max_attempts=3,
                enable_playwright=False,
                url_check=lambda _u: None,
            )
            # Directory stays empty — nothing persisted.
            self.assertEqual(os.listdir(d), [])
            # No cookie_jar trace breadcrumb.
            self.assertFalse(
                any(a.executor == "cookie_jar" for a in result.trace),
                "no jar breadcrumb expected when feature is off",
            )


# ---------------------------------------------------------------------------
# Jar roundtrip across two fetch() calls
# ---------------------------------------------------------------------------

class TestJarRoundtrip(_Base):
    def test_clearance_persists_across_calls(self):
        import tempfile
        with tempfile.TemporaryDirectory() as jar_dir:
            os.environ["INSANE_COOKIE_JAR_DIR"] = jar_dir

            # --- fetch #1: earns + persists cf_clearance ---
            r1 = self.fetch_chain.fetch(
                "https://example.com/page",
                success_selectors=["article.never"],
                timeout=1,
                max_attempts=3,
                enable_playwright=False,
                url_check=lambda _u: None,
            )
            # A jar file now exists and is 0600 under a 0700 dir.
            files = os.listdir(jar_dir)
            self.assertEqual(len(files), 1, f"expected one jar file, got {files}")
            jar_path = os.path.join(jar_dir, files[0])
            if os.name != "nt":
                mode = stat.S_IMODE(os.stat(jar_path).st_mode)
                self.assertEqual(mode, 0o600, f"jar file must be 0600, got {oct(mode)}")
                dir_mode = stat.S_IMODE(os.stat(jar_dir).st_mode)
                self.assertEqual(dir_mode, 0o700, f"jar dir must be 0700, got {oct(dir_mode)}")
            # Trace records the jar is active but never the cookie value.
            jar_crumbs = [a for a in r1.trace if a.executor == "cookie_jar"]
            self.assertTrue(jar_crumbs, "expected a cookie_jar trace breadcrumb")
            self.assertNotIn("SECRET_TOKEN", (jar_crumbs[0].error or ""))

            # --- fetch #2: a fresh session must be pre-loaded from the jar ---
            r2 = self.fetch_chain.fetch(
                "https://example.com/other",
                success_selectors=["article.never"],
                timeout=1,
                max_attempts=3,
                enable_playwright=False,
                url_check=lambda _u: None,
            )
            # The new session's jar was seeded with the persisted cookie before
            # the first GET (set() was called during _load_cookie_jar).
            self.assertIsNotNone(_LAST_SESSION)
            names = {c.name for c in _LAST_SESSION.cookies}
            self.assertIn("cf_clearance", names,
                          "persisted clearance must reload into the next session")
            # And again the value never leaked into the trace.
            for a in r2.trace:
                self.assertNotIn("SECRET_TOKEN", (a.error or ""))

    def test_registrable_domain_shared_across_subdomains(self):
        import tempfile
        with tempfile.TemporaryDirectory() as jar_dir:
            os.environ["INSANE_COOKIE_JAR_DIR"] = jar_dir
            self.fetch_chain.fetch(
                "https://www.example.com/",
                success_selectors=["article.never"],
                timeout=1, max_attempts=2, enable_playwright=False,
                url_check=lambda _u: None,
            )
            first = set(os.listdir(jar_dir))
            self.assertEqual(len(first), 1)
            # apex host must hash to the SAME jar file (registrable-domain key).
            self.fetch_chain.fetch(
                "https://example.com/",
                success_selectors=["article.never"],
                timeout=1, max_attempts=2, enable_playwright=False,
                url_check=lambda _u: None,
            )
            self.assertEqual(set(os.listdir(jar_dir)), first,
                             "www + apex must share one registrable-domain jar")


# ---------------------------------------------------------------------------
# Playwright handoff: winning URL + curl cookies forwarded
# ---------------------------------------------------------------------------

class TestPlaywrightHandoff(_Base):
    def test_fallback_receives_cookies_and_url(self):
        from unittest import mock
        from engine.validators import Verdict
        from engine.fetch_chain import Attempt

        captured = {}

        def _fake_fallback(url, *, profile_id, cookies=None, **kwargs):
            captured["url"] = url
            captured["cookies"] = cookies
            captured["kwargs"] = kwargs
            att = Attempt(
                phase="fallback", executor="playwright_real_chrome",
                url=url, url_transform="original", impersonate=None, referer="",
            )
            att.verdict = Verdict.UNKNOWN.value  # keep going / give up cleanly
            return att, ""

        # Patch the executor symbol the engine lazily imports.
        import engine.executor as _ex
        with mock.patch.object(_ex, "run_playwright_fallback", _fake_fallback):
            self.fetch_chain.fetch(
                "https://example.com/deep/page",
                success_selectors=["article.never"],
                timeout=1,
                max_attempts=4,
                enable_playwright=True,
                url_check=lambda _u: None,
            )

        # The fallback was invoked with the curl-side clearance cookie.
        self.assertIn("cookies", captured)
        self.assertIsNotNone(captured["cookies"],
                             "curl session cookies must be handed to Playwright")
        names = {c["name"] for c in captured["cookies"]}
        self.assertIn("cf_clearance", names)
        # The handed-over URL is a real fetched URL (winning transform), and the
        # cookie value travels in the handoff payload (not the trace).
        self.assertTrue(captured["url"].startswith("https://"))
        values = {c.get("value") for c in captured["cookies"]}
        self.assertIn("SECRET_TOKEN", values)


class TestDictJarHandoffContract(_Base):
    """CR-M2 regression: a dict-style curl jar (name→value, domain="") must
    still produce an addCookies-VALID payload (every cookie carries url OR
    domain+path). Before the fix the empty-domain entries reached addCookies
    verbatim and the whole batch was rejected — the handoff silently lost."""

    @staticmethod
    def _assert_addcookies_valid(payload):
        # Playwright's addCookies contract: each cookie needs EITHER `url`
        # OR BOTH `domain` and `path`. An entry with neither (or domain="")
        # makes Playwright reject the WHOLE batch.
        for c in payload:
            has_url = bool(c.get("url"))
            has_domain_path = bool(c.get("domain")) and bool(c.get("path"))
            assert has_url or has_domain_path, f"invalid addCookies entry: {c}"
            assert c.get("domain", "x") != "", f"empty domain leaked: {c}"

    def test_dict_jar_produces_valid_addcookies_payload(self):
        from unittest import mock
        import engine.executor as _ex

        # Dict-style jar: iterating yields KEYS (strings, no .name attr) so
        # _session_cookies falls through the cookielib branch into the
        # dict-fallback that emits domain="".
        class _DictJar(dict):
            pass

        class _Sess:
            def __init__(self, jar):
                self.cookies = jar

        sess = _Sess(_DictJar({"cf_clearance": "SECRET_TOKEN", "sessid": "abc"}))
        cookies = self.fetch_chain._session_cookies(sess)
        # The dict path emits empty-domain entries (the fragile shape).
        self.assertTrue(cookies)
        self.assertTrue(all(c["domain"] == "" for c in cookies))

        captured = {}

        def _fake_run_node_template(template, args, timeout=90):
            captured["args"] = args
            return 0, "<html>ok</html>", ""

        with mock.patch.object(_ex, "_run_node_template", _fake_run_node_template), \
                mock.patch.object(_ex, "load_profile",
                                  lambda _pid: {"capabilities_needed": []}):
            _ex.run_playwright_fallback(
                "https://example.com/deep/page",
                profile_id="cloudflare_turnstile",
                force_executor="playwright_real_chrome",
                cookies=cookies,
            )

        prepared = captured["args"].get("cookies")
        self.assertIsNotNone(prepared, "dict-jar cookies must reach the template")
        names = {c["name"] for c in prepared}
        self.assertEqual(names, {"cf_clearance", "sessid"})
        # The contract: empty-domain entries must be url-anchored, not dropped.
        self._assert_addcookies_valid(prepared)
        self.assertTrue(
            all(c.get("url") == "https://example.com/deep/page" for c in prepared),
            "empty-domain dict-jar cookies must be anchored by the target URL",
        )


if __name__ == "__main__":
    unittest.main()
