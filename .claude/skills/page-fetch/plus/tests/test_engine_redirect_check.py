"""Per-hop redirect IP re-check (patch queue item #2, C1).

The engine now follows redirects manually so the caller's `url_check`
callback fires *before* the next GET. Plus injects `_ssrf_guard` as that
callback in `_proxy_fetch`, closing the DNS-rebinding / external→internal
redirect window at the moment the next hop becomes known instead of
relying on the post-fetch trace sweep.

These tests pin three behaviours without touching the network:
  1. External → external redirect chains fetch through normally and the
     final response's `.url` reflects the post-redirect endpoint.
  2. External → internal redirects raise at `url_check` and surface as an
     attempt-level `url_check_rejected:` error (no body leak).
  3. A pathological redirect loop is bounded at 10 hops with a clear
     `max redirects exceeded` error.

Mock strategy mirrors `test_engine_cookie_persistence.py`: inject a fake
`curl_cffi` module via `sys.modules`, reload `engine.fetch_chain`, then
re-bind `engine_proxy` to the freshly-loaded module so the patched
`fetch` survives the swap.
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
# Fake curl_cffi.requests with scripted responses per call
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal duck-typed response. `.url` is mutable so the engine can
    stamp the final post-redirect URL onto it."""

    def __init__(self, *, status_code: int, text: str, url: str,
                 headers: dict | None = None, cookies: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.content = text.encode("utf-8", errors="replace")


class _ScriptedSession:
    """A session whose .get() returns a queue of pre-built responses.

    `responses` is a list of `_FakeResponse` (or callables returning one).
    Each .get() pops the head; if the queue empties we raise loudly so a
    misconfigured test surfaces instead of hanging on a default 200.
    """

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []
        self.closed = False

    def get(self, url, *, impersonate=None, headers=None, timeout=None,
            allow_redirects=True, **_extra):
        self.calls.append({
            "url": url,
            "impersonate": impersonate,
            "headers": dict(headers or {}),
            "timeout": timeout,
            "allow_redirects": allow_redirects,
        })
        if not self._responses:
            raise AssertionError(
                f"_ScriptedSession ran out of scripted responses at call "
                f"#{len(self.calls)} url={url!r}"
            )
        nxt = self._responses.pop(0)
        if callable(nxt):
            return nxt(url)
        # Default: clone with the queried URL stamped so the response's
        # .url matches what the engine asked for, unless the scripted
        # response declared its own.
        if not nxt.url:
            nxt.url = url
        return nxt

    def close(self):
        self.closed = True


_LAST_SESSION: _ScriptedSession | None = None


def _install_fake_curl_cffi(responses):
    """Insert a fake curl_cffi tree backed by `responses`."""
    global _LAST_SESSION

    fake_requests = types.ModuleType("curl_cffi.requests")

    def _session_factory():
        global _LAST_SESSION
        _LAST_SESSION = _ScriptedSession(responses)
        return _LAST_SESSION

    def _module_level_get(*_args, **_kwargs):  # pragma: no cover
        raise AssertionError(
            "cffi_requests.get() should not run — Session path is in use"
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
    for name in list(sys.modules):
        if name == "engine.fetch_chain" or name.startswith("engine.fetch_chain."):
            del sys.modules[name]
    fc = importlib.import_module("engine.fetch_chain")
    import engine as _engine_root
    _engine_root.fetch_chain = fc
    return fc


# ---------------------------------------------------------------------------
# Test base — handles install/uninstall and reload boilerplate
# ---------------------------------------------------------------------------

class _RedirectTestBase(unittest.TestCase):
    """Common setUp/tearDown for the three scenarios.

    Subclasses set `RESPONSES = [...]` (list of `_FakeResponse` or
    callables) before calling `_run_fetch`.
    """

    RESPONSES: list = []

    def setUp(self):
        # addCleanup registers rollbacks immediately so a raise mid-setUp still
        # rolls back what we touched (tearDown would not run in that case).
        from plus.tests._engine_fake_helper import install_fake_curl_cffi_isolation
        install_fake_curl_cffi_isolation(self)
        _install_fake_curl_cffi(self.RESPONSES)
        self.fetch_chain = _reload_fetch_chain()


# ---------------------------------------------------------------------------
# 1. External → external redirect: passes, .url is final URL
# ---------------------------------------------------------------------------

class TestExternalToExternalRedirectPasses(_RedirectTestBase):
    """A 302 to another external host should follow through and the final
    response's `.url` should be the second URL."""

    RESPONSES = [
        # Probe: 302 redirecting to another external host.
        _FakeResponse(
            status_code=302,
            text="",
            url="https://example.com/start",
            headers={"Location": "https://other-external.example.org/landing"},
        ),
        # Hop 2: real content, large enough to clear validators'
        # SMALL_BODY_THRESHOLD (3000 bytes) so the verdict can advance
        # past UNKNOWN to WEAK_OK.
        _FakeResponse(
            status_code=200,
            text="<html><body>" + ("ok " * 1500) + "</body></html>",
            url="https://other-external.example.org/landing",
        ),
    ]

    def test_external_to_external_redirect_passes(self):
        # Use the engine fetch directly (engine_proxy is uninstalled during
        # setUp so we're calling the raw engine signature). Pass an
        # allow-all url_check so the redirect chain is followed.
        result = self.fetch_chain.fetch(
            "https://example.com/start",
            success_selectors=None,
            timeout=1,
            max_attempts=1,
            enable_playwright=False,
            url_check=lambda _u: None,
        )
        self.assertIsNotNone(_LAST_SESSION)
        # Two GETs: original + redirect target.
        self.assertEqual(len(_LAST_SESSION.calls), 2,
                         f"expected 2 GETs (original + hop), got {len(_LAST_SESSION.calls)}")
        self.assertEqual(_LAST_SESSION.calls[0]["url"], "https://example.com/start")
        self.assertEqual(_LAST_SESSION.calls[1]["url"],
                         "https://other-external.example.org/landing")
        # Engine should have stamped the final URL on the result.
        self.assertEqual(result.final_url,
                         "https://other-external.example.org/landing")
        # Manual redirect path → allow_redirects must be False on every hop.
        for call in _LAST_SESSION.calls:
            self.assertFalse(call["allow_redirects"],
                             "engine must drive redirects manually")
        # Body cleared the SMALL_BODY_THRESHOLD floor, so validators
        # should have promoted the verdict and fetch() returned ok=True.
        self.assertTrue(result.ok,
                        f"expected fetch to succeed, got verdict={result.verdict!r} "
                        f"summary={result.summary!r}")


# ---------------------------------------------------------------------------
# 2. External → internal redirect: url_check raises, attempt marked error
# ---------------------------------------------------------------------------

class TestExternalToInternalRedirectRejected(_RedirectTestBase):
    """302 to AWS metadata IP must be refused at `url_check` *before* the
    next GET goes out. The attempt is marked UNKNOWN with a
    `url_check_rejected:` error and the internal URL is never fetched."""

    RESPONSES = [
        # Probe: 302 pointing at AWS instance metadata service.
        _FakeResponse(
            status_code=302,
            text="",
            url="https://example.com/lure",
            headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        ),
        # Note: NO follow-up response queued. If the engine ever issues a
        # GET for the metadata URL the _ScriptedSession will raise loudly.
    ]

    def test_external_to_internal_redirect_rejected(self):
        from plus._ssrf import _ssrf_guard  # real guard; recognises 169.254.x.x

        result = self.fetch_chain.fetch(
            "https://example.com/lure",
            success_selectors=None,
            timeout=1,
            max_attempts=1,
            enable_playwright=False,
            url_check=_ssrf_guard,
        )
        # Exactly one GET — the original. The metadata URL never went out.
        self.assertEqual(len(_LAST_SESSION.calls), 1,
                         "internal IP must not be requested; "
                         f"calls={[c['url'] for c in _LAST_SESSION.calls]}")
        self.assertEqual(_LAST_SESSION.calls[0]["url"],
                         "https://example.com/lure")
        # The probe attempt must carry the url_check_rejected marker.
        self.assertTrue(len(result.trace) >= 1)
        probe = result.trace[0]
        self.assertEqual(probe.verdict, "unknown")
        self.assertIsNotNone(probe.error)
        self.assertIn("url_check_rejected", probe.error)
        # fetch() returns ok=False when no attempt validates.
        self.assertFalse(result.ok)


# ---------------------------------------------------------------------------
# 3. Max redirects exceeded
# ---------------------------------------------------------------------------

class _CookieAwareScriptedSession:
    """Like `_ScriptedSession` but also accumulates Set-Cookie response
    headers into a jar and auto-attaches them as `Cookie:` on subsequent
    GETs. Mirrors the curl_cffi Session contract well enough to verify
    that cookies set on a 302 hop are re-sent on the redirect target."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.cookies: dict[str, str] = {}
        self.calls: list[dict] = []
        self.closed = False

    def get(self, url, *, impersonate=None, headers=None, timeout=None,
            allow_redirects=True, **_extra):
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
        if not self._responses:
            raise AssertionError(
                f"_CookieAwareScriptedSession ran out at call "
                f"#{len(self.calls)} url={url!r}"
            )
        nxt = self._responses.pop(0)
        if callable(nxt):
            nxt = nxt(url)
        if not nxt.url:
            nxt.url = url
        # Mimic real session: harvest Set-Cookie into the jar. We only
        # need a minimal `name=value` parse — `; path=/` and the rest of
        # the attribute soup is irrelevant to the test assertion.
        sc = nxt.headers.get("Set-Cookie") or nxt.headers.get("set-cookie")
        if sc:
            kv = sc.split(";", 1)[0].strip()
            if "=" in kv:
                name, _, value = kv.partition("=")
                self.cookies[name.strip()] = value.strip()
        return nxt

    def close(self):
        self.closed = True


def _install_fake_curl_cffi_cookie_aware(responses):
    """Variant of `_install_fake_curl_cffi` whose Session has a cookie jar."""
    global _LAST_SESSION

    fake_requests = types.ModuleType("curl_cffi.requests")

    def _session_factory():
        global _LAST_SESSION
        _LAST_SESSION = _CookieAwareScriptedSession(responses)
        return _LAST_SESSION

    def _module_level_get(*_args, **_kwargs):  # pragma: no cover
        raise AssertionError(
            "cffi_requests.get() should not run — Session path is in use"
        )

    fake_requests.Session = _session_factory  # type: ignore[attr-defined]
    fake_requests.get = _module_level_get  # type: ignore[attr-defined]

    fake_pkg = types.ModuleType("curl_cffi")
    fake_pkg.requests = fake_requests  # type: ignore[attr-defined]

    sys.modules["curl_cffi"] = fake_pkg
    sys.modules["curl_cffi.requests"] = fake_requests
    return fake_pkg


class TestCookieAttachedToRedirectedHop(unittest.TestCase):
    """Cookie set on a 302 response must be auto-attached as `Cookie:` on
    the next hop driven by the manual redirect loop."""

    RESPONSES = [
        _FakeResponse(
            status_code=302,
            text="",
            url="https://example.com/start",
            headers={
                "Set-Cookie": "sid=ZZZ; path=/",
                "Location": "https://target.example.com/landing",
            },
        ),
        _FakeResponse(
            status_code=200,
            text="<html><body>" + ("ok " * 500) + "</body></html>",
            url="https://target.example.com/landing",
        ),
    ]

    def setUp(self):
        # addCleanup registers rollbacks immediately so a raise mid-setUp still
        # rolls back what we touched (tearDown would not run in that case).
        from plus.tests._engine_fake_helper import install_fake_curl_cffi_isolation
        install_fake_curl_cffi_isolation(self)
        _install_fake_curl_cffi_cookie_aware(self.RESPONSES)
        self.fetch_chain = _reload_fetch_chain()

    def test_cookie_attached_to_redirected_hop(self):
        self.fetch_chain.fetch(
            "https://example.com/start",
            success_selectors=None,
            timeout=1,
            max_attempts=1,
            enable_playwright=False,
            url_check=lambda _u: None,
        )
        self.assertIsNotNone(_LAST_SESSION)
        self.assertEqual(len(_LAST_SESSION.calls), 2,
                         f"expected 2 GETs (original + hop), "
                         f"got {len(_LAST_SESSION.calls)}")
        first_call, second_call = _LAST_SESSION.calls
        # First call: jar empty, no Cookie sent.
        self.assertNotIn("Cookie", first_call["headers"])
        # Second call: the Set-Cookie from the 302 was harvested and the
        # redirect-driven GET re-sends it.
        self.assertIn("Cookie", second_call["headers"],
                      "cookie set on redirect hop must be attached to "
                      "the follow-up GET")
        self.assertIn("sid=ZZZ", second_call["headers"]["Cookie"])


class TestLowercaseLocationHeaderFollowed(_RedirectTestBase):
    """RFC 7230 header names are case-insensitive: a `location` (lowercase)
    redirect header must be honoured the same as `Location`."""

    RESPONSES = [
        _FakeResponse(
            status_code=302,
            text="",
            url="https://example.com/start",
            headers={"location": "https://target.example.com/landing"},
        ),
        _FakeResponse(
            status_code=200,
            text="<html><body>" + ("ok " * 1500) + "</body></html>",
            url="https://target.example.com/landing",
        ),
    ]

    def test_lowercase_location_header_followed(self):
        result = self.fetch_chain.fetch(
            "https://example.com/start",
            success_selectors=None,
            timeout=1,
            max_attempts=1,
            enable_playwright=False,
            url_check=lambda _u: None,
        )
        self.assertEqual(len(_LAST_SESSION.calls), 2,
                         f"expected 2 GETs (original + lowercase-location hop), "
                         f"got {len(_LAST_SESSION.calls)}")
        self.assertEqual(_LAST_SESSION.calls[1]["url"],
                         "https://target.example.com/landing")
        self.assertEqual(result.final_url,
                         "https://target.example.com/landing")


class TestMaxRedirectsExceeded(_RedirectTestBase):
    """If every response is a 302, the engine should bail out at the 10-hop
    cap with a `max redirects exceeded` error, not loop forever."""

    # 20 successive 302s all bouncing the request between two URLs. The
    # engine should give up at hop 10 + 1.
    RESPONSES = [
        _FakeResponse(
            status_code=302,
            text="",
            url=f"https://example.com/h{i}",
            headers={"Location": f"https://example.com/h{i + 1}"},
        )
        for i in range(20)
    ]

    def test_max_redirects_exceeded(self):
        result = self.fetch_chain.fetch(
            "https://example.com/h0",
            success_selectors=None,
            timeout=1,
            max_attempts=1,
            enable_playwright=False,
            url_check=lambda _u: None,
        )
        # 1 original + 10 redirect hops = 11 GETs, then bail.
        self.assertEqual(len(_LAST_SESSION.calls), 11,
                         f"expected 11 GETs (1 + 10 hops), "
                         f"got {len(_LAST_SESSION.calls)}")
        # Engine should record an attempt-level error mentioning the cap.
        self.assertTrue(len(result.trace) >= 1)
        probe = result.trace[0]
        self.assertIsNotNone(probe.error)
        self.assertIn("max redirects", probe.error)
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
